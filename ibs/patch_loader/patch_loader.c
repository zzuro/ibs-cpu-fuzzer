#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/nmi.h>
#include <asm/pgtable_types.h>
#include <asm/processor.h>
#include <asm/sev-common.h>
#include <asm/sev.h>
#include <asm/svm.h>
#include <asm/tdx.h>
#include <kvm/iodev.h>
#include <linux/anon_inodes.h>
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/compat.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/kvm_types.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/psp-sev.h>
#include <linux/psp.h>
#include <linux/reboot.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/stat.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/swap.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/cpu.h>
#include <asm/amd/ibs.h>
#include <asm/extable.h>
#include <asm/trapnr.h>
#include <linux/delay.h>
#include <linux/psp-sev.h>
#include <asm/svm.h>
#include <asm/sev-common.h>
#include <linux/cpu.h>
#include <linux/container_of.h>
#include <linux/firmware.h>

#include "apic.h"
#include "msr.h"
#include "nmi.h"
#include "page_table_stuff.h"
#include "opcode_wrappers.h"
#include "ibs_logger.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Vezzù");
MODULE_DESCRIPTION("Kernel module to load patches for IBS-based CPU fuzzing");
MODULE_VERSION("1.0");

#define CPU_NUMBER_IBS_USE 8

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

static __always_inline uint64_t __read_msr(uint32_t msr_register)
{
    uint64_t msr_value;
    uint32_t low, high;

    asm volatile(
        "rdmsr"
        : "=a"(low), "=d"(high) // Output operands
        : "c"(msr_register)     // Input operand
    );

    msr_value = ((uint64_t)high << 32) | low;
    return msr_value;
}

// Function to write an MSR
static __always_inline void __write_msr(uint32_t msr_register, uint64_t msr_value)
{
    uint32_t low = (uint32_t)msr_value;
    uint32_t high = (uint32_t)(msr_value >> 32);

    asm volatile(
        "wrmsr"
        :                                        // No output operands
        : "c"(msr_register), "a"(low), "d"(high) // Input operands
    );
}

static __always_inline uint64_t measure_access_time(const uint8_t *addr)
{
    uint32_t lo_start, hi_start;
    uint32_t lo_end, hi_end;
    uint32_t aux;
    volatile uint8_t value;
    preempt_disable();
    /*
     * Serialize earlier memory ops before timing.
     * mfence is conservative; lfence is the key one for load timing.
     */
    asm volatile("mfence\n\t"
                 "lfence\n\t" ::: "memory");

    /* Read starting timestamp */
    asm volatile("rdtscp\n\t"
                 : "=a"(lo_start), "=d"(hi_start), "=c"(aux)
                 :
                 : "memory");

    /* Prevent later ops from executing early */
    asm volatile("lfence\n\t" ::: "memory");

    /* Timed load */
    asm volatile("movb (%1), %0\n\t"
                 : "=r"(value)
                 : "r"(addr)
                 : "memory");

    /* Ensure load completes before reading end timestamp */
    asm volatile("lfence\n\t" ::: "memory");

    /* Read ending timestamp */
    asm volatile("rdtscp\n\t"
                 : "=a"(lo_end), "=d"(hi_end), "=c"(aux)
                 :
                 : "memory");

    asm volatile("mfence\n\t" ::: "memory");
    preempt_enable();
    return (((uint64_t)hi_end << 32) | lo_end) -
           (((uint64_t)hi_start << 32) | lo_start);
}

typedef union ibs_opt_ctrl
{
    struct
    {
        u64 IbsOpMaxCnt2 : 16;   // 15:0
        u64 IbsOpL3MissOnly : 1; // 16
        u64 IbsOpEn : 1;         // 17
        u64 IbsOpValid : 1;      // 18
        u64 IbsOpCntCtl : 1;     // 19
        u64 IbsOpMaxCnt1 : 7;    // 26:20
        u64 rsvd2 : 5;           // 31:27
        u64 IbsOpCurCnt : 27;    // 58:32
        u64 rsvd1 : 5;           // 63:59
    };
    u64 value;
} ibs_opt_ctrl;

typedef union ibs_op_data_1
{
    struct
    {
        u64 IbsCompToRetCtr : 16; // bits 15:0
        u64 IbsTagToRetCtr : 16;  // bits 31:16
        u64 Reserved2 : 2;        // bits 33:32 (Reserved)
        u64 IbsOpReturn : 1;      // bit 34
        u64 IbsOpBrnTaken : 1;    // bit 35
        u64 IbsOpBrnMisp : 1;     // bit 36
        u64 IbsOpBrnRet : 1;      // bit 37
        u64 IbsRipInvalid : 1;    // bit 38
        u64 IbsOpFuse : 1;        // bit 39
        u64 IbsOpMicrocode : 1;   // bit 40
        u64 Reserved1 : 24;       // bits 63:40 (Reserved)
    } __attribute__((packed));
    u64 value;
} ibs_op_data_1;

typedef union ibs_op_data_3
{
    struct
    {
        u64 IbsOpLd : 1;              // bit 0
        u64 IbsOpSt : 1;              // bit 1
        u64 IbsDcL1tlbMiss : 1;       // bit 2
        u64 IbsDcL2tlbMiss : 1;       // bit 3
        u64 IbsDcL1tlbHit2M : 1;      // bit 4
        u64 IbsDcL1tlbHit1G : 1;      // bit 5
        u64 rsvd1 : 1;                // bit 6
        u64 IbsDcMiss : 1;            // bit 7
        u64 IbsDcMisAcc : 1;          // bit 8
        u64 rsvd2 : 3;                // bits 11:9 (Reserved)
        u64 IbsDcWcMemAcc : 1;        // bit 12
        u64 IbsDcUcMemAcc : 1;        // bit 13
        u64 IbsDcLockedOp : 1;        // bit 14
        u64 DcMissNoMabAlloc : 1;     // bit 15
        u64 IbsDcLinAddrValid : 1;    // bit 16
        u64 IbsDcPhyAddrValid : 1;    // bit 17
        u64 rsvd3 : 1;                // bit 18 (Reserved)
        u64 IbsL2Miss : 1;            // bit 20
        u64 IbsSwPf : 1;              // bit 21
        u64 IbsOpMemWidth : 4;        // bits 25:22
        u64 IbsOpDcMissOpMemReqs : 6; // bits 31:26
        u64 IbsDcMissLat : 16;        // bits 47:32
        u64 IbsTlbRefillLat : 16;     // bits 63:48
    } __attribute__((packed));
    u64 value;
} ibs_op_data_3;

char *memwithStrings[] = {"0 ", "1 ", "2 ", "4 ", "8 ", "16", "32", "64", "?8", "?9", "?A", "?B", "?C", "?D", "?C", "?E", "?F"};

static void noinline write_ibs_ctrl(u64 instruction_offset)
{
    ibs_opt_ctrl ibs_op_ctl_data;
    ibs_op_ctl_data.value = __read_msr(IBS_OP_CTL);

    // zero everything
    ibs_op_ctl_data.value = 0;

    // ibs_op_ctl_data.IbsOpMaxCnt2 = (1 << 15);
    ibs_op_ctl_data.IbsOpMaxCnt1 = (1 << 5);
    ibs_op_ctl_data.IbsOpCurCnt = (1 << 25) - instruction_offset;
    ibs_op_ctl_data.IbsOpCntCtl = 1; // 1 for counting micro ops / 0 for counting cycles
    ibs_op_ctl_data.IbsOpEn = 1;
    // ibs_op_ctl_data.rsvd2 = 0x1F;
    __write_msr(IBS_OP_CTL, ibs_op_ctl_data.value);
}

static void __maybe_unused noinline read_ibs_ctrl(u64 uop_cnt, u64 rip_out)
{
    ibs_opt_ctrl ibs_op_ctl_data;
    ibs_op_ctl_data.value = __read_msr(IBS_OP_CTL);

    if (ibs_op_ctl_data.IbsOpValid == 0)
    {
        return;
    }

    u64 rip_value;
    rip_value = __read_msr(IBS_OP_RIP);

    union ibs_op_data opData1;
    opData1.val = __read_msr(IBS_OP_DATA);

    union ibs_op_data3 opData3;
    opData3.val = __read_msr(IBS_OP_DATA3);

    u64 lin_addr = __read_msr(IBS_DC_LIN_AD);
    u64 phys_addr = __read_msr(IBS_DC_PHYS_AD);

    u64 branch_target_rip = __read_msr(BP_IBSTGT_RIP);

    if (opData3.ld_op == 1 || opData3.st_op == 1)
    {
        pr_info("[RIP: 0x%016llx][uop cnt: %lld] [%6s%s] 0x%016llx (v=0x%016llx) UC[%s] WC[%s] CacheMiss [%s] tagToRetire [%4d] compToRetire [%4d] \n", rip_value, uop_cnt, opData3.ld_op ? "load" : "store", memwithStrings[opData3.op_mem_width], phys_addr, lin_addr, opData3.dc_wc_mem_acc ? "+" : "-", opData3.dc_uc_mem_acc ? "+" : "-", opData3.dc_miss ? "+" : "-", opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr);
    }
    else
    {
        // pr_info("[RIP: 0x%016llx][uop cnt: %lld] [%8s] Branch[%3s] tagToRetire [%4d] compToRetire [%4d] micro [%3s] multiOP [%3s] branchTarget [0x%016llx] brnTaken [%s] brnMisp [%s]\n", rip_value, uop_cnt, "ALU", opData1.op_brn_ret ? "yes" : "no", opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr, opData1.op_microcode ? "yes" : "no", opData1.op_brn_fuse ? "yes" : "no", branch_target_rip, opData1.op_brn_taken ? "yes" : "no", opData1.op_brn_misp ? "yes" : "no");
    }

    ibs_op_ctl_data.value = 0;
    __write_msr(IBS_OP_CTL, ibs_op_ctl_data.value);
    __write_msr(IBS_OP_DATA, 0);
    __write_msr(IBS_OP_DATA2, 0);
    __write_msr(IBS_OP_DATA3, 0);
    __write_msr(IBS_DC_LIN_AD, 0);
    __write_msr(IBS_DC_PHYS_AD, 0);
    __write_msr(IBS_OP_RIP, 0);
    __write_msr(BP_IBSTGT_RIP, 0);
}

static uint8_t raw_instr[4] = {0x00, 0x01, 0x00, 0x20}; // .byte 0x00, 0x01, 0x00, 0x20 -> opcode for WRMSR with ecx=0xC0010020 (IBS_OP_DATA_CODE)

static void __maybe_unused noinline log_ibs_ctrl(u64 uop_cnt)
{
    union ibs_op_ctl ibs_op_ctl_data;
	ibs_op_ctl_data.val = __read_msr(IBS_OP_CTL);

	u64 rip_value;
	rip_value = __read_msr(IBS_OP_RIP);

	union ibs_op_data opData1;
	opData1.val = __read_msr(IBS_OP_DATA);

	union ibs_op_data3 opData3;
	opData3.val = __read_msr(IBS_OP_DATA3);

	u64 lin_addr = __read_msr(IBS_DC_LIN_AD);
	u64 phys_addr = __read_msr(IBS_DC_PHYS_AD);

	u64 branch_target_rip = __read_msr(BP_IBSTGT_RIP);

	ibs_log_event(rip_value, uop_cnt, ibs_op_ctl_data.op_val, opData3, opData1, phys_addr, lin_addr,
		0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, raw_instr, 4);

    ibs_op_ctl_data.val = 0;
    __write_msr(IBS_OP_CTL, ibs_op_ctl_data.val);
    __write_msr(IBS_OP_DATA, 0);
    __write_msr(IBS_OP_DATA2, 0);
    __write_msr(IBS_OP_DATA3, 0);
    __write_msr(IBS_DC_LIN_AD, 0);
    __write_msr(IBS_DC_PHYS_AD, 0);
    __write_msr(IBS_OP_RIP, 0);
    __write_msr(BP_IBSTGT_RIP, 0);
}

static void ibs_analysis_opcode(enum opcode_id id, u64 location,
                                u64 arg0, u64 arg1, u8 *ptr)
{
    struct opcode_result res;

    write_ibs_ctrl(location);

    READ_ONCE(ptr[1]);
    READ_ONCE(ptr[2]);
    READ_ONCE(ptr[3]);
    READ_ONCE(ptr[4]);
    READ_ONCE(ptr[5]);
    READ_ONCE(ptr[6]);

    run_selected_opcode(id, arg0, arg1, &res);

    READ_ONCE(ptr[1]);
    READ_ONCE(ptr[2]);
    READ_ONCE(ptr[3]);
    READ_ONCE(ptr[4]);
    READ_ONCE(ptr[5]);
    READ_ONCE(ptr[6]);

    if (res.rc == 0)
    {
        // pr_info("%s success RIP=0x%llx\n",
        //         opcode_table[id].name, res.rip);
    }
    else
    {
        // pr_info("%s fault RIP=0x%llx vec=%d\n",
        //         opcode_table[id].name, res.rip, res.vec);
    }

    read_ibs_ctrl(location, res.rip);
}

static __always_inline void flush_cache_line_fenced(const void *addr)
{
    asm volatile("mfence\n\t" ::: "memory");
    asm volatile("clflush (%0)\n\t" : : "r"(addr) : "memory");
    asm volatile("mfence\n\t" ::: "memory");
}

#define MY_PMC_IDX 0
#define MY_PERFEVTSEL_MSR (0xc0010200ULL + MY_PMC_IDX * 2)
#define MY_PERFCTR_MSR (0xc0010201ULL + MY_PMC_IDX * 2)

#define MY_PERFEVTSEL_VAL \
    ((0x60ULL) |          \
     (0x80ULL << 8) |     \
     (1ULL << 17) |       \
     (1ULL << 22) |       \
     (2ULL << 40))

static void setup_l1miss_pmc(void)
{
    wrmsrl(MY_PERFCTR_MSR, 0ULL);
    wrmsrl(MY_PERFEVTSEL_MSR, MY_PERFEVTSEL_VAL);
}

static void mfence(void)
{
    asm volatile("mfence" ::: "memory");
}

#define PMC_BARRIER()                \
    asm volatile(                    \
        "mfence\n\t"                 \
        "mov $0x80000005, %%eax\n\t" \
        "cpuid\n\t"                  \
        : : : "eax", "ebx", "ecx", "edx", "memory")

static __always_inline u64 read_pmc(void)
{
    u32 lo, hi;
    asm volatile("rdmsr"
                 : "=a"(lo), "=d"(hi)
                 : "c"((u32)MY_PERFCTR_MSR)
                 : "memory");
    return ((u64)hi << 32) | lo;
}

static __always_inline bool is_l1_miss(const u8 *addr)
{
    u64 before, after;
    volatile u8 val;

    preempt_disable();

    PMC_BARRIER();
    before = read_pmc();

    asm volatile("movb (%1), %0" : "=r"(val) : "r"(addr) : "memory");

    after = read_pmc();
    PMC_BARRIER();

    preempt_enable();

    return (after - before) > 0;
}

#define GET_BIT(va, bit) (((uint64_t)(va) >> (bit)) & 1ULL)

uint64_t calculate_zen_utag(void *ptr)
{
    uint64_t va = (uint64_t)ptr;
    uint64_t u0 = GET_BIT(va, 12) ^ GET_BIT(va, 13) ^ GET_BIT(va, 14) ^ GET_BIT(va, 15) ^ GET_BIT(va, 16) ^ GET_BIT(va, 17) ^ GET_BIT(va, 18) ^ GET_BIT(va, 19) ^ GET_BIT(va, 20) ^ GET_BIT(va, 21) ^ GET_BIT(va, 22) ^ GET_BIT(va, 23) ^ GET_BIT(va, 24) ^ GET_BIT(va, 25) ^ GET_BIT(va, 26) ^ GET_BIT(va, 27);
    uint64_t u1 = GET_BIT(va, 13) ^ GET_BIT(va, 26);
    uint64_t u2 = GET_BIT(va, 14) ^ GET_BIT(va, 25);
    uint64_t u3 = GET_BIT(va, 19) ^ GET_BIT(va, 24);
    uint64_t u4 = GET_BIT(va, 18) ^ GET_BIT(va, 23);
    uint64_t u5 = GET_BIT(va, 17) ^ GET_BIT(va, 22);
    uint64_t u6 = GET_BIT(va, 16) ^ GET_BIT(va, 21);
    uint64_t u7 = GET_BIT(va, 15) ^ GET_BIT(va, 20);

    return (u0 << 0) | (u1 << 1) | (u2 << 2) | (u3 << 3) | (u4 << 4) | (u5 << 5) | (u6 << 6) | (u7 << 7);
}

#define ITERATIONS 200

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

static void print_ibs_trace(struct microcode_amd *mc)
{
    u8 *ptr = kmalloc(4096, GFP_KERNEL);
    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }

    for (int i = 0; i < 6000; i++)
    {
        ibs_analysis_opcode(OP_WRMSR, i, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, ptr);
    }

    kfree(ptr);
}

static void measure_cache_behavior(struct microcode_amd *mc)
{
    uint64_t phys_addr = virt_to_phys(kmalloc(4096, GFP_KERNEL));
    uint8_t *addr = (uint8_t *)0x000ffffdf7003000;
    map_physical_to_virtual(phys_addr, addr);

    addr += 0x060; // offset to the data_code field in the microcode header, which is what we will write to with WRMSR
    struct opcode_result out;

    setup_l1miss_pmc();

    u64 time = 0;
    u64 l1_hits = 0;
    u64 l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits += !miss;

        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        u64 t = measure_access_time(addr);
        time += t;
    }

    pr_info("%-60s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
            "READ_ONCE(addr); PATCH_LOADER, uTag(addr) = uTag(HT)", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    addr = (uint8_t *)0x00007fff00100000;
    map_physical_to_virtual(phys_addr, addr);
    addr += 0x060;

    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits += !miss;

        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        u64 t = measure_access_time(addr);
        time += t;
    }

    pr_info("%-60s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
            "READ_ONCE(addr); PATCH_LOADER, uTag(addr) != uTag(HT)", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        flush_cache_line_fenced(addr);
        READ_ONCE(*addr);
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits += !miss;

        flush_cache_line_fenced(addr);
        READ_ONCE(*addr);
        u64 t = measure_access_time(addr);
        time += t;
    }

    pr_info("%-60s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
            "READ_ONCE", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);
}


static void check_tsa_mitigation(struct microcode_amd *mc)
{
    

    struct opcode_result out;
    void *addr = (void *)&mc->hdr.data_code;
    setup_l1miss_pmc();

    u64 time = 0;
    u64 l1_hits = 0;
    u64 l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits += !miss;

        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        u64 t = measure_access_time(addr);
        time += t;
    }

    pr_info("%-60s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
            "READ_ONCE(addr); PATCH_LOADER", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    time = 0;
    l1_hits = 0;
    l1_misses = 0;

    for (int j = 0; j < ITERATIONS; j++)
    {
        READ_ONCE(*addr);
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits += !miss;

        READ_ONCE(*addr);
        u64 t = measure_access_time(addr);
        time += t;
    }

    pr_info("%-60s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
            "READ_ONCE(addr);", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);
}

static void log_ibs_trace(struct microcode_amd *mc)
{
    u8 *ptr = kmalloc(4096, GFP_KERNEL);
    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }


    int ret = ibs_log_open();
    if (ret)
    {
        pr_err("Failed to open IBS log: %d\n", ret);
        kfree(ptr);
        return;
    }
    struct opcode_result out;
    for (int i = 0; i < 1000000; i++)
    {
      

        write_ibs_ctrl(i);
        
        READ_ONCE(ptr[1]);
        READ_ONCE(ptr[2]);
        READ_ONCE(ptr[3]);
        READ_ONCE(ptr[4]);
        READ_ONCE(ptr[5]);
        READ_ONCE(ptr[6]);
        
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        
        READ_ONCE(ptr[1]);
        READ_ONCE(ptr[2]);
        READ_ONCE(ptr[3]);
        READ_ONCE(ptr[4]);
        READ_ONCE(ptr[5]);
        READ_ONCE(ptr[6]);

        log_ibs_ctrl(i);
    }

    ibs_log_finish();
    ibs_log_close();
    kfree(ptr);

    pr_info("IBS logging done\n");
}


static long ibs_routine(void *data)
{

    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    struct microcode_amd *mc;
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
    
    log_ibs_trace(mc);

    return 0;
}

static int __init patch_loader_init(void)
{
    int ret;

    ret = request_firmware(&fw, "amd-ucode/microcode_amd_fam19h.bin", NULL);
    if (ret)
    {
        pr_err("request_firmware failed: %d\n", ret);
        return ret;
    }

    work_on_cpu(CPU_NUMBER_IBS_USE, ibs_routine, NULL);

    release_firmware(fw);
    return -1;
}

static void __exit patch_loader_exit(void)
{
    printk(KERN_INFO "patch_loader: Exiting the module\n");
    return;
}

module_init(patch_loader_init);
module_exit(patch_loader_exit);
