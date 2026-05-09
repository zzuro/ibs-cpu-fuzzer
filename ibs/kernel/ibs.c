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

#include "apic.h"
#include "msr.h"
#include "nmi.h"
#include "page_table_stuff.h"
#include "opcode_wrappers.h"
#include "swap.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Vezzù");
MODULE_DESCRIPTION("Kernel module to write a memory pointer to RAX and execute VMSAVE to a previously allocated page");
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

// Function to read an MSR
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

static u64 __maybe_unused rmpupdate_firmware(u64 paddr) {
    struct rmp_state state = {0};
    u64 ret;

    state.assigned = 1;
    state.pagesize = 0;
    state.immutable = 1;

    do {
        /* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
        asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
                     : "=a"(ret)
                     : "a"(paddr), "c"((unsigned long)&state)
                     : "memory", "cc");
    } while (ret == RMPUPDATE_FAIL_OVERLAP);

    pr_info("RMPUPDATE firmware call returned: %llu\n", ret);
    return ret;
}

static __always_inline uint64_t read_rdtscp(void)
{
    uint32_t lo, hi;
    asm volatile("rdtscp" : "=a"(lo), "=d"(hi) :: "rcx");
    return ((uint64_t)hi << 32) | lo;
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
        //pr_info("[RIP: 0x%016llx][uop cnt: %lld] [%8s] Branch[%3s] tagToRetire [%4d] compToRetire [%4d] micro [%3s] multiOP [%3s] branchTarget [0x%016llx] brnTaken [%s] brnMisp [%s]\n", rip_value, uop_cnt, "ALU", opData1.op_brn_ret ? "yes" : "no", opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr, opData1.op_microcode ? "yes" : "no", opData1.op_brn_fuse ? "yes" : "no", branch_target_rip, opData1.op_brn_taken ? "yes" : "no", opData1.op_brn_misp ? "yes" : "no");
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

struct gpr_state
{
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
};

static inline void read_gprs(struct gpr_state *out)
{
    __asm__ volatile(
        "mov %%rax, 0(%0)\n\t"
        "mov %%rbx, 8(%0)\n\t"
        "mov %%rcx, 16(%0)\n\t"
        "mov %%rdx, 24(%0)\n\t"
        "mov %%rsi, 32(%0)\n\t"
        "mov %%rdi, 40(%0)\n\t"
        "mov %%rbp, 48(%0)\n\t"
        "mov %%rsp, 56(%0)\n\t"
        "mov %%r8,  64(%0)\n\t"
        "mov %%r9,  72(%0)\n\t"
        "mov %%r10, 80(%0)\n\t"
        "mov %%r11, 88(%0)\n\t"
        "mov %%r12, 96(%0)\n\t"
        "mov %%r13, 104(%0)\n\t"
        "mov %%r14, 112(%0)\n\t"
        "mov %%r15, 120(%0)\n\t"
        :
        : "r"(out)
        : "memory");
}

void dump_gprs(void)
{
    struct gpr_state r;
    read_gprs(&r);

    pr_info("RAX=%016lx RBX=%016lx RCX=%016lx RDX=%016lx\n", r.rax, r.rbx, r.rcx, r.rdx);
    pr_info("RSI=%016lx RDI=%016lx RBP=%016lx RSP=%016lx\n", r.rsi, r.rdi, r.rbp, r.rsp);
    pr_info("R8 =%016lx R9 =%016lx R10=%016lx R11=%016lx\n", r.r8, r.r9, r.r10, r.r11);
    pr_info("R12=%016lx R13=%016lx R14=%016lx R15=%016lx\n", r.r12, r.r13, r.r14, r.r15);
}

static inline int repe_scasq(const void *src, uint64_t value, size_t count)
{
    unsigned char zf;
    __asm__ volatile(
        "rep scasq\n\t"
        "setz %0"
        : "=q"(zf), "+D"(src), "+c"(count)
        : "a"(value)
        : "memory");
    return zf;
}

static inline int repe_cmpsb(const void *s1, const void *s2, size_t count)
{
    unsigned char zf;
    __asm__ volatile(
        "rep cmpsb\n\t"
        "setz %0"
        : "=q"(zf), "+S"(s1), "+D"(s2), "+c"(count)
        :
        : "memory");
    return zf;
}

static inline void rep_stosq(void *dst, uint64_t value, size_t count)
{
    __asm__ volatile(
        "rep stosq"
        : "+D"(dst), "+c"(count)
        : "a"(value)
        : "memory");
}

static inline void rep_movsq(void *dst, const void *src, size_t count)
{
    __asm__ volatile(
        "rep movsb"
        :
        : "D"(dst), "S"(src), "c"(count)
        : "memory");
}

static inline uint64_t rep_lodsq(const void *src, size_t count)
{
    uint64_t value = 0x0;
    __asm__ volatile(
        "rep lodsq"
        : "+S"(src), "+c"(count), "=a"(value)
        :
        : "memory");
    return value;
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

static inline void flush_tlb(void)
{
    uintptr_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
}

static __always_inline void flush_cache_line_fenced(const void *addr)
{
    asm volatile("mfence\n\t" ::: "memory");
    asm volatile("clflush (%0)\n\t" : : "r"(addr) : "memory");
    asm volatile("mfence\n\t" ::: "memory");
}

static struct task_struct *thread;

struct thread_data
{
    u64 lin_addr;
    u64 phys_addr1;
    u64 phys_addr2;
};

static void dummy_wake(void *info) {
    // Just a placeholder to trigger the interrupt delivery
    // Execution will return to the instruction after HLT on the target core
}

static int thread_fn(void *data)
{
    int target_cpu = CPU_NUMBER_IBS_USE; 

    while(true) {
        smp_call_function_single(target_cpu, dummy_wake, NULL, 1);
    }

    return 0;
}

static inline void prefetcht0_strict(const void *addr) {
    asm volatile("prefetchnta (%0)" :: "r"(addr) : "memory");
}

static inline u64 set_asid_bits(u64 val, u8 asid)
{
    /* Clear bits 46–53 */
    val &= ~(0xFFULL << 46);

    /* Set new ASID (only lower 8 bits used) */
    val |= ((u64)(asid & 0xFF) << 46);

    // val |= (1ULL << 51);
    return val;
}

static inline u64 set_c_bit(u64 val)
{
    return val | (1ULL << 51) ;
}

static inline unsigned long read_cr3(void) {
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

#define MY_PMC_IDX          0
#define MY_PERFEVTSEL_MSR   (0xc0010200ULL + MY_PMC_IDX * 2)
#define MY_PERFCTR_MSR      (0xc0010201ULL + MY_PMC_IDX * 2)

#define MY_PERFEVTSEL_VAL \
    ((0x60ULL)        | \
     (0x80ULL << 8)   | \
     (1ULL    << 17)  | \
     (1ULL    << 22)  | \
     (2ULL    << 40))

static void setup_l1miss_pmc(void)
{
    wrmsrl(MY_PERFCTR_MSR, 0ULL);
    wrmsrl(MY_PERFEVTSEL_MSR, MY_PERFEVTSEL_VAL);
}

static void mfence(void)
{
    asm volatile("mfence" ::: "memory");
}

#define PMC_BARRIER() \
    asm volatile(                        \
        "mfence\n\t"                     \
        "mov $0x80000005, %%eax\n\t"     \
        "cpuid\n\t"                      \
        : : : "eax","ebx","ecx","edx","memory")

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

uint64_t calculate_zen_utag(void *ptr) {
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
static void check_physcial_uTag(void *data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    struct thread_data *tdata = (struct thread_data *)data;

    u8 *ptr = (u8 *)kmalloc(4096, GFP_KERNEL);
    memset(ptr, 0xAA, 4096);

    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }   

    int offset = 0x610;
    volatile uint8_t *addr = (uint8_t *)tdata->lin_addr + offset;

    uint64_t mask =
    (1ULL << 13) | (1ULL << 26) |   // u1
    (1ULL << 14) | (1ULL << 25);    // u2

    pr_info("alias mask: 0x%llx\n", 0x345600000 ^ mask);

    uint64_t alias = tdata->phys_addr1 ^ mask;
    pr_info("Physical address: 0x%llx, Tag Physical Address: 0x%llx\n", tdata->phys_addr1, calculate_zen_utag((void*)tdata->phys_addr1));
    pr_info("Alias address: 0x%llx, Tag Alias Address: 0x%llx\n", alias, calculate_zen_utag((void*)alias));

    volatile uint8_t *addr2 = (uint8_t *)alias;
   

    map_physical_to_virtual(tdata->phys_addr1, addr2);
    addr2 += offset;

    setup_l1miss_pmc();

    u64 time = 0;
    u64 l1_hits = 0;
    u64 l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        flush_cache_line_fenced(addr2);
        asm volatile("vmsave %0" :: "a"(tdata->phys_addr1) : "memory");
        bool miss = is_l1_miss(addr2);
        l1_misses += miss;
        l1_hits   += !miss;

        flush_cache_line_fenced(addr2);
        asm volatile("vmsave %0" :: "a"(tdata->phys_addr1) : "memory");

        u64 t     = measure_access_time(addr2);
        time     += t;
    }

    pr_info("%-40s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "vmsave (uTag(PA) = uTag(VA))", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        flush_cache_line_fenced(addr);
        asm volatile("vmsave %0" :: "a"(tdata->phys_addr1) : "memory");
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits   += !miss;

        flush_cache_line_fenced(addr);
        asm volatile("vmsave %0" :: "a"(tdata->phys_addr1) : "memory");
        u64 t     = measure_access_time(addr);
        time     += t;
    }

    pr_info("%-40s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "vmsave (uTag(PA) != uTag(VA))", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);
    
    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        flush_cache_line_fenced(addr2);
        asm volatile("vmsave %0" :: "a"(tdata->phys_addr1) : "memory");

        x86_clear_cpu_buffers();
        bool miss = is_l1_miss(addr2);
        l1_misses += miss;
        l1_hits   += !miss;

        flush_cache_line_fenced(addr2);
        asm volatile("vmsave %0" :: "a"(tdata->phys_addr1) : "memory");

        x86_clear_cpu_buffers();
        u64 t     = measure_access_time(addr2);
        time     += t;
    }

    pr_info("%-40s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "vmsave VERW (uTag(PA) = uTag(VA))", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);


    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        flush_cache_line_fenced(addr);
        READ_ONCE(*addr);
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits   += !miss;

        flush_cache_line_fenced(addr);
        READ_ONCE(*addr);
        u64 t     = measure_access_time(addr);
        time     += t;
    }
    
    pr_info("%-40s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "READ_ONCE", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);    
        
        kfree(ptr);
}

static void ibs_routine_testest(void *data)
{

    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    struct thread_data *tdata = (struct thread_data *)data;

    uint64_t mask =
    (1ULL << 13) | (1ULL << 26) |   // u1
    (1ULL << 14) | (1ULL << 25);    // u2

    uint8_t* addr2 = (uint8_t*)0x00007fff00001000;
    uint8_t* addr1 = (uint8_t*)0x00007fff00000000;
    uint8_t* addr3 = (uint8_t*)0x00007fff00002000;
    uint8_t* addr4 = (uint8_t*)0x00007fff00003000;
    uint8_t* addr5 = (uint8_t*)0x00007fff00004000;
    uint8_t* addr6 = (uint8_t*)0x00007fff00005000;
    uint8_t* addr7 = (uint8_t*)0x00007fff00006000;
    uint8_t* addr8 = (uint8_t*)0x00007fff00007000;
    uint8_t* addr9 = (uint8_t*)0x00007fff00008000;

    void* buff1 = kmalloc(4096, GFP_KERNEL);
    void* buff2 = kmalloc(4096, GFP_KERNEL);

    map_physical_to_virtual(virt_to_phys(buff2), addr2);
    map_physical_to_virtual(virt_to_phys(buff1), addr1);
    map_physical_to_virtual(virt_to_phys(buff1), addr3);
    map_physical_to_virtual(virt_to_phys(buff1), addr4);
    map_physical_to_virtual(virt_to_phys(buff1), addr5);
    map_physical_to_virtual(virt_to_phys(buff1), addr6);
    map_physical_to_virtual(virt_to_phys(buff1), addr7);
    map_physical_to_virtual(virt_to_phys(buff1), addr8);
    map_physical_to_virtual(virt_to_phys(buff1), addr9);
    

    pr_info("addr1: 0x%llx, uTag(addr1): 0x%llx\n", (uint64_t)addr1, calculate_zen_utag(addr1));
    pr_info("addr2: 0x%llx, uTag(addr2): 0x%llx\n", (uint64_t)addr2, calculate_zen_utag(addr2));
    pr_info("addr3: 0x%llx, uTag(addr3): 0x%llx\n", (uint64_t)addr3, calculate_zen_utag(addr3));
    pr_info("addr4: 0x%llx, uTag(addr4): 0x%llx\n", (uint64_t)addr4, calculate_zen_utag(addr4));
    pr_info("addr5: 0x%llx, uTag(addr5): 0x%llx\n", (uint64_t)addr5, calculate_zen_utag(addr5));
    pr_info("addr6: 0x%llx, uTag(addr6): 0x%llx\n", (uint64_t)addr6, calculate_zen_utag(addr6));
    pr_info("addr7: 0x%llx, uTag(addr7): 0x%llx\n", (uint64_t)addr7, calculate_zen_utag(addr7));
    pr_info("addr8: 0x%llx, uTag(addr8): 0x%llx\n", (uint64_t)addr8, calculate_zen_utag(addr8));
    pr_info("addr9: 0x%llx, uTag(addr9): 0x%llx\n", (uint64_t)addr9, calculate_zen_utag(addr9));



    setup_l1miss_pmc();

    u64 time = 0;
    u64 l1_hits = 0;
    u64 l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        flush_cache_line_fenced(addr1);
        READ_ONCE(*addr1);
        x86_clear_cpu_buffers();
        bool miss = is_l1_miss(addr1);
        l1_misses += miss;
        l1_hits   += !miss;

        flush_cache_line_fenced(addr1);
        READ_ONCE(*addr1);
        x86_clear_cpu_buffers();
        u64 t     = measure_access_time(addr1);
        time     += t;
    }

    pr_info("%-35s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "READ_ONCE(addr1) VERW (0x0 = uTag(VA))", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        flush_cache_line_fenced(addr2);
        READ_ONCE(*addr2);
        x86_clear_cpu_buffers();
        bool miss = is_l1_miss(addr2);
        l1_misses += miss;
        l1_hits   += !miss;

        flush_cache_line_fenced(addr2);
        READ_ONCE(*addr2);
        x86_clear_cpu_buffers();
        u64 t     = measure_access_time(addr2);
        time     += t;
    }

    pr_info("%-35s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "READ_ONCE(addr2) VERW (0x0 != uTag(VA))", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    
}

static void ibs_routine__(void *data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    struct thread_data *tdata = (struct thread_data *)data;

    u8 *ptr = (u8 *)kmalloc(4096, GFP_KERNEL);
    memset(ptr, 0xAA, 4096);

    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }   

    pr_info("PA of allocated memory: %llx\n", get_physical_from_virtual_4lvl(tdata->lin_addr));
    pr_info("VA of allocated memory:  %llx\n", tdata->lin_addr);
    pr_info("cr3 value: 0x%llx\n", read_cr3());

   
    for (int j = 0; j < 200; j++)
    {
        ibs_analysis_opcode(OP_IN_DX_EAX, j, 0x80, tdata->lin_addr, ptr);
    }
    kfree(ptr);
}


// Target Physical Address (52-bit range)
#define TARGET_PA           0x000FFFFDFC000000ULL 
#define MTRR_TYPE_WB        0x06
#define MTRR_TYPE_WP        0x05   // Write-Protect: reads OK, writes -> #GP
#define MTRR_VCNT_MAX       8

// MSR Definitions
#define MSR_MTRR_VAR_BASE(i) (0x200 + (i) * 2)
#define MSR_MTRR_VAR_MASK(i) (0x201 + (i) * 2)

// BIT DEFINITIONS
#define MTRR_MASK_VALID     (1ULL << 11)

/* * The PhysMask (bits 51:12) defines the range size.
 * For a 4KB range, all bits in the mask field (51:12) must be 1.
 * 0x000F_FFFF_FFFF_F000 represents bits 51:12 set to 1.
 */
#define AMDP_PHYMASK_BASE   0x000FFFFFFFFF000ULL

int targeted_index = -1;

static int mtrr_inject_init(void) {
    int i;
    uint64_t mask_val;
    uint64_t base_setting;
    uint64_t mask_setting;

    // 1. Find an empty MTRR slot
    for (i = 0; i < MTRR_VCNT_MAX; i++) {
        rdmsrl(MSR_MTRR_VAR_MASK(i), mask_val);
        if (!(mask_val & MTRR_MASK_VALID)) {
            targeted_index = i;
            break;
        }
    }

    if (targeted_index == -1) {
        pr_err("MTRR_INJECT: No empty MTRR slots found!\n");
        return -EBUSY;
    }

    /* * 2. Program the Base
     * We only take the address bits from the target and OR in the type.
     * Ensure TARGET_PA is aligned to the 4KB boundary.
     */
    base_setting = (TARGET_PA & AMDP_PHYMASK_BASE) | MTRR_TYPE_WB;
    
    /* * 3. Program the Mask
     * The mask must have bits 51:12 set to 1 for a 4KB match.
     * Bits 63:52 MUST be 0.
     * Bit 11 is the Valid bit.
     */
    mask_setting = AMDP_PHYMASK_BASE | MTRR_MASK_VALID;

    pr_info("MTRR_INJECT: Using index %d. Base: 0x%llx Mask: 0x%llx\n", 
             targeted_index, base_setting, mask_setting);

    /*
     * WRITING ORDER MATTERS: 
     * Always write the Base first, then the Mask (which contains the Valid/Enable bit).
     */
    wrmsrl(MSR_MTRR_VAR_BASE(targeted_index), base_setting);
    wrmsrl(MSR_MTRR_VAR_MASK(targeted_index), mask_setting);
    
    return 0;
}


static void ibs_routine_888(void *data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    struct thread_data *tdata = (struct thread_data *)data;

    u8 *ptr = (u8 *)kmalloc(4096, GFP_KERNEL);
    memset(ptr, 0xAA, 4096);

    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }   

    
    mtrr_inject_init();
    int offset = 0x670;    
    tdata->lin_addr = 0x000ffffdfc000000;
    volatile uint8_t *addr = (uint8_t *)tdata->lin_addr + offset;   
    map_physical_to_virtual(tdata->phys_addr1, tdata->lin_addr);

    pr_info("VA of allocated memory:  %llx\n", tdata->lin_addr);


    setup_l1miss_pmc();

    u64 time = 0;
    u64 l1_hits = 0;
    u64 l1_misses = 0;

    
    uint32_t value;
    for (int j = 0; j < ITERATIONS; j++)
    {
         
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);

        __asm__ volatile (
            "movw $0x670, %%dx\n\t"
            "inl %%dx, %%eax"
            : "=a"(value)
            :
            : "dx"
        );

        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits   += !miss;

        __asm__ volatile (
            "movw $0x670, %%dx\n\t"
            "inl %%dx, %%eax"
            : "=a"(value)
            :
            : "dx"
        );
        u64 t     = measure_access_time(addr);
        time     += t;
    }

    pr_info("%-30s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "with outl: ", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);

        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits   += !miss;

        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        READ_ONCE(*(uint8_t *)addr);
        u64 t     = measure_access_time(addr);
        time     += t;
    }

    pr_info("%-30s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "without outl", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);
        
        kfree(ptr);
}

static void check_rmp_protection(u64 vaddr)
{
    struct opcode_result res;

    run_selected_opcode(OP_MOVL, 0xDEADBEEFDEADBEEF, vaddr, &res);
    pr_info("RESULT OF MOVL: rc=%d vec=%d\n", res.rc, res.vec);
}


static u64 __maybe_unused rmpupdate_pre_guest(u64 paddr, u32 asid){
	struct rmp_state state = {0};
	u64 ret;

	state.assigned = 1;
	state.pagesize = 0;
	state.immutable = 0;
	state.asid = asid;
	
	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)&state)
			     : "memory", "cc");
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	return ret;
}

static int psp_move_page(struct kvm *kvm, u64 hpa_src, u64 hpa_dst)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct psp_sev_cmd_move data = {0};
	u32 error = 0;
	int ret;

	if (!sev || !sev->snp_context)
		return -EINVAL;

	if (!IS_ALIGNED(hpa_src, PAGE_SIZE) || !IS_ALIGNED(hpa_dst, PAGE_SIZE))
		return -EINVAL;

	data.gctx_paddr = __psp_pa(sev->snp_context);
	data.page_size = 0; /* 4 KiB */
	data.src_paddr = hpa_src;
	data.dst_paddr = hpa_dst;

	pr_info("SNP_PAGE_MOVE gctx=%llx src=%llx dst=%llx asid=%u\n",
		data.gctx_paddr, data.src_paddr, data.dst_paddr, sev->asid);

	ret = sev_do_cmd(SEV_CMD_SNP_PAGE_MOVE, &data, &error);

	pr_info("SNP_PAGE_MOVE ret=%d fw_error=0x%x\n", ret, error);
	return ret;
}



static u64 __maybe_unused rmpupdate_pre_guest_failure(u64 paddr, u32 asid){
    struct rmp_state state = {0};
	u64 ret;

	state.assigned = 1;
	state.pagesize = 0;
	state.immutable = 1;
    state.rsvd = 1;
	state.asid = asid;
	
	asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)&state)
			     : "memory", "cc");

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name",
};
#endif

static struct list_head *kvm_vm_list;

static int resolve_symbols(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	if (!kallsyms_lookup_name) {
		pr_err("could not resolve kallsyms_lookup_name\n");
		return -ENXIO;
	}
#endif

	kvm_vm_list = (void *)kallsyms_lookup_name("vm_list");
	if (!kvm_vm_list) {
		pr_err("could not resolve KVM vm_list\n");
		return -ENXIO;
	}

	return 0;
}

static int find_snp_kvm(struct kvm **out_kvm, struct kvm_sev_info **out_sev, struct kvm_vcpu **vcpu_out)
{
	struct list_head *i;
	struct kvm *kvm;

	if (!out_kvm || !out_sev)
		return -EINVAL;

	*out_kvm = NULL;
	*out_sev = NULL;
    *vcpu_out = NULL;

	list_for_each(i, kvm_vm_list) {
		struct kvm_vcpu *vcpu;
		struct kvm_sev_info *sev;

		kvm = list_entry(i, struct kvm, vm_list);

		pr_info("candidate kvm=%px online_vcpus=%d\n",
			kvm, atomic_read(&kvm->online_vcpus));

		if (atomic_read(&kvm->online_vcpus) <= 0)
			continue;

		vcpu = xa_load(&kvm->vcpu_array, 0);
		if (!vcpu)
			continue;

		*out_kvm = kvm;
		*out_sev = sev;
        *vcpu_out = vcpu;
		return 0;
	}

	return -ENOENT;
}

#define MSR_AMD64_PATCH_LEVEL   0x0000008B
#define MSR_AMD64_PATCH_LOADER  0xC0010020

#define UCODE_MAGIC             0x00414d44  /* "AMD\0" little-endian */
#define UCODE_EQUIV_CPU_TABLE   0x00000000
#define UCODE_UCODE_TYPE        0x00000001

#define CONTAINER_HDR_SIZE      12
#define SECTION_HDR_SIZE        8

struct equiv_cpu_entry {
    u32 installed_cpu;
    u32 fixed_errata_mask;
    u32 fixed_errata_compare;
    u16 equiv_cpu;
    u16 res;
} __packed;

struct microcode_header_amd {
    u32 data_code;
    u32 patch_id;
    u16 mc_patch_data_id;
    u8  mc_patch_data_len;
    u8  init_flag;
    u32 mc_patch_data_checksum;
    u32 nb_dev_id;
    u32 sb_dev_id;
    u16 processor_rev_id;
    u8  nb_rev_id;
    u8  sb_rev_id;
    u8  bios_api_rev;
    u8  reserved1[3];
    u32 match_reg[8];
} __packed;

struct microcode_amd {
    struct microcode_header_amd hdr;
    unsigned int mpb[];
} __packed;

struct selected_patch {
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

    stepping  = (patch_id >> 8)  & 0xf;
    model     = (patch_id >> 12) & 0xf;
    ext_model = (patch_id >> 20) & 0xf;
    ext_fam   = (patch_id >> 24) & 0xff;

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

    while (left >= CONTAINER_HDR_SIZE) {
        const u32 *container_hdr = (const u32 *)p;
        u32 magic;
        u32 first_type;
        u32 first_size;
        const u8 *q;
        size_t qleft;

        magic = container_hdr[0];
        first_type = container_hdr[1];
        first_size = container_hdr[2];

        if (magic != UCODE_MAGIC) {
            pr_err("bad AMD microcode container magic: 0x%08x\n", magic);
            return NULL;
        }

        if (left < CONTAINER_HDR_SIZE + first_size) {
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

        while (qleft >= SECTION_HDR_SIZE) {
            const u32 *sec = (const u32 *)q;
            u32 sec_type = sec[0];
            u32 sec_size = sec[1];
            struct microcode_amd *mc;
            u32 patch_cpuid;

            if (sec_type != UCODE_UCODE_TYPE) {
                /*
                 * Probably start of another glued container or unknown section.
                 * Stop this container scan.
                 */
                break;
            }

            if (sec_size < sizeof(struct microcode_header_amd)) {
                pr_err("patch section too small: %u\n", sec_size);
                return NULL;
            }

            if (qleft < SECTION_HDR_SIZE + sec_size) {
                pr_err("truncated patch section\n");
                return NULL;
            }

            mc = (struct microcode_amd *)(q + SECTION_HDR_SIZE);

            if (mc->hdr.nb_dev_id || mc->hdr.sb_dev_id) {
                pr_info("skip chipset-specific patch 0x%08x\n",
                        mc->hdr.patch_id);
                goto next_patch;
            }

            patch_cpuid = amd_patch_id_to_cpuid_eax(mc->hdr.patch_id);

            pr_info("candidate patch_id=0x%08x patch_cpuid=0x%08x size=%u\n",
                    mc->hdr.patch_id, patch_cpuid, sec_size);

            if (patch_cpuid == cpuid_eax) {
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

#include <linux/firmware.h>
static const struct firmware *fw;
static void ibs_routine(void * data)
{

    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);


    struct microcode_amd *mc;
    u32 cpuid_eax;
    u32 patch_size = 0;


    struct thread_data *tdata = (struct thread_data *)data;

    u8* ptr = kmalloc(4096, GFP_KERNEL);
    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }


    cpuid_eax = my_cpuid_1_eax();
    pr_info("CPUID(1).EAX = 0x%08x current_patch_level=0x%08x\n",
            cpuid_eax, get_patch_level());

    pr_info("firmware virtual address: %px size=%zu\n", fw->data, fw->size);


     if (!verify_container(fw->data, fw->size)) {
        pr_err("not a valid AMD microcode container\n");
        return;
    }

    mc = find_matching_zen_patch(fw->data, fw->size,
                                 cpuid_eax, &patch_size);
    if (!mc) {
        pr_err("no matching Zen/Zen4 patch found\n");
        return;
    }

    pr_info("selected patch_id=0x%08x processor_rev_id=0x%04x patch_addr=%px patch_size=%u\n",
            mc->hdr.patch_id,
            mc->hdr.processor_rev_id,
            &mc->hdr.data_code,
            patch_size);
    


    for(int i = 0; i < 6000; i++)
    {
        ibs_analysis_opcode(OP_WRMSR, i, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, ptr);
    }

    uint64_t phys_addr = virt_to_phys(kmalloc(4096, GFP_KERNEL));
    uint8_t *addr = (uint8_t*)0x000ffffdf7003000;
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
        l1_hits   += !miss;

        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        u64 t     = measure_access_time(addr);
        time     += t;
    }

    pr_info("%-60s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "READ_ONCE(addr); PATCH_LOADER, uTag(addr) = uTag(HT)", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);
    
    addr = (uint8_t*)0x00007fff00100000;
    map_physical_to_virtual(phys_addr, addr);
    addr += 0x945; 
    
    time = 0;
    l1_hits = 0;
    l1_misses = 0;
    for (int j = 0; j < ITERATIONS; j++)
    {
        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        bool miss = is_l1_miss(addr);
        l1_misses += miss;
        l1_hits   += !miss;

        READ_ONCE(*addr);
        run_selected_opcode(OP_WRMSR, MSR_AMD64_PATCH_LOADER, &mc->hdr.data_code, &out);
        u64 t     = measure_access_time(addr);
        time     += t;
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
        l1_hits   += !miss;

        flush_cache_line_fenced(addr);
        READ_ONCE(*addr);
        u64 t     = measure_access_time(addr);
        time     += t;
    }

    pr_info("%-60s -> avg: %llu cycles | hits: %llu misses: %llu, ITERATIONS: %u\n",
        "READ_ONCE", time / ITERATIONS, l1_hits, l1_misses, ITERATIONS);

    kfree(ptr);
    
}

#define MTRR_VAR_COUNT 8

static const char *mtrr_type_name(u8 type)
{
	switch (type) {
	case 0x0: return "UC (uncacheable)";
	case 0x1: return "WC (write-combining)";
	case 0x4: return "WT (write-through)";
	case 0x5: return "WP (write-protect)";
	case 0x6: return "WB (write-back)";
	case 0x7: return "UC- (uncacheable minus)";
	default:  return "Reserved/unsupported";
	}
}

#define TEST_MTRR_INDEX     7
#define MTRR_VAR_BASE_MSR   (0x200 + TEST_MTRR_INDEX * 2)
#define MTRR_VAR_BASE0     0x200
#define MTRR_PHYBASE_MASK   GENMASK_ULL(51, 12)

#define MTRR_PHYS_ADDR_MASK  0x000FFFFFFFFF000ULL  // bits 51:12

static void ibs_routine_mtrr(void * data)
{

    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    u8* ptr = kmalloc(4096, GFP_KERNEL);
    u64 physical = virt_to_phys(ptr);
    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }

	u64 val;
	int i;

	pr_info("Dumping variable MTRR base MSRs 0x200..0x20e\n");

	for (i = 0; i < MTRR_VAR_COUNT; i++) {
		u32 msr = MTRR_VAR_BASE0 + (i * 2);
		u64 phys_base;
		u8 mem_type;

		val = read_msr(msr);
		mem_type  = val & 0x7;
		phys_base = val & GENMASK_ULL(51, 12);

		pr_info("MTRRVarBase[%d] MSR 0x%03x = 0x%016llx\n",
			i, msr, val);
		pr_info("  PhyBase : 0x%013llx\n", phys_base);
		pr_info("  MemType : 0x%x %s\n",
			mem_type, mtrr_type_name(mem_type));
	}

    u64 phys;
	u64 new_base;
    u64 old_base;

	void * buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	phys = virt_to_phys(buf);

	old_base = read_msr(MTRR_VAR_BASE_MSR);
	new_base = (phys & MTRR_PHYBASE_MASK) | MTRR_TYPE_WB;

	pr_info("kmalloc virt = %px\n", buf);
	pr_info("kmalloc phys = 0x%llx\n", phys);
	pr_info("old MTRRVarBase[%d] MSR 0x%x = 0x%016llx\n",
		TEST_MTRR_INDEX, MTRR_VAR_BASE_MSR, old_base);
	pr_info("writing new base = 0x%016llx, type = WB\n", new_base);
    
    flush_cache_line_fenced(buf);
    __write_msr(MTRR_VAR_BASE_MSR, new_base);

    /* serialize the MSR write into the CPU pipeline */
    asm volatile("cpuid" ::: "eax","ebx","ecx","edx","memory");

    /* touch the physical address that new_base points to */
    volatile u8 dummy = *(volatile u8 *)buf;
    (void)dummy;

    /* measure if that access was cached or not */
    u64 cycles = measure_access_time(buf);
    pr_info("Access time after MTRR update: %llu cycles\n", cycles);

}

static void smm_lock(void *data)
{
    /* ------------------------------------------------------------------ */
    /* 0. Check SmmLock                                                    */
    /* ------------------------------------------------------------------ */
    u64 hwcr = read_msr(0xC0010015);
    if (hwcr & BIT_ULL(0)) {
        pr_err("HWCR.SmmLock = 1 — SMM_BASE is locked, aborting\n");
        return;
    }

    /* ------------------------------------------------------------------ */
    /* 1. Allocate contiguous physical buffer large enough for SMRAM       */
    /*    SMI save state is written at SMM_BASE + 0x7E00, so we need      */
    /*    at least 0x8000 bytes of contiguous physical memory              */
    /* ------------------------------------------------------------------ */
    unsigned int order   = get_order(0x8000);
    void        *smm_buf = (void *)__get_free_pages(GFP_KERNEL, order);
    if (!smm_buf) {
        pr_err("Failed to allocate SMRAM buffer\n");
        return;
    }
    memset(smm_buf, 0, 0x8000);
    u64 smm_phys = virt_to_phys(smm_buf);

    pr_info("SMRAM buffer virt = %px\n",   smm_buf);
    pr_info("SMRAM buffer phys = 0x%llx\n", smm_phys);

    /* ------------------------------------------------------------------ */
    /* 2. Save old SMM_BASE                                                */
    /* ------------------------------------------------------------------ */
    u64 old_smm_base = read_msr(0xC0010111);
    pr_info("old SMM_BASE = 0x%llx\n", old_smm_base);

    /* ------------------------------------------------------------------ */
    /* 3. Flush our buffer from cache so we can observe microcode's access */
    /* ------------------------------------------------------------------ */
    clflush_cache_range(smm_buf, 0x8000);
    mfence();

    /* ------------------------------------------------------------------ */
    /* 4. Write our physical address into SMM_BASE                         */
    /* ------------------------------------------------------------------ */
    __write_msr(0xC0010111, smm_phys);
    pr_info("wrote SMM_BASE = 0x%llx\n", smm_phys);

    /* serialize */
    asm volatile("cpuid" ::: "eax","ebx","ecx","edx","memory");

    /* ------------------------------------------------------------------ */
    /* 5. Trigger SMI — microcode will write save state to smm_phys+0x7E00*/
    /* ------------------------------------------------------------------ */
    outb(0x00, 0xB2);   /* ACPI SMI command port */

    /* SMI handler runs here (original SMM code at old_smm_base),         */
    /* but save state is written to our smm_phys+0x7E00 by microcode      */
    /* on SMI entry before the handler even runs                           */

    mfence();

    /* ------------------------------------------------------------------ */
    /* 6. Measure latency — save state area is at offset 0x7E00           */
    /*    microcode wrote there → those cache lines should now be hot      */
    /* ------------------------------------------------------------------ */
    volatile u8 *save_state = (volatile u8 *)smm_buf + 0x7E00;

    u64 cycles = measure_access_time((void *)save_state);
    pr_info("latency at smm_buf+0x7E00 after SMI: %llu cycles (%s)\n",
            cycles,
            cycles < 50 ? "CACHED (microcode touched it)" : "UNCACHED (miss)");

    /* ------------------------------------------------------------------ */
    /* 7. Restore old SMM_BASE                                             */
    /* ------------------------------------------------------------------ */
    __write_msr(0xC0010111, old_smm_base);
    pr_info("SMM_BASE restored to 0x%llx\n", old_smm_base);

    /* ------------------------------------------------------------------ */
    /* 8. Cleanup                                                          */
    /* ------------------------------------------------------------------ */
    free_pages((unsigned long)smm_buf, order);
}

#define SLB_SIZE (64 * 1024)
static void ibs_routine_trace(void *data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    struct thread_data *tdata = (struct thread_data *)data;

    u8 *ptr = (u8 *)kmalloc(4096, GFP_KERNEL);
    memset(ptr, 0xAA, 4096);

    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }
    
    u64 apic_base = read_msr(0x1B) & 0xFFFFFFFFFFFFF000ULL;
    pr_info("APIC Base: 0x%llx\n", apic_base);

    struct opcode_result res;
    for (int j = 0; j < 6000; j++)
    {
        
        ibs_analysis_opcode(OP_WRMSR, j, 0x0000010B, 1, ptr);
        
        // write_ibs_ctrl(j);

        // READ_ONCE(ptr[1]);
        // READ_ONCE(ptr[2]);
        // READ_ONCE(ptr[3]);
        // READ_ONCE(ptr[4]);
        // READ_ONCE(ptr[5]);
        // READ_ONCE(ptr[6]);

        // x86_clear_cpu_buffers();

        // READ_ONCE(ptr[1]);
        // READ_ONCE(ptr[2]);
        // READ_ONCE(ptr[3]);
        // READ_ONCE(ptr[4]);
        // READ_ONCE(ptr[5]);
        // READ_ONCE(ptr[6]);


        // read_ibs_ctrl(j, res.rip);
    }

    kfree(ptr);
}

static u64 rmpupdate_pre_hv(u64 paddr, u8 read_only)
{
	struct rmp_state state = {0};
	u64 ret;

	state.assigned = 0;   /* hypervisor-owned / shared */
	state.pagesize = 0;   /* 4K page */
	state.immutable = read_only;

	do {
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)&state)
			     : "memory", "cc");
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	return ret;
}

static int __sev_issue_cmd(int fd, int id, void *data, int *error)
{
	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	return sev_issue_cmd_external_user(fd_file(f), id, data, error);
}

static int sev_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = to_kvm_sev_info(kvm);

	return __sev_issue_cmd(sev->fd, id, data, error);
}

static unsigned int sev_get_asid(struct kvm *kvm)
{
	return to_kvm_sev_info(kvm)->asid;
}

static int snp_bind_asid(struct kvm *kvm, int *error)
{
	struct kvm_sev_info *sev = to_kvm_sev_info(kvm);
	struct sev_data_snp_activate data = {0};

	data.gctx_paddr = __psp_pa(sev->snp_context);
	data.asid = sev_get_asid(kvm);
	return sev_issue_cmd(kvm, SEV_CMD_SNP_ACTIVATE, &data, error);
}


static void ibs_routine_update(void *data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    u8 *ptr = kmalloc(4096, GFP_KERNEL);
    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }

    struct kvm *kvm;
    struct kvm_sev_info *sev;
    struct kvm_vcpu *vcpu;
    u64 gctx_paddr;
    int ret;

    ret = resolve_symbols();
    if (ret)
        return;

    ret = find_snp_kvm(&kvm, &sev, &vcpu);
    if (ret)
    {
        pr_err("SNP KVM object not found: %d\n", ret);
        return;
    }

    sev = to_kvm_sev_info(kvm);
    gctx_paddr = __psp_pa(sev->snp_context);

    pr_info("kvm=%px\n", kvm);
    pr_info("sev=%px\n", sev);
    pr_info("sev->asid=%u\n", sev->asid);
    pr_info("gctx_paddr=0x%llx\n", gctx_paddr);
    struct vcpu_svm *svm = to_svm(vcpu); 
    pr_info("vmsa_pa: 0x%llx\n", svm->vmcb->control.vmsa_pa);
    // map_physical_to_virtual(svm->vmcb->control.vmsa_pa, (u64)ptr);

    // check_rmp_protection((u64)ptr);
}



static void ibs_routine_vmcb_switch(void *data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    u8* ptr = kmalloc(4096, GFP_KERNEL);
    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }

    struct kvm *kvm;
	struct kvm_sev_info *sev;
    struct kvm_vcpu *vcpu;
	int ret;

    ret = resolve_symbols();
    if (ret)
        return;

	ret = find_snp_kvm(&kvm, &sev, &vcpu);
	if (ret) {
		pr_err("SNP KVM object not found: %d\n", ret);
		return;
	}
    
    struct vcpu_svm *svm = to_svm(vcpu);
    
    pr_info("pa of current VMCB: 0x%llx\n", svm->current_vmcb->pa);
    ret = rmpupdate_pre_guest(svm->current_vmcb->pa, 0x3);
    if(ret){
        pr_info("RMPUPDATE failed: %d\n", ret);
        return;
    }


}

/**
 * mtrr_write_protect_pa - Mark a 4KB-aligned physical address as write-protected.
 *
 * @pa:        The physical address to protect (will be aligned down to 4KB).
 * @out_index: Optional. If non-NULL, receives the MTRR slot index used.
 *
 * Returns 0 on success, -EBUSY if no free MTRR slot is available,
 *         -EINVAL if the address exceeds the 52-bit physical range.
 */
static int mtrr_write_protect_pa(uint64_t pa, int *out_index)
{
    int i, targeted_index = -1;
    uint64_t mask_val;
    uint64_t base_setting;
    uint64_t mask_setting;

    /* Validate: must fit in 52-bit physical address space */
    if (pa & ~0x000FFFFFFFFFFFFFULL) {
        pr_err("MTRR_WP: Address 0x%llx exceeds 52-bit PA space\n", pa);
        return -EINVAL;
    }

    /* Align down to 4KB boundary — MTRR granularity */
    pa = pa & MTRR_PHYS_ADDR_MASK;

    /* Find a free (invalid) MTRR slot */
    for (i = 0; i < MTRR_VCNT_MAX; i++) {
        rdmsrl(MSR_MTRR_VAR_MASK(i), mask_val);
        if (!(mask_val & MTRR_MASK_VALID)) {
            targeted_index = i;
            break;
        }
    }

    if (targeted_index == -1) {
        pr_err("MTRR_WP: No empty MTRR slots available\n");
        return -EBUSY;
    }

    /*
     * Base register:
     *   Bits 51:12 = physical address
     *   Bits  7:0  = memory type (0x05 = WP)
     */
    base_setting = (pa & MTRR_PHYS_ADDR_MASK) | MTRR_TYPE_WP;

    /*
     * Mask register:
     *   Bits 51:12 = all 1s  -> 4KB exact match
     *   Bit     11 = 1       -> Valid/Enable
     *   Bits 63:52 = 0       -> must be zero (reserved)
     */
    mask_setting = MTRR_PHYS_ADDR_MASK | MTRR_MASK_VALID;

    pr_info("MTRR_WP: Slot %d | PA: 0x%llx | Base: 0x%llx | Mask: 0x%llx\n",
            targeted_index, pa, base_setting, mask_setting);

    /*
     * Write order matters: Base first, then Mask.
     * The Valid bit in Mask is what activates the entry —
     * Base must already be correct before that happens.
     */
    wrmsrl(MSR_MTRR_VAR_BASE(targeted_index), base_setting);
    wrmsrl(MSR_MTRR_VAR_MASK(targeted_index), mask_setting);

    if (out_index)
        *out_index = targeted_index;

    return 0;
}

/**
 * mtrr_clear_slot - Disable and zero out a variable MTRR slot.
 *
 * Call this to undo a previous mtrr_write_protect_pa().
 * Always clear the Mask (Valid bit) before zeroing the Base.
 */
static void mtrr_clear_slot(int index)
{
    if (index < 0 || index >= MTRR_VCNT_MAX) {
        pr_err("MTRR_WP: Invalid slot index %d\n", index);
        return;
    }

    /* Disable (clear Valid bit) before touching Base */
    wrmsrl(MSR_MTRR_VAR_MASK(index), 0ULL);
    wrmsrl(MSR_MTRR_VAR_BASE(index), 0ULL);

    pr_info("MTRR_WP: Slot %d cleared\n", index);
}

static void ibs_routine_rmp(void* data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    struct thread_data *tdata = (struct thread_data *)data;

    u8 *ptr = (u8 *)kmalloc(4096, GFP_KERNEL);
    memset(ptr, 0xAA, 4096);

    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }

    function_address = (u64) ibs_routine;
	recover_address = (u64) &&recovery_label;

    int ret = rmpupdate_firmware(virt_to_phys(ptr));
    if(ret)
    {
        pr_info("RMPUPDATE failed with %d\n", ret);
        return;
    }
    
    pr_info("ptr befor write: 0x%llx\n", *(u64*)ptr);
    check_rmp_protection((u64)ptr);
    

recovery_label:

    pr_info("ptr after write: 0x%llx\n", *(u64*)ptr);
}

static int __init vmsave_module_init(void)
{
    
    size_t buff_size = 4096 * 3;
    void *va_addr = vmalloc(buff_size);


    struct thread_data tdata;
    tdata.lin_addr = (u64)va_addr;

    void *src_buff1 = kmalloc(buff_size, GFP_KERNEL);
    void *src_buff2 = kmalloc(buff_size, GFP_KERNEL);

    tdata.phys_addr1 = virt_to_phys(src_buff1);
    tdata.phys_addr2 = virt_to_phys(src_buff2);
    map_physical_to_virtual(virt_to_phys(src_buff1), tdata.lin_addr);
    map_physical_to_virtual(virt_to_phys(src_buff1) + 0x1000, tdata.lin_addr + 0x1000);
    map_physical_to_virtual(virt_to_phys(src_buff1) + 0x2000, tdata.lin_addr + 0x2000);
    memset(src_buff1, 0xAA, buff_size);
    memset(src_buff2, 0xBB, buff_size);


    int ret;

    ret = request_firmware(&fw,
                           "amd-ucode/microcode_amd_fam19h.bin",
                           NULL);
    if (ret) {
        pr_err("request_firmware failed: %d\n", ret);
        return ret;
    }

    smp_call_function_single(CPU_NUMBER_IBS_USE, ibs_routine, &tdata, 1);
    /*
     * fw->data points to the loaded file contents.
     * Only valid until release_firmware(fw).
     */

    release_firmware(fw);


    // pr_info("Physical address 1: 0x%llx\n", tdata.phys_addr1);
    // pr_info("Physical address 2: 0x%llx\n", tdata.phys_addr2);
    // //pr_info("PA of allocated memory: %llx\n", get_physical_from_virtual_4lvl(tdata.lin_addr));

    // // hexdump(src_buff1, 64);
    // // pr_info("--------------------------------------------------\n");
    // // hexdump(src_buff2, 64 );

    kfree(src_buff1);
    kfree(src_buff2);
    return -1;
}

static void __exit vmsave_module_exit(void)
{
    printk(KERN_INFO "vmsave_module: Exiting the module\n");
    return;
}

module_init(vmsave_module_init);
module_exit(vmsave_module_exit);
