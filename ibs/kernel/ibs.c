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


#include "apic.h"
#include "msr.h"
#include "nmi.h"
#include "page_table_stuff.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to write a memory pointer to RAX and execute VMSAVE to a previously allocated page");
MODULE_VERSION("1.0");

#define CPU_NUMBER_IBS_USE 5

#define BYTES_PER_LINE 16

static void __maybe_unused hexdump(const void *addr, size_t len) {
    const unsigned char *ptr = addr;
    size_t i, j;

    for (i = 0; i < len; i += BYTES_PER_LINE) {
        printk(KERN_INFO "%08lx: ", (unsigned long)(ptr + i));
        for (j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < len)
                printk(KERN_CONT "%02x ", ptr[i + j]);
            else
                printk(KERN_CONT "   ");
        }

        printk(KERN_CONT " | \n");
    }
}

// Function to read an MSR
static __always_inline uint64_t __read_msr(uint32_t msr_register) {
    uint64_t msr_value;
    uint32_t low, high;

    asm volatile(
        "rdmsr"
        : "=a"(low), "=d"(high)  // Output operands
        : "c"(msr_register)      // Input operand
    );

    msr_value = ((uint64_t)high << 32) | low;
    return msr_value;
}

// Function to write an MSR
static __always_inline void __write_msr(uint32_t msr_register, uint64_t msr_value) {
    uint32_t low = (uint32_t)msr_value;
    uint32_t high = (uint32_t)(msr_value >> 32);

    asm volatile(
        "wrmsr"
        :                                         // No output operands
        : "c"(msr_register), "a"(low), "d"(high)  // Input operands
    );
}

typedef union ibs_opt_ctrl {
    struct {
        u64 IbsOpMaxCnt2 : 16;    // 15:0
        u64 IbsOpL3MissOnly : 1;  // 16
        u64 IbsOpEn : 1;          // 17
        u64 IbsOpValid : 1;       // 18
        u64 IbsOpCntCtl : 1;      // 19
        u64 IbsOpMaxCnt1 : 7;     // 26:20
        u64 rsvd2 : 5;            // 31:27
        u64 IbsOpCurCnt : 27;     // 58:32
        u64 rsvd1 : 5;            // 63:59
    };
    u64 value;
} ibs_opt_ctrl;

typedef union ibs_op_data_1 {
    struct {
		u64 IbsCompToRetCtr : 16;       // bits 15:0
        u64 IbsTagToRetCtr : 16;        // bits 31:16
        u64 Reserved2 : 2;              // bits 33:32 (Reserved)
        u64 IbsOpReturn : 1;            // bit 34
        u64 IbsOpBrnTaken : 1;          // bit 35
        u64 IbsOpBrnMisp : 1;           // bit 36
        u64 IbsOpBrnRet : 1;            // bit 37
        u64 IbsRipInvalid : 1;          // bit 38
        u64 IbsOpFuse : 1;              // bit 39
        u64 IbsOpMicrocode : 1;         // bit 40
        u64 Reserved1 : 24;              // bits 63:40 (Reserved)
    } __attribute__((packed));
    u64 value;
} ibs_op_data_1;


typedef union ibs_op_data_3 {
    struct {
        u64 IbsOpLd : 1;                   // bit 0
        u64 IbsOpSt : 1;                   // bit 1
        u64 IbsDcL1tlbMiss : 1;            // bit 2
        u64 IbsDcL2tlbMiss : 1;            // bit 3
        u64 IbsDcL1tlbHit2M : 1;           // bit 4
        u64 IbsDcL1tlbHit1G : 1;           // bit 5
        u64 rsvd1 : 1;                     // bit 6
        u64 IbsDcMiss : 1;                 // bit 7
        u64 IbsDcMisAcc : 1;               // bit 8
        u64 rsvd2 : 3;                     // bits 11:9 (Reserved)
        u64 IbsDcWcMemAcc : 1;             // bit 12
        u64 IbsDcUcMemAcc : 1;             // bit 13
        u64 IbsDcLockedOp : 1;             // bit 14
        u64 DcMissNoMabAlloc : 1;          // bit 15
        u64 IbsDcLinAddrValid : 1;         // bit 16
        u64 IbsDcPhyAddrValid : 1;         // bit 17
        u64 rsvd3 : 1;                     // bit 18 (Reserved)
        u64 IbsL2Miss : 1;                 // bit 20
        u64 IbsSwPf : 1;                   // bit 21
        u64 IbsOpMemWidth : 4;             // bits 25:22
        u64 IbsOpDcMissOpMemReqs : 6;      // bits 31:26
        u64 IbsDcMissLat : 16;             // bits 47:32
        u64 IbsTlbRefillLat : 16;          // bits 63:48
    } __attribute__((packed));
    u64 value;
} ibs_op_data_3;


char *memwithStrings[] = {"0 ","1 ", "2 ", "4 ", "8 ", "16", "32", "64", "?8", "?9", "?A", "?B", "?C", "?D", "?C", "?E", "?F"};

static void noinline write_ibs_ctrl(u64 instruction_offset) {
    ibs_opt_ctrl ibs_op_ctl_data;
    ibs_op_ctl_data.value = __read_msr(IBS_OP_CTL);

    // zero everything
    ibs_op_ctl_data.value = 0;

    // ibs_op_ctl_data.IbsOpMaxCnt2 = (1 << 15);
    ibs_op_ctl_data.IbsOpMaxCnt1 = (1 << 5);
    ibs_op_ctl_data.IbsOpCurCnt = (1 << 25) - instruction_offset;
    ibs_op_ctl_data.IbsOpCntCtl = 1;  // 1 for counting micro ops / 0 for counting cycles
    ibs_op_ctl_data.IbsOpEn = 1;
    //ibs_op_ctl_data.rsvd2 = 0x1F;
    __write_msr(IBS_OP_CTL, ibs_op_ctl_data.value);
}

/*

                pr_info("[%6s%s] 0x%016llx (v=0x%016llx) UC[%s] WC[%s] CacheMiss [%s] tagToRetire [%4d] compToRetire [%4d] micro [%3s] multiOP [%3s]\n", opData3.IbsOpLd ? "load" : "store", memwithStrings[opData3.IbsOpMemWidth], phys_addr, lin_addr,
                        opData3.IbsDcWcMemAcc ? "+" : "-", opData3.IbsDcUcMemAcc ? "+" : "-", opData3.IbsDcMiss ? "+" : "-", opData1.IbsTagToRetCtr, opData1.IbsCompToRetCtr, opData1.IbsOpMicrocode ? "yes" : "no", opData1.IbsOpFuse ? "yes" : "no");
*/

static void __maybe_unused noinline read_ibs_ctrl(u64 uop_cnt, u64 rip_out) {
    ibs_opt_ctrl ibs_op_ctl_data;
    ibs_op_ctl_data.value = __read_msr(IBS_OP_CTL);

    if (ibs_op_ctl_data.IbsOpValid == 0) {
        //pr_info("IBS_OP_CTL failed\n");
        //return;
    }
    // pr_info("IBS_OP_CTL valid\n");

    u64 rip_value;
    rip_value = __read_msr(IBS_OP_RIP);
    if(rip_out != rip_value)
    {
        return;
    }
    // pr_info("IBS_OP_RIP: %llx\n", rip_value);

    // pr_info("Opcode: %llx\n", *(u64 *)rip_value);

    union ibs_op_data opData1;
    opData1.val = __read_msr(IBS_OP_DATA);

    union ibs_op_data3 opData3;
    opData3.val = __read_msr(IBS_OP_DATA3);

    u64 lin_addr = __read_msr(IBS_DC_LIN_AD);
    u64 phys_addr = __read_msr(IBS_DC_PHYS_AD);

    //u64 branch_target_rip = __read_msr(BP_IBSTGT_RIP);

    //if ((phys_addr & 0xfd00000000) == 0xfd00000000) {
    if (1) {
        if (opData3.ld_op == 1 || opData3.st_op == 1) {
            pr_info("[RIP: 0x%016llx][uop cnt: %lld] [%6s%s] 0x%016llx (v=0x%016llx) UC[%s] WC[%s] CacheMiss [%s] tagToRetire [%4d] compToRetire [%4d] \n",rip_value ,uop_cnt, opData3.ld_op ? "load" : "store", memwithStrings[opData3.op_mem_width], phys_addr, lin_addr,  opData3.dc_wc_mem_acc ? "+" : "-", opData3.dc_uc_mem_acc ? "+" : "-", opData3.dc_miss ? "+" : "-",opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr);
		} else {
            pr_info("[RIP: 0x%016llx][uop cnt: %lld] [%8s] Branch[%3s] tagToRetire [%4d] compToRetire [%4d] micro [%3s] multiOP [%3s]\n",rip_value, uop_cnt, "ALU", opData1.op_brn_ret ? "yes" : "no" , opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr, opData1.op_microcode ? "yes" : "no", opData1.op_brn_fuse ? "yes" : "no" );
        }
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


static __always_inline void __prefetchw(void *addr) {
    __asm__ __volatile__(
        "prefetchw (%0)"
        :
        : "r"(addr)
        : "memory");
}

static __always_inline void __prefetchnta(void *addr) {
    __asm__ __volatile__(
        "PREFETCHNTA (%0)"
        :
        : "r"(addr)
        : "memory");
}

static __always_inline void __prefetch(void *addr) {
    __asm__ __volatile__(
        "prefetch (%0)"
        :
        : "r"(addr)
        : "memory");
}

static __always_inline void __clflush(void *address) {
    __asm__ __volatile__(
        "clflush (%0)\n\t"
        :
        : "r"(address)
        : "memory");
}

static __always_inline void flush_pipeline(void) {
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__(
        "cpuid\n\t"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0)
        : "memory");
}

// void wbnoinvd(void) {
//     __asm__ __volatile__(
//         "wbnoinvd\n\t"
//         :
//         :
//         : "memory");
// }

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

    return ret;
}

static __always_inline void inline_outl(uint32_t port, uint32_t val)
{
    asm volatile ( "outl %0, %1" : : "a"(val), "Nd"(port) );
}

static inline unsigned long __read_cr3_ibs(void) {
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static inline void __write_cr3_ibs(u64 cr3_val) {
	asm volatile("mov %0,%%cr3": : "r" (cr3_val) : "memory");
}


static void dummy_callback_function(void) {
    asm volatile (        "nop\n\t"  // No operation, just a placeholder
    );
    // This function is called to trigger the VMSAVE instruction.
}

//src: https://binarydebt.wordpress.com/2018/11/16/try-catch-in-linux-kernel/
static void fault_handler(void)
{
    unsigned long bad = 0xdead000000000000UL; /* intentionally bogus */
        unsigned long val = 0;
        int vec = -1; /* -1 means “no fault” */

        asm volatile(
                "1: mov (%[addr]), %[out]\n\t"   /* may #PF */
                "movl $-1, %[vec]\n\t"           /* no exception happened */
                "2:\n\t"

                ".section .fixup,\"ax\"\n\t"
                "3:\n\t"
                "movl %%eax, %[vec]\n\t"
                "xor  %[out], %[out]\n\t"        /* val = 0 on fault */
                "jmp  2b\n\t"
                ".previous\n\t"

                _ASM_EXTABLE_FAULT(1b, 3b)
                : [out] "=&r"(val), [vec] "=&r"(vec)
                : [addr] "r"(bad)
                : "eax", "memory"
        );

        pr_info("read val=%lx, exception_vector=%d\n", val, vec);
}

static __always_inline int try_vmrun(u64 vmcb_pa, int *vec, u64 *rip_out)
{
        int rc;

        asm volatile(
        "movl $0, %[rc]\n\t"
        "movl $-1, %[vec]\n\t"

        "movq %[pa], %%rax\n\t"

        /* RIP of the vmrun instruction (address of label 1) */
        "leaq 1f(%%rip), %[rip]\n\t"

        "1: cpuid\n\t"
        "2:\n\t"

        ".section .fixup,\"ax\"\n\t"
        "3:\n\t"
        "movl %%eax, %[vec]\n\t"
        "movl $-1, %[rc]\n\t"
        "jmp 2b\n\t"
        ".previous\n\t"

        _ASM_EXTABLE_FAULT(1b, 3b)
        : [rc] "=&r"(rc),
          [vec] "=&r"(*vec),
          [rip] "=&r"(*rip_out)
        : [pa] "r"(vmcb_pa)
        : "rax", "cc", "memory"
    );


        return rc;
}

static void test_vmrun(u64 vmcb_pa, u64* rip_out)
{
        int vec, rc;
        rc = try_vmrun(vmcb_pa, &vec, rip_out);

        if (!rc) {
                pr_info("VMRUN executed successfully\n");
                return;
        }

        //pr_info("vmrun RIP = 0x%lx rc=%d vec=%d\n", rip, rc, vec);

        // if (vec == X86_TRAP_UD)
        //         pr_info(" (#UD: invalid opcode / SVM unavailable?)\n");
        // else if (vec == X86_TRAP_GP)
        //         pr_info(" (#GP: general protection)\n");
        // else
        //         pr_info(" (other exception)\n");
}


static void noinline ibs_analysis(u64 location, u8 *ptr){
    // function_address = (u64) ibs_analysis;
    // recover_address = (u64) &&recovery_label;
    //recover_address = function_address  + 0x;
    //pr_info("Delta address: %llx\n", (u64)&&recovery_label - (u64)function_address);
    
/*     u64 cr3val = __read_cr3_ibs();
    cr3val |= (1UL << 63);
    cr3val |= ~(1UL << 49); */
    map_physical_to_virtual(0x03ffd00000000,0xffffffffffffE000);
    map_physical_to_virtual(0x0000000001000,0xffffffffffffD000);

    //u64 *faulting_ptr = (u64 *)0xffffffffffffDff9;
    u64 *faulting_ptr = (u64 *)0xffffffffffffDfff;
   // void (*func_ptr)(void) = dummy_callback_function;

    write_ibs_ctrl(location);
    u64 rip;
    test_vmrun(0x03ffd00000000, &rip);
    // READ_ONCE(ptr[1]);
    // READ_ONCE(ptr[2]);
    // READ_ONCE(ptr[3]);
    // READ_ONCE(ptr[4]);
    // READ_ONCE(ptr[5]);
    // READ_ONCE(ptr[6]);
    // rmpupdate_firmware(0x0000);
    //__read_msr(0xC0010117);
    //__write_cr3_ibs(cr3val);

    //__write_msr(0xC0010117, 0x03ffd00000000);

/*     asm volatile (
        "movq %0, %%rax\n\t"   // Move phys_addr into RAX
        "vmsave\n\t"           // Execute the VMSAVE instruction
        : // No outputs
        : "r" (0x03ffd00000000)  // Input is the physical address of the allocated page
        : "%rax"                       // Clobber RAX
    ); */
/*     asm volatile (
        "movq %0, %%rax\n\t"   // Move phys_addr into RAX
        "vmload\n\t"           // Execute the VMLOAD instruction
        : //
        : "r" (0x03ffd00000000)  // Input is the physical address of the allocated page
        : "%rax"                       // Clobber RAX
    ); */

/*     asm volatile (
        "movq %[ptr], %%rax\n\t"   // Move the function pointer into %rax
        "call *%%rax"              // Indirect call to the function via %rax
        :
        : [ptr] "r" (func_ptr)
        : "rax"
    ); */
    //READ_ONCE(faulting_ptr[0]);

recovery_label:
    //inline_outl(0xFFFF, 0x80000000);
    // Read the value from the PCI_CONFIG_DATA (0xCFC) port
    u64 value = inl(0xcfc);
    // inline code here, we have markers in the beginning and end to help identify failures
    // WRITE_ONCE(ptr[1], 0xAB);
    // WRITE_ONCE(ptr[2], 0xAB);
    // WRITE_ONCE(ptr[3], 0xAB);
    // WRITE_ONCE(ptr[4], 0xAB);
    // WRITE_ONCE(ptr[5], 0xAB);
    // WRITE_ONCE(ptr[6], 0xAB);
    read_ibs_ctrl(location, rip);

    flush_pipeline();
    //__write_cr3_ibs(cr3val);

    if(location == -1) {
        goto recovery_label;
    }

}


static void ibs_routine(void *data) {
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    // Allocate a page of memory
    // disable interrupt based sampling, do it inline.
    ibs_apic_exit(NULL);

    u8 *ptr = (u8 *)kmalloc(4096, GFP_KERNEL);
    
    pr_info("Virtual address of allocated memory: %llx\n", (u64)ptr);

    if (!ptr) {
        pr_err("Failed to allocate memory\n");
        return;
    }
    //map_physical_to_virtual(0x400000000000,0xfffffffffffE0000);
    for (int j = 17; j < 130; j++) {
        ibs_analysis(j, ptr);
    }
}

static int __init vmsave_module_init(void) {
    /* 	if(initialize_nmi() != 0){
                    pr_err("Failed to initialize APIC\n");
                    return -1;
            } */

    smp_call_function_single(CPU_NUMBER_IBS_USE, ibs_routine, NULL, 1);

    // cleanup_nmi();
    return -1;
}

static void __exit vmsave_module_exit(void) {
    printk(KERN_INFO "vmsave_module: Exiting the module\n");
    return;
}

module_init(vmsave_module_init);
module_exit(vmsave_module_exit);
