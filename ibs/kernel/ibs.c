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
#include "opcode_wrappers.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Vezzù");
MODULE_DESCRIPTION("Kernel module to write a memory pointer to RAX and execute VMSAVE to a previously allocated page");
MODULE_VERSION("1.0");

#define CPU_NUMBER_IBS_USE 2

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

    // if (ibs_op_ctl_data.IbsOpValid == 0)
    // {
    //     return;
    // }

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
        pr_info("[RIP: 0x%016llx][uop cnt: %lld] [%8s] Branch[%3s] tagToRetire [%4d] compToRetire [%4d] micro [%3s] multiOP [%3s]\n", rip_value, uop_cnt, "ALU", opData1.op_brn_ret ? "yes" : "no", opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr, opData1.op_microcode ? "yes" : "no", opData1.op_brn_fuse ? "yes" : "no");
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

    if (res.rc == 0) {
        // pr_info("%s success RIP=0x%llx\n",
        //         opcode_table[id].name, res.rip);
    } else {
        pr_info("%s fault RIP=0x%llx vec=%d\n",
                opcode_table[id].name, res.rip, res.vec);
    }


    read_ibs_ctrl(location, res.rip);
}


static void ibs_routine(void *data)
{
    pr_info("IBS routine called on CPU %d\n", smp_processor_id());
    ibs_apic_exit(NULL);

    u8 *ptr = (u8 *)kmalloc(4096, GFP_KERNEL);

    pr_info("Virtual address of allocated memory: %llx\n", (u64)ptr);
    if (!ptr)
    {
        pr_err("Failed to allocate memory\n");
        return;
    }
    //105cfc000
    u8 *src_buf = kmalloc(4096, GFP_KERNEL);
    src_buf[0] = 0x41;
    src_buf[1] = 0x42;
    src_buf[2] = 0x43;
    src_buf[3] = 0x44;

    /* virtual address */
    pr_info("src_buf virtual address: %px\n", src_buf);
    /* physical address */
    pr_info("src_buf physical address: %pa\n", &(phys_addr_t){ virt_to_phys(src_buf) }); 
    pr_info("ptr physical address: %pa\n", &(phys_addr_t){ virt_to_phys(ptr) }); 
    /*
    4] src_buf virtual address: ff1590b98147c5d0
    [ 1230.701235] src_buf physical address: 0x000000010147c5d0
    [ 1230.701236] ptr physical address: 0x000000010149a000

    */
    u64 addr =  0xffff90b98147c000; //0x000590b98147c5d0
    //0x00000001099a9f60           10149a000
    map_physical_to_virtual_4lvl(0x10eccc000, addr);
    //memset((void*)addr, 0xAB, 4096);
    // for(int i = 0; i < PAGE_SIZE/2; i++) {
    //     *((u16*)(addr+i)) =  0xAABB;
    // }
    //*((u64*)(addr + 0xFF8)) = 0xdeadbeefdeadbeefULL;
    //*((u32*)(addr)+0x10) = 0xdeadbeef;
    //pr_info("va: %x\n", *((u16*)(addr + 0x3F8)));
    memset((void*)(addr), 0x0, 64 + 56);
    *((u64*)(addr)) = 0xdeadbeefdeadbeefULL;
    memset((void*)(addr + 64 + 60), 0xFFFEEF , 4);
    memset((void*)(addr + 128), 0x0, 4096-128);
    hexdump((const void *)addr, 4096);
    //pr_info("src_buf physical address: %pa\n", &(phys_addr_t){ virt_to_phys(src_buf) });

     /* Write the physical address of src_buf to ptr */

    // for(int i = 0; i < 8; i++) {
    //     *((u64*)(addr)+i) = 0xdeadbeefdeadbeefULL;
    //     pr_info("addr va: %llx\n", *((u64*)(addr)+i));
    // }
    
    // for (int j = 0; j < 300; j++)
    // {
    //    ibs_analysis_opcode(OP_OUTSD, j, 0x80, (u64)src_buf, ptr); 
    // }

    // u64 val = __read_msr(0xc0000103);
    // pr_info("Value read from MSR 0xc0010200: 0x%016llx\n", val);

    kfree(src_buf);
    kfree(ptr);

    // // u64 addr =  0xff1590b98147c000;
    // // map_physical_to_virtual(0x128cf1000, 0xff1590b98147c000);
    
    // // //*(u64*)addr = 0xdeadbeefdeadbeefULL;
	// for(int i = 0; i < 8; i++) {
    //     pr_info("addr va: %llx\n", *((u64*)(addr)+i));
    // }
}

static int __init vmsave_module_init(void)
{
    smp_call_function_single(CPU_NUMBER_IBS_USE, ibs_routine, NULL, 1);
    return -1;
}

static void __exit vmsave_module_exit(void)
{
    printk(KERN_INFO "vmsave_module: Exiting the module\n");
    return;
}

module_init(vmsave_module_init);
module_exit(vmsave_module_exit);
