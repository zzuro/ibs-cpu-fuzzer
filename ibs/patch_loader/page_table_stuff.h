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
#include <linux/mm.h> 
#include <asm/tlbflush.h>  


#define PAGE_PRESENT 0x1
#define PAGE_RW 0x2
#define PAGE_USER 0x4
#define NX_BIT (0x1ULL << 63)
#define PAGE_SIZE_4K 4096

#define PCD_BIT (0x1ULL << 4)

#define INVLPGB_FLAG_VA     BIT(0)
#define INVLPGB_FLAG_PCID   BIT(1)
#define INVLPGB_FLAG_ASID   BIT(2)
#define INVLPGB_FLAG_GLOBAL BIT(3)

enum addr_stride {
	PTE_STRIDE = 0,
	PMD_STRIDE = 1
};

void map_physical_to_virtual(unsigned long phys_addr, unsigned long virt_addr);
unsigned long get_physical_from_virtual(unsigned long virt_addr);
unsigned long * get_pte_address(unsigned long virt_addr);
void map_physical_to_virtual_4lvl(unsigned long phys_addr, unsigned long virt_addr);
unsigned long get_physical_from_virtual_4lvl(unsigned long virt_addr);
void invlpgb_flush(unsigned long addr);
void get_asid_4lvl(unsigned long virt_addr);