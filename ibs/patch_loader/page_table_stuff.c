#include "page_table_stuff.h"

#define INVLPGB_VA              BIT(0)
#define INVLPGB_PCID            BIT(1)
#define INVLPGB_ASID            BIT(2)
#define INVLPGB_INCLUDE_GLOBAL  BIT(3)
#define INVLPGB_FINAL_ONLY      BIT(4)
#define INVLPGB_INCLUDE_NESTED  BIT(5)

static inline unsigned long read_cr3(void) {
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

void map_physical_to_virtual(unsigned long phys_addr, unsigned long virt_addr) {
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;
    
    // Get the base of PML5
    pml5 = (unsigned long *)phys_to_virt(read_cr3() & ~0xFFFull);
	
    // Compute indices for the 5-level page table
    index5 = (virt_addr >> 48) & 0x1FF;
    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    //pr_info("pml5 = %lx\n", (unsigned long)pml5);
    // Walk the 5-level paging hierarchy, allocating new tables if necessary
    if (!pml5[index5]) {
        pml5[index5] = virt_to_phys((void *)__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    //pr_info("pl5[index5] = %lx\n", pml5[index5]);
    pml4 = (unsigned long *)(unsigned long)phys_to_virt(pml5[index5] & PAGE_MASK);
    //pr_info("pml4 = %lx\n", (unsigned long)pml4);
    if (!pml4[index4]) {
        pml4[index4] = virt_to_phys((void *)__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    //pr_info("pl4[index4] = %lx\n", pml4[index4]);
    pdp = (unsigned long *)((unsigned long)phys_to_virt(pml4[index4]) & PAGE_MASK);
    //pr_info("pdp = %lx\n", (unsigned long)pdp);
    if (!pdp[index3]) {
        pdp[index3] = virt_to_phys((void *)__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    //pr_info("pdp[index3] = %lx\n", pdp[index3]);
    pd = (unsigned long *)((unsigned long)phys_to_virt(pdp[index3]) & PAGE_MASK);
    //pr_info("pd = %lx\n", (unsigned long)pd);
    if (!pd[index2]) {
        pd[index2] = virt_to_phys((void *)__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    //pr_info("pd[index2] = %lx\n", pd[index2]);
    pt = (unsigned long *)((unsigned long)phys_to_virt(pd[index2]) & PAGE_MASK);
    //pr_info("pt = %lx\n", (unsigned long)pt);
    if (!pt[index1]) {
        pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | NX_BIT;
    }else{
        pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | NX_BIT;
    }
    //pr_info("pt[index1] = %lx\n", pt[index1]);

    // Flush TLB
    invlpgb_flush(virt_addr);
}

unsigned long * get_pte_address(unsigned long virt_addr) {
   unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;
    unsigned long new_page;

    /* CR3 points to PML4 in 4-level paging */
    pml4 = (unsigned long *)phys_to_virt(read_cr3() & PAGE_MASK);

    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!(pml4[index4] & PAGE_PRESENT)) {
        new_page = __get_free_page(GFP_KERNEL);
        if (!new_page)
            return 0;
        memset((void *)new_page, 0, PAGE_SIZE);
        pml4[index4] = virt_to_phys((void *)new_page) | PAGE_PRESENT | PAGE_RW;
    }

    pdp = (unsigned long *)phys_to_virt(pml4[index4] & PAGE_MASK);

    if (!(pdp[index3] & PAGE_PRESENT)) {
        new_page = __get_free_page(GFP_KERNEL);
        if (!new_page)
            return 0;
        memset((void *)new_page, 0, PAGE_SIZE);
        pdp[index3] = virt_to_phys((void *)new_page) | PAGE_PRESENT | PAGE_RW;
    }

    pd = (unsigned long *)phys_to_virt(pdp[index3] & PAGE_MASK);

    if (!(pd[index2] & PAGE_PRESENT)) {
        new_page = __get_free_page(GFP_KERNEL);
        if (!new_page)
            return 0;
        memset((void *)new_page, 0, PAGE_SIZE);
        pd[index2] = virt_to_phys((void *)new_page) | PAGE_PRESENT | PAGE_RW;
    }

    pt = (unsigned long *)phys_to_virt(pd[index2] & PAGE_MASK);

    return &pt[index1];
}

unsigned long get_physical_from_virtual(unsigned long virt_addr)
{
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;
    unsigned long phys_base;

    pml5 = (unsigned long *)phys_to_virt(read_cr3() & PAGE_MASK);

    index5 = (virt_addr >> 48) & 0x1FF;
    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!pml5[index5])
        return 0;

    pml4 = (unsigned long *)phys_to_virt(pml5[index5] & PAGE_MASK);
    if (!pml4[index4])
        return 0;

    pdp = (unsigned long *)phys_to_virt(pml4[index4] & PAGE_MASK);
    if (!pdp[index3])
        return 0;

    pd = (unsigned long *)phys_to_virt(pdp[index3] & PAGE_MASK);
    if (!pd[index2])
        return 0;

    pt = (unsigned long *)phys_to_virt(pd[index2] & PAGE_MASK);
    if (!pt[index1])
        return 0;

    phys_base = pt[index1] & PAGE_MASK;

    return (phys_base | (virt_addr & ~PAGE_MASK)) & 0xFFFFFFFFFFFFF;
}

unsigned long get_physical_from_virtual_4lvl(unsigned long virt_addr)
{
    unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;
    unsigned long phys_base;

    pml4 = (unsigned long *)phys_to_virt(read_cr3() & PAGE_MASK);

    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!pml4[index4])
        return 0;

    pdp = (unsigned long *)phys_to_virt(pml4[index4] & PAGE_MASK);
    if (!pdp[index3])
        return 0;

    pd = (unsigned long *)phys_to_virt(pdp[index3] & PAGE_MASK);
    if (!pd[index2])
        return 0;

    pt = (unsigned long *)phys_to_virt(pd[index2] & PAGE_MASK);
    if (!pt[index1])
        return 0;

    phys_base = pt[index1] & PAGE_MASK;

    return (phys_base | (virt_addr & ~PAGE_MASK)) & 0xFFFFFFFFFFFFF;
}

static __always_inline void flush_cache_line_fenced(const void *addr)
{
    asm volatile("mfence\n\t" ::: "memory");
    asm volatile("clflush (%0)\n\t" : : "r"(addr) : "memory");
    asm volatile("mfence\n\t" ::: "memory");
}



void map_physical_to_virtual_4lvl(unsigned long phys_addr, unsigned long virt_addr)
{
    unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;
    unsigned long new_page;

    /* CR3 points to PML4 in 4-level paging */
    pml4 = (unsigned long *)phys_to_virt(read_cr3() & PAGE_MASK);

    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!(pml4[index4] & PAGE_PRESENT)) {
        new_page = __get_free_page(GFP_KERNEL);
        if (!new_page)
            return;
        memset((void *)new_page, 0, PAGE_SIZE);
        pml4[index4] = virt_to_phys((void *)new_page) | PAGE_PRESENT | PAGE_RW;
    }

    pdp = (unsigned long *)phys_to_virt(pml4[index4] & PAGE_MASK);

    if (!(pdp[index3] & PAGE_PRESENT)) {
        new_page = __get_free_page(GFP_KERNEL);
        if (!new_page)
            return;
        memset((void *)new_page, 0, PAGE_SIZE);
        pdp[index3] = virt_to_phys((void *)new_page) | PAGE_PRESENT | PAGE_RW;
    }

    pd = (unsigned long *)phys_to_virt(pdp[index3] & PAGE_MASK);

    if (!(pd[index2] & PAGE_PRESENT)) {
        new_page = __get_free_page(GFP_KERNEL);
        if (!new_page)
            return;
        memset((void *)new_page, 0, PAGE_SIZE);
        pd[index2] = virt_to_phys((void *)new_page) | PAGE_PRESENT | PAGE_RW;
    }

    pt = (unsigned long *)phys_to_virt(pd[index2] & PAGE_MASK);

    pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | NX_BIT;

    asm volatile("invlpg (%0)" : : "r"(virt_addr) : "memory");
    //invlpgb_flush(virt_addr);
}


static inline void my_invlpgb(unsigned long asid, unsigned long pcid,
			     unsigned long addr, u16 nr_pages,
			     enum addr_stride stride, u8 flags)
{
	u64 rax = addr | flags | INVLPGB_FLAG_ASID;
	u32 ecx = (stride << 31) | (nr_pages - 1);
	u32 edx = (pcid << 16) | asid;

	/* The low bits in rax are for flags. Verify addr is clean. */
	VM_WARN_ON_ONCE(addr & ~PAGE_MASK);

	/* INVLPGB; supported in binutils >= 2.36. */
	asm volatile(".byte 0x0f, 0x01, 0xfe" : : "a" (rax), "c" (ecx), "d" (edx));
}

static __always_inline void my_tlbsync(void)
{
    cant_migrate();
    asm volatile(".byte 0x0f, 0x01, 0xff" ::: "memory");
}

void invlpgb_flush(unsigned long addr)
{
    wmb();
    smp_mb(); // Ensure all previous memory operations are completed before invalidating TLB entries

    if(!cpu_feature_enabled(X86_FEATURE_INVLPGB)){
        pr_info("INVLPGB not supported on this CPU\n");
        return;
    }
    preempt_disable();
    my_invlpgb(0, 0, addr, 1, 0, INVLPGB_FLAG_VA | INVLPGB_FLAG_GLOBAL);
    my_tlbsync();
    preempt_enable();
}
