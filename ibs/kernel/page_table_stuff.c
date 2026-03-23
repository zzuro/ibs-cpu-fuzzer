#include "page_table_stuff.h"


#define PAGE_PRESENT 0x1
#define PAGE_RW 0x2
#define PAGE_USER 0x4
#define NX_BIT (0x1ULL << 63)
#define PAGE_SIZE_4K 4096

#define PCD_BIT (0x1ULL << 4)

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
    asm volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
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

    asm volatile("invlpg (%0)" :: "r"(virt_addr) : "memory");
}
