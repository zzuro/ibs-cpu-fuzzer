#include "ktypes.h"
#include "serial.h"
#include "interrupts.h"
#include "sevsnp.h"
#include "gdt.h"
#include "paging.h"
#include "memory.h"
#include "util.h"
#include "sse.h"
#include "vectorops.h"
#include <stdbool.h>

/*
    Ensure that we target the correct environment
*/
// #if defined(__linux__)
// #error "You are not using a cross-compiler, you will most certainly run into trouble"
// #endif

#if !defined(__i386__)
// #error "This tutorial needs to be compiled with a ix86-elf compiler"
#endif

extern char __data_start[], __data_end[], __data_load[];
extern char __bss_start[], __bss_end[];

#define PAGE_SIZE 4096
#define MAGIC_VALUE 0x1234DEADBEEF1234ULL
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#define BASE 0x300000 //this address will hold the fuzzing instruction address

static void init_data_bss(void)
{
    // copy .data from ROM to RAM
    for (char *dst = __data_start, *src = __data_load; dst < __data_end;)
        *dst++ = *src++;

    // zero .bss
    for (char *p = __bss_start; p < __bss_end;)
        *p++ = 0;
}



void __attribute__((noreturn)) kernel_main(void);

void __attribute__((noreturn)) kernel_main(void)
{

    init_data_bss();

    // See https://stackoverflow.com/questions/6385850/pointer-array-extern-question
    // Do NOT use a pointer!
    extern GDT_entry_t global_descriptor_table[];
    extern interrupts__descriptor_t interrupt_descriptor_table[];
    extern interrupts__idtr_t interrupts_idtr[];
    extern union paging__any_table_type paging_space[];

    // Set up by the bootloader
    serial_init();

    serial_puts("Installing GDT...");

    interrupts__cli();
    gdt__entry_make_null(global_descriptor_table);
    gdt__entry_make_kernel_mode_code_segment64(global_descriptor_table + 1);
    gdt__entry_make_kernel_mode_data_segment64(global_descriptor_table + 2);
    gdt__install_table(global_descriptor_table, 3, 0x10, 0x08);

    serial_puts(" OK!\n");

    serial_puts("Installing IDT...");
    for (size_t i = 0; i < N_IDT_ENTRIES_MAX; i++)
    {
        interrupts__fill_descriptor(interrupt_descriptor_table + i, interrupts__get_handler_for_exception(i), gdt__get_system_code_selector(), 0, 0x8E);
    }

    interrupts_idtr->size = ((uint16_t)sizeof(interrupts__descriptor_t) * N_IDT_ENTRIES_MAX) - 1;
    interrupts_idtr->offset = interrupt_descriptor_table;

    interrupts__load_idtr(interrupts_idtr);
    interrupts__sti();
    serial_puts(" OK!\n");

    serial_puts("Building page table...");

    
    // pd alias to map VA >= 4Gib to 0x00400000
    paging__pd_t *alias_pd = &paging_space[7].pd;
    for (u32 i = 0; i < 512; i++)
    {
        paging__pd_entry_t *e = &alias_pd->pd_entries[i];

        e->present = 1;
        e->read_write = 1;
        e->user_supervisor = 0;
        e->write_through = 0;
        e->cache_disable = 0;
        e->accessed = 1;

        e->page_size = 1;   
        e->ignored_1 = 1;
        e->reserved = 0;    
        e->xd = 0;

        e->pt_base_address = (0x00400000ULL >> 12);
    }

    // pdp alias to map VA >= 4Gib to 0x00400000
    paging__pdp_t *pdpt_alias = &paging_space[8].pdp;
    for (u16 i = 0; i < 512; i++)
    {
        paging__pdp_entry_t *e = &pdpt_alias->pdp_entries[i];

        e->present = 1;
        e->read_write = 1;
        e->user_supervisor = 0;
        e->write_through = 0;
        e->cache_disable = 0;
        e->accessed = 1;
        e->page_size = 0; 
        e->xd = 0;
        e->reserved = 0;

        e->pd_base_address = ((u64)alias_pd) >> 12;
    }

    paging__pdp_t *pdpt_low = &paging_space[1].pdp;
    for (u16 i = 0; i < 512; i++)
    {
        paging__pdp_entry_t *e = &pdpt_low->pdp_entries[i];

        e->present = 1;
        e->read_write = 1;
        e->user_supervisor = 0;
        e->write_through = 0;
        e->cache_disable = 0;
        e->accessed = 1;
        e->page_size = 0; 
        e->xd = 0;
        e->reserved = 0;

        if (i < 4)
        {
            // 0..4GiB-1: linearly mapped
            e->pd_base_address = ((u64)(&paging_space[2 + i].pd)) >> 12;
        }
        else
        {
            // >=4GiB (within PML4[0]'s 512GiB window): alias
            e->pd_base_address = ((u64)alias_pd) >> 12;
        }
    }


    // Setup the PML4
    paging__pml4_t *pml4 = &paging_space[0].pml4;
    for (u16 i = 0; i < 512; i++)
    {
        paging__pml4_entry_t *e = &pml4->pml4_entries[i];

        e->present = 1;
        e->read_write = 1;
        e->user_supervisor = 0;
        e->write_through = 0;
        e->cache_disable = 0;
        e->accessed = 1;
        e->xd = 0;
        e->reserved = 0;

        if (i == 0)
        {
            // VA range 0..512GiB-1: keep first 4GiB "normal", rest aliased
            e->pdp_base_address = ((u64)pdpt_low) >> 12;
        }
        else
        {
            // Any address in these PML4 slots is already >512GiB, hence >4GiB -> alias it all
            e->pdp_base_address = ((u64)pdpt_alias) >> 12;
        }
    }


    // Setup the four PDs (each filled with valid entries)
    for (u32 pd_index = 0; pd_index < 4; pd_index++)
    {
        for (u32 i = 0; i < 512; i++)
        {
            paging__pd_entry_t *cur_entry = paging_space[2 + pd_index].pd.pd_entries + i;

            cur_entry->present = 1;
            cur_entry->read_write = 1;
            cur_entry->user_supervisor = 0;
            cur_entry->write_through = 0;
            cur_entry->cache_disable = 0;
            cur_entry->accessed = 1;
            cur_entry->page_size = 1; // Leaf page in the page table walk
            cur_entry->ignored_1 = 1; // Copy the bootloader behavior
            cur_entry->reserved = 0;  // Set encryption bit
            cur_entry->xd = 0;

            // Map each 2MiB chunk of memory linearily
            cur_entry->pt_base_address = (i + ((pd_index) * 512)) << 9; // 21 - 12 = 9
        }
    }

    // split 0x200000..0x3fffff into 4KiB pages
    paging__pd_entry_t *pde = &paging_space[2].pd.pd_entries[1];
    paging__pt_t *pt = &paging_space[6].pt;
    for (u32 i = 0; i < 512; i++)
    {
        paging__pt_entry_t *pte = &pt->pt_entries[i];

        pte->present = 1;
        pte->read_write = 1;
        pte->user_supervisor = 0;
        pte->write_through = 0;
        pte->cache_disable = 0;
        pte->accessed = 0;
        pte->dirty = 0;
        pte->pat = 0;
        pte->global = 0;
        pte->available_1 = 0;

        // Map 4KiB pages starting at physical 0x200000
        u64 phys = 0x200000ULL + (i * 0x1000ULL);
        pte->pp_base_address = phys >> 12;

        pte->reserved = 0;
        pte->available_2 = 0;
        pte->pk = 0;
        pte->xd = 0;
    }

    pde->page_size = 0;
    pde->pt_base_address = ((u64)pt) >> 12;

    // Remap VA 0x00000000..0x001FFFFF (first 2MiB) to PA 0x00400000..0x005FFFFF
    // needed such that derefencing the null pointer doesn't cause any problems
    paging__pd_entry_t* pde0 = &paging_space[2].pd.pd_entries[0];
    pde0->pt_base_address = (0x400000ULL >> 21) << 9;

    serial_puts(" OK!\n");

    // Assuming an identity mapping
    serial_puts("Installing page table...");
    paging__install_page_table(&((paging_space + 0)->pml4));
    serial_puts(" OK!\n");

    serial_puts("Enabling SSE...");
    enable_sse();
    serial_puts(" OK!\n");

    serial_puts("Enabling AVX...");
    enable_avx();
    serial_puts(" OK!\n");

    
    paging__pt_entry_t *pte_300 = &pt->pt_entries[256]; // address 0x300000
    paging__pt_entry_t *pte_301 = &pt->pt_entries[257]; // address 0x301000


    pte_300->xd = 0; // Mark the page as executable
    pte_301->xd = 1; // Mark the page as non-executable

    // // capture VM state here
    // asm volatile(
    //     "mov %0, %%rax\n\t"
    //     "mov %1, %%rdi\n\t"
    //     "ud2\n\t"
    //     :
    //     : "i"(BASE), "r"(MAGIC_VALUE)
    //     : "rax", "rdi");


    // // //sanity check, check log if loads are visible
    // ACCESS_ONCE(*(uint64_t*)BASE);
    // ACCESS_ONCE(*((uint64_t*)BASE + 1));
    // ACCESS_ONCE(*((uint64_t*)BASE + 2));
    // ACCESS_ONCE(*((uint64_t*)BASE + 3));
    // ACCESS_ONCE(*((uint64_t*)BASE + 4));
    // ACCESS_ONCE(*((uint64_t*)BASE + 5));
    // ACCESS_ONCE(*((uint64_t*)BASE + 6));
    // ACCESS_ONCE(*((uint64_t*)BASE + 7));
    
    // asm volatile(
    //     "jmp *(%0) \n\t" 
    //     :
    //     : "r"(BASE)
    //     : "memory");

    serial_puts("idling...\n");
    while (true)
    {
        asm volatile("hlt");
    }
}