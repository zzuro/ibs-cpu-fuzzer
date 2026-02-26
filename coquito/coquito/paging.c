#include "ktypes.h"

#include "paging.h"
#include "serial.h"

// struct page_table_entry{
//     u64 present: 1;
//     u64 read_write: 1;
//     u64 user_supervisor: 1;
//     u64 write_through: 1;
//     u64 cache_disable: 1;
//     u64 accessed: 1;
//     u64 dirty: 1;
//     union __attribute__((packed)) {
//         u64 page_size: 1;
//         u64 leaf_pat: 1;
//     } bit7;
//     u64 global: 1;
//     u64 available_1: 3;
//     union __attribute__((packed)) {
//         struct __attribute__((packed)) {
//             u64 pat: 1;
//             u64 reserved: 17;  
//             u64 addr_upper: 22;
//         } addr_pgpt_entry;
//         struct __attribute__((packed)) {
//             u64 pat: 1;
//             u64 reserved: 8;
//             u64 addr_middle: 31;
//         } addr_pde;
//         struct __attribute__((packed)) {
//             u64 addr_lower: 40;
//         } addr_pte;
//     };
//     u64 available_2: 7;
//     u64 pk: 4;
//     u64 xd: 1;
// };


// Blindy assume identity paging
physaddr_t virt2phys(virtaddr_t addr){
    return addr;
}

void paging__print_pml4_entry(paging__pml4_entry_t* entry){
    serial_puts("\tPresent: "); serial_puts(entry->present ? "Y\n" : "N\n");
    serial_puts("\tRead/write: "); serial_puts(entry->read_write ? "RW\n" : "RO\n");
    serial_puts("\tUser/Supervisor: "); serial_puts(entry->user_supervisor ? "U+S\n" : "S\n");
    serial_puts("\tWrite-through: "); serial_puts(entry->write_through ? "Y\n" : "N\n");
    serial_puts("\tCache disable: "); serial_puts(entry->cache_disable ? "Y\n" : "N\n");
    serial_puts("\tAccessed: "); serial_puts(entry->accessed ? "Y\n" : "N\n");
    serial_puts("\tIgnored field: "); serial_puts(entry->ignored ? "1\n" : "0\n");
    serial_puts("\tMust be zero: "); serial_puts(entry->_zero1 ? "Isn't zero\n" : "Is zero\n");
    serial_puts("\tMust be zero#2: "); serial_puts(entry->_zero2 ? "Isn't zero\n" : "Is zero\n");
    serial_puts("\tAvailable_1: "); serial_print_hex8(entry->available_1); serial_puts("\n");
    serial_puts("\tPage directory pointer base address: "); serial_print_hex64(((u64)entry->pdp_base_address)<<12); serial_puts("\n");
    serial_puts("\tReserved: "); serial_print_hex16(entry->reserved); serial_puts("\n");
    serial_puts("\tAvailable_2: "); serial_print_hex16(entry->available_2); serial_puts("\n");
    serial_puts("\tExecute disable: "); serial_puts(entry->xd ? "Y\n" : "N\n");
}

void paging__print_pdp_entry(paging__pdp_entry_t* entry){
    serial_puts("\tPresent: "); serial_puts(entry->present ? "Y\n" : "N\n");
    serial_puts("\tRead/write: "); serial_puts(entry->read_write ? "RW\n" : "RO\n");
    serial_puts("\tUser/Supervisor: "); serial_puts(entry->user_supervisor ? "U+S\n" : "S\n");
    serial_puts("\tWrite-through: "); serial_puts(entry->write_through ? "Y\n" : "N\n");
    serial_puts("\tCache disable: "); serial_puts(entry->cache_disable ? "Y\n" : "N\n");
    serial_puts("\tAccessed: "); serial_puts(entry->accessed ? "Y\n" : "N\n");
    serial_puts("\tIgnored field#1: "); serial_puts(entry->ignored_1 ? "1\n" : "0\n");
    serial_puts("\tPage size: "); serial_puts(entry->page_size ? "Y\n" : "N\n");
    serial_puts("\tIgnored field#2: "); serial_puts(entry->ignored_2 ? "1\n" : "0\n");
    serial_puts("\tAvailable_1: "); serial_print_hex8(entry->available_1); serial_puts("\n");
    serial_puts("\tPage directory base address: "); serial_print_hex64(((u64)entry->pd_base_address)<<12); serial_puts("\n");
    serial_puts("\tReserved: "); serial_print_hex16(entry->reserved); serial_puts("\n");
    serial_puts("\tAvailable_2: "); serial_print_hex16(entry->available_2); serial_puts("\n");
    serial_puts("\tExecute disable: "); serial_puts(entry->xd ? "Y\n" : "N\n");
}

void paging__print_pd_entry(paging__pd_entry_t* entry){
    serial_puts("\tPresent: "); serial_puts(entry->present ? "Y\n" : "N\n");
    serial_puts("\tRead/write: "); serial_puts(entry->read_write ? "RW\n" : "RO\n");
    serial_puts("\tUser/Supervisor: "); serial_puts(entry->user_supervisor ? "U+S\n" : "S\n");
    serial_puts("\tWrite-through: "); serial_puts(entry->write_through ? "Y\n" : "N\n");
    serial_puts("\tCache disable: "); serial_puts(entry->cache_disable ? "Y\n" : "N\n");
    serial_puts("\tAccessed: "); serial_puts(entry->accessed ? "Y\n" : "N\n");
    serial_puts("\tIgnored field#1: "); serial_puts(entry->ignored_1 ? "1\n" : "0\n");
    serial_puts("\tPage size: "); serial_puts(entry->page_size ? "Y\n" : "N\n");
    serial_puts("\tIgnored field#2: "); serial_puts(entry->ignored_2 ? "1\n" : "0\n");
    serial_puts("\tAvailable_1: "); serial_print_hex8(entry->available_1); serial_puts("\n");
    serial_puts("\tPage table base address: "); serial_print_hex64(((u64)entry->pt_base_address)<<12); serial_puts("\n");
    serial_puts("\tReserved: "); serial_print_hex16(entry->reserved); serial_puts("\n");
    serial_puts("\tAvailable_2: "); serial_print_hex16(entry->available_2); serial_puts("\n");
    serial_puts("\tExecute disable: "); serial_puts(entry->xd ? "Y\n" : "N\n");
}

void paging__print_pt_entry(paging__pt_entry_t* entry){
    serial_puts("\tPresent: "); serial_puts(entry->present ? "Y\n" : "N\n");
    serial_puts("\tRead/write: "); serial_puts(entry->read_write ? "RW\n" : "RO\n");
    serial_puts("\tUser/Supervisor: "); serial_puts(entry->user_supervisor ? "U+S\n" : "S\n");
    serial_puts("\tWrite-through: "); serial_puts(entry->write_through ? "Y\n" : "N\n");
    serial_puts("\tCache disable: "); serial_puts(entry->cache_disable ? "Y\n" : "N\n");
    serial_puts("\tAccessed: "); serial_puts(entry->accessed ? "Y\n" : "N\n");
    serial_puts("\tDirty: "); serial_puts(entry->dirty ? "Y\n" : "N\n");
    serial_puts("\tPat: "); serial_puts(entry->pat ? "Y\n" : "N\n");
    serial_puts("\tGlobal: "); serial_puts(entry->global ? "Y\n" : "N\n");
    serial_puts("\tAvailable_1: "); serial_print_hex8(entry->available_1); serial_puts("\n");
    serial_puts("\tPhysical page base address: "); serial_print_hex64(((u64)entry->pp_base_address)<<12); serial_puts("\n");
    serial_puts("\tReserved: "); serial_print_hex16(entry->reserved); serial_puts("\n");
    serial_puts("\tAvailable_2: "); serial_print_hex8(entry->available_2); serial_puts("\n");
    serial_puts("\tPK: "); serial_print_hex8(entry->pk); serial_puts("\n");
    serial_puts("\tExecute disable: "); serial_puts(entry->xd ? "Y\n" : "N\n");
}

void* read_cr3(void){
    void* cr3_val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3_val) :);
    return cr3_val; 
}


physaddr_t get_paging_base(void){
    // Clear the low bits
    return (((physaddr_t)read_cr3())>>12)<<12;
}

paging__mapping_indices_t paging__mapping_indices_from_virt(virtaddr_t addr){
    paging__mapping_indices_t mapping;

    // See https://zolutal.github.io/understanding-paging/
    mapping.pt_index   = (addr >> 12)&0x1ff;
    mapping.pd_index   = (addr >> 21)&0x1ff;
    mapping.pdp_index  = (addr >> 30)&0x1ff;
    mapping.pml4_index = (addr >> 39)&0x1ff;

    return mapping;
}

paging__mapping_t paging__mapping_from_indices(paging__pml4_t* page_table, paging__mapping_indices_t indices){
    paging__mapping_t mapping = {
        .pml4_entry = NULL,
        .pdp_entry = NULL,
        .pd_entry = NULL,
        .pt_entry = NULL
    };

    paging__pml4_entry_t* entry4 = page_table->pml4_entries + indices.pml4_index;
    mapping.pml4_entry = entry4;

    if(!entry4->present){
        return mapping;
    }

    paging__pdp_t* table3 = paging__pml4_entry_child_address(entry4);
    paging__pdp_entry_t* entry3 = table3->pdp_entries + indices.pdp_index; 
    mapping.pdp_entry = entry3;

    if(!entry3->present || entry3->page_size){
        return mapping;
    }

    paging__pd_t* table2 = paging__pdp_entry_child_address(entry3);
    paging__pd_entry_t* entry2 = table2->pd_entries + indices.pd_index; 
    mapping.pd_entry = entry2;

    if(!entry2->present || entry2->page_size){
        return mapping;
    }
    
    paging__pt_t* table1 = paging__pd_entry_child_address(entry2);
    paging__pt_entry_t* entry1 = table1->pt_entries + indices.pt_index;
    mapping.pt_entry = entry1;

    return mapping; 
}


void paging__walk_page_table(virtaddr_t addr){
    paging__pml4_t* page_table = (void*)((u64)read_cr3()&(~0xfffL));
    paging__walk_page_table_with_page_table_addr(page_table, addr);
}

void paging__walk_page_table_with_page_table_addr(paging__pml4_t* page_table, virtaddr_t addr){
    serial_puts("Address: "); serial_print_addr((void*)addr); serial_putchar('\n');
    paging__mapping_indices_t mapping = paging__mapping_indices_from_virt(addr);

    // See Figure 5-16 of the AMD programmer's manual volume 2
    paging__pml4_t* table4 = page_table;
    paging__pml4_entry_t* entry4 = table4->pml4_entries + mapping.pml4_index;

    serial_puts("PML4 entry:\n");
    serial_puts("Raw: ");
    serial_print_hex64(*((u64*)(entry4)));
    serial_puts("\n");
    if(!entry4->present){
        serial_puts("--- not present ---\n");
        return;
    }
    paging__print_pml4_entry(entry4);


    paging__pdp_t* table3 = paging__pml4_entry_child_address(entry4);
    paging__pdp_entry_t* entry3 = table3->pdp_entries + mapping.pdp_index; 
    serial_puts("PDP entry:\n");
    serial_puts("Raw: "); serial_print_hex64(*((u64*)(entry3))); serial_puts("\n");
    if(!entry3->present){
        serial_puts("--- not present ---\n");
        return;
    }
    paging__print_pdp_entry(entry3);
    if(entry3->page_size){
        serial_puts("--- final leaf ---\n");  
        return;
    }

    paging__pd_t* table2 = paging__pdp_entry_child_address(entry3);
    paging__pd_entry_t* entry2 = table2->pd_entries + mapping.pd_index; 
    serial_puts("PD entry:\n");
    serial_puts("Raw: "); serial_print_hex64(*((u64*)(entry2))); serial_puts("\n");
    if(!entry2->present){
        serial_puts("--- not present ---\n");
        return;
    }
    paging__print_pd_entry(entry2);
    if(entry2->page_size){
        serial_puts("--- final leaf ---\n");  
        return;
    }


    paging__pt_t* table1 = paging__pd_entry_child_address(entry2);
    paging__pt_entry_t* entry1 = table1->pt_entries + mapping.pt_index; 
    serial_puts("PT entry:\n");
    serial_puts("Raw: "); serial_print_hex64(*((u64*)(entry1))); serial_puts("\n");
    if(!entry1->present){
        serial_puts("--- not present ---\n");
        return;
    }
    paging__print_pt_entry(entry1);


    serial_puts("Final address: "); serial_print_addr(paging__pt_entry_child_address(entry1)); serial_puts("\n");
    return;

}

paging__pdp_t* paging__pml4_entry_child_address(paging__pml4_entry_t* entry){
    return (paging__pdp_t*)(((u64)entry->pdp_base_address)<<12);
}

paging__pd_t* paging__pdp_entry_child_address(paging__pdp_entry_t* entry){
    return (paging__pd_t*)(((u64)entry->pd_base_address)<<12);
}

paging__pt_t* paging__pd_entry_child_address(paging__pd_entry_t* entry){
    return (paging__pt_t*)(((u64)entry->pt_base_address)<<12);
}

void* paging__pt_entry_child_address(paging__pt_entry_t* entry){
    return (void*)(((u64)entry->pp_base_address)<<12);
}

void paging__install_page_table(paging__pml4_t* page_table){
    __asm__ volatile("mov %0, %%cr3" :: "r"(page_table));
}

static void _invlpgb(u64 rax_val, u64 rcx_val, u64 rdx_val){
    register u64 rax asm("rax") = rax_val;
    register u64 rcx asm("rcx") = rcx_val;
    register u64 rdx asm("rdx") = rdx_val;

    // See AMD Programmer' Manual Volume 3
    // This encodes the INVLPGB instruction, which might not exist
    // in the assembler yet.
    __asm__ volatile(".byte 0x0f, 0x01, 0xff" :: "r"(rax), "r"(rcx), "r"(rdx));
}

void paging__tlb_flush(void){
    // See coconut source (src/cpu/tlb.rs)
    _invlpgb(4, 0, 0);
}