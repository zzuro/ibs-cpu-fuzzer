#include "ktypes.h"

/**
    @file Describes paging structures

    Source: "AMD64 Architecture Programmer’s Manual, Volume 2: System Programming"
    Section 5.3,  figure 5-19 to 5-34 

    Augmented by https://www.iaik.tugraz.at/teaching/materials/os/tutorials/paging-on-intel-x86-64/
    (to split the base addresses between the "reserved" part [which holds the SEV C-bit] and the actual
    address part)
*/


struct __attribute__((packed)) paging__pml4_entry{
    u64 present: 1;
    u64 read_write: 1;
    u64 user_supervisor: 1;
    u64 write_through: 1;
    u64 cache_disable: 1;
    u64 accessed: 1;
    u64 ignored: 1;
    u64 _zero1: 1;
    u64 _zero2: 1;
    u64 available_1: 3;

    /** page directory pointer base address */
    u64 pdp_base_address: 28;
    u64 reserved: 12;
    u64 available_2: 11;
    u64 xd: 1;
};
typedef struct paging__pml4_entry paging__pml4_entry_t;


struct __attribute__((packed)) paging__pdp_entry{
    u64 present: 1;
    u64 read_write: 1;
    u64 user_supervisor: 1;
    u64 write_through: 1;
    u64 cache_disable: 1;
    u64 accessed: 1;
    u64 ignored_1: 1;
    u64 page_size: 1;
    u64 ignored_2: 1;
    u64 available_1: 3;

    /** page directory base address */
    u64 pd_base_address: 28;
    u64 reserved: 12;
    u64 available_2: 11;
    u64 xd: 1;
};
typedef struct paging__pdp_entry paging__pdp_entry_t;

struct __attribute__((packed)) paging__pd_entry{
    u64 present: 1;
    u64 read_write: 1;
    u64 user_supervisor: 1;
    u64 write_through: 1;
    u64 cache_disable: 1;
    u64 accessed: 1;
    u64 ignored_1: 1;
    u64 page_size: 1;
    u64 ignored_2: 1;
    u64 available_1: 3;

    /** page table base address */
    u64 pt_base_address: 28;
    u64 reserved: 12;
    u64 available_2: 11;
    u64 xd: 1;
};
typedef struct paging__pd_entry paging__pd_entry_t;

struct __attribute__((packed)) paging__pt_entry{
    u64 present: 1;
    u64 read_write: 1;
    u64 user_supervisor: 1;
    u64 write_through: 1;
    u64 cache_disable: 1;
    u64 accessed: 1;
    u64 dirty: 1;
    u64 pat: 1;
    u64 global: 1;
    u64 available_1: 3;

    /** physical page base address */
    u64 pp_base_address: 28;
    u64 reserved: 12;
    u64 available_2: 7;
    u64 pk: 4;
    u64 xd: 1;
};
typedef struct paging__pt_entry paging__pt_entry_t;


struct paging__pml4{
    paging__pml4_entry_t pml4_entries[512];
};
typedef struct paging__pml4 paging__pml4_t;

struct paging__pdp{
    paging__pdp_entry_t pdp_entries[512];
};
typedef struct paging__pdp paging__pdp_t;

struct paging__pd{
    paging__pd_entry_t pd_entries[512];
};
typedef struct paging__pd paging__pd_t;

struct paging__pt{
    paging__pt_entry_t pt_entries[512];
};
typedef struct paging__pt paging__pt_t;

struct paging__mapping_indices{
    u16 pml4_index;
    u16 pdp_index;
    u16 pd_index;
    u16 pt_index;
};
typedef struct paging__mapping_indices paging__mapping_indices_t;

struct paging__mapping{
    paging__pml4_entry_t* pml4_entry;
    paging__pdp_entry_t* pdp_entry;
    paging__pd_entry_t* pd_entry;
    paging__pt_entry_t* pt_entry;
};
typedef struct paging__mapping paging__mapping_t;

union paging__any_table_type{
    paging__pml4_t pml4;
    paging__pdp_t pdp;
    paging__pd_t pd;
    paging__pt_t pt;
};

void paging__print_pml4_entry(paging__pml4_entry_t* entry);
void paging__print_pdp_entry(paging__pdp_entry_t* entry);
void paging__print_pd_entry(paging__pd_entry_t* entry);
void paging__print_pt_entry(paging__pt_entry_t* entry);

paging__pdp_t* paging__pml4_entry_child_address(paging__pml4_entry_t* entry);
paging__pd_t* paging__pdp_entry_child_address(paging__pdp_entry_t* entry);
paging__pt_t* paging__pd_entry_child_address(paging__pd_entry_t* entry);
void* paging__pt_entry_child_address(paging__pt_entry_t* entry);


paging__mapping_indices_t paging__mapping_indices_from_virt(virtaddr_t addr);
paging__mapping_t paging__mapping_from_indices(paging__pml4_t* page_table, paging__mapping_indices_t indices);
void paging__walk_page_table_with_page_table_addr(paging__pml4_t* page_table, virtaddr_t addr);
void paging__walk_page_table(virtaddr_t addr);
void paging__install_page_table(paging__pml4_t* page_table);
void paging__tlb_flush(void);

void* read_cr3(void);
physaddr_t get_paging_base(void);

physaddr_t virt2phys(virtaddr_t addr);