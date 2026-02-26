#pragma once

#include "ktypes.h"


struct __attribute__((packed)) GDT_entry{ 
    u64 limit_1:16;
    u64 base_1:24;
    u64 access:8;
    u64 limit_2:4;
    u64 flags:4;
    u64 base_2:8;
};
typedef struct GDT_entry GDT_entry_t;

struct __attribute__((packed)) GDT_entry64{ 
    u64 limit_1:16;
    u64 base_1:24;
    u64 access:8;
    u64 limit_2:4;
    u64 flags:4;
    u64 base_2:40;
    u64 _reserved:32;
};
typedef struct GDT_entry64 GDT_entry64_t;

void gdt__entry_make_null(GDT_entry_t* entry);
void gdt__entry_make_kernel_mode_code_segment64(GDT_entry_t* entry);
void gdt__entry_make_kernel_mode_data_segment64(GDT_entry_t* entry);
void gdt__install_table(GDT_entry_t* table_start, size_t entry_count, u16 data_selector, u16 code_selector);
u16 gdt__get_system_code_selector(void);
u16 gdt__get_system_data_selector(void);