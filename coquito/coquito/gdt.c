#include "gdt.h"
#include "serial.h"

struct __attribute__((packed)) GDT_descriptor32{
    u16 size;
    u32 offset;
};
typedef struct GDT_descriptor32 GDT_descriptor32_t;

struct __attribute__((packed)) GDT_descriptor64{
    u16 size;
    u64 offset;
};
typedef struct GDT_descriptor64 GDT_descriptor64_t;

/** Values set by gdt__install_table */
static u16 _kernel_code_segment_selector = 0;
static u16 _kernel_data_segment_selector = 0;

/** Interrupts are supposed to be tured off before the call */
void gdt__install_table(GDT_entry_t* table_start, size_t entry_count, u16 data_selector, u16 code_selector){
    GDT_descriptor64_t gdtr;
    gdtr.size = entry_count*sizeof(*table_start)-1;
    gdtr.offset = (u64)table_start;

    u64 code_selector64 = code_selector;

    __asm__ volatile("lgdt %0" :: "m"(gdtr));


    // See https://stackoverflow.com/questions/34264752/change-gdt-and-update-cs-while-in-long-mode 
    __asm__ volatile(
        "sub $16, %%rsp\n\t"
        "mov %0, 8(%%rsp)\n\t"
        "movabsq $reload_CS, %%rax\n\t"
        "mov %%rax, (%%rsp)\n\t"
        "lretq\n\t"
        "jmp end\n\t"
        "reload_CS:\n\t"
        "movw %1, %%ax\n\t"
        "movw %%ax, %%ds\n\t"
        "movw %%ax, %%es\n\t"
        "movw %%ax, %%fs\n\t"
        "movw %%ax, %%gs\n\t"
        "movw %%ax, %%ss\n\t"
        "end:\n\t"
             :: "r"(code_selector64), "r"(data_selector));
    
    _kernel_code_segment_selector = code_selector;
    _kernel_data_segment_selector = data_selector; 
}

static inline __attribute__((always_inline)) void _entry_set_limit(GDT_entry_t* entry, u32 limit){
    entry->limit_1 = limit&0xffff;
    entry->limit_2 = (limit>>16)&0xf;
}

void gdt__entry_make_null(GDT_entry_t* entry){
    entry->access = 0;
    entry->base_1 = 0;
    entry->base_2 = 0;
    entry->flags = 0;
    entry->limit_1 = 0;
    entry->limit_2 = 0;
}

void gdt__entry_make_kernel_mode_code_segment64(GDT_entry_t* entry){
    /** See https://wiki.osdev.org/GDT_Tutorial "Kernel Mode Code Segment"; slightly modified to resemble
        the EDKII bootloader-installed GDT more
    */

    entry->base_1 = 0;
    entry->base_2 = 0;

    _entry_set_limit(entry, 0xfffff);

    entry->access = 0x9b;
    entry->flags = 0xa;
}

void gdt__entry_make_kernel_mode_data_segment64(GDT_entry_t* entry){
    /** See https://wiki.osdev.org/GDT_Tutorial "Kernel Mode Data Segment"; slightly modified to resemble
        the EDKII bootloader-installed GDT more
    */

    entry->base_1 = 0;
    entry->base_2 = 0;

    _entry_set_limit(entry, 0xfffff);

    entry->access = 0x93;
    entry->flags = 0xc;
}

u16 gdt__get_system_code_selector(void){
    return _kernel_code_segment_selector;
} 

u16 gdt__get_system_data_selector(void){
    return _kernel_data_segment_selector;
}