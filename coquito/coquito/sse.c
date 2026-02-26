#include "ktypes.h"
#include "sse.h"

static u64 read_cr0(void);
static void set_cr0(const u64 new_cr0);
static u64 read_cr4(void);
static void set_cr4(const u64 new_cr4);


static u64 read_cr0(void) {
    u64 cr0_val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0_val) :);
    return cr0_val;
}

static void set_cr0(const u64 new_cr0) {
    __asm__ volatile("mov %0, %%cr0" :: "r"(new_cr0));
}

static u64 read_cr4(void) {
    u64 cr4_val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4_val) :);
    return cr4_val;
}

static void set_cr4(const u64 new_cr4) {
    __asm__ volatile("mov %0, %%cr4" :: "r"(new_cr4));
}


void enable_sse(void) {
    u64 cr0 = read_cr0();
    cr0 &= ~(1UL<<2);   // clear EM (Emulate coprocessor bit) bit
    cr0 |= 1UL << 1;    // set MP (Monitor coprocessor) bit
    set_cr0(cr0);

    u64 cr4 = read_cr4();
    cr4 |= (1UL<<9);    // enable FXSAVE and FXRSTOR instructions
    cr4 |= (1UL<<10);   // enable SIMD floating point execptions (OSXMMEXCPT)
    cr4 |= (1UL<<18);   // enable XSETBV and XGETBV instructions
    set_cr4(cr4);
}

void enable_avx(void) {

    // TODO: Allocate area for FXSAVE/FXRSTR

    __asm__ volatile(
        "xor %%rcx, %%rcx\n\t"
        "xgetbv\n\t" 
        "or $7, %%eax\n\t"
        "xsetbv"
        ::: "eax", "edx");
}