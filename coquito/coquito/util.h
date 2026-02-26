#include "ktypes.h"

u64 rdtsc(void);
u64 perf_timer(void);

// See https://stackoverflow.com/questions/56940066/rdtsc-a-a0-d-d0-what-does-this-do
inline u64 rdtsc(void){
    u32 lo, hi;
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((u64)hi << 32) | lo;
}

inline u64 perf_timer(void) {
    // See https://stackoverflow.com/a/58146426 in https://stackoverflow.com/questions/27693145/rdtscp-versus-rdtsc-cpuid
    u32 lo, hi;
    __asm__ volatile ("mfence; lfence");
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((u64)hi << 32) | lo;
}