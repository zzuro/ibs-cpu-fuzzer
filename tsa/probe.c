#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <x86intrin.h>

#define PAGE_SIZE       4096ULL
#define DELTA_PAIR      (0x108000ULL)
#define N_UNIQUE        8
#define N_TOTAL         16
#define ALLOC_SIZE      (DELTA_PAIR + N_UNIQUE * PAGE_SIZE + PAGE_SIZE)
#define BASE_VA         0x200000000000ULL

/* Tune these for your machine — run calibration first */
#define WARMUP_ITERATIONS  100
#define MEASURE_ITERATIONS 5000
#define TRIALS             10
#define HIT_THRESHOLD      8.0   /* cycles — L1 hit on Zen 5 ~4 cyc */

#define BIT(va, b) (((uint64_t)(va) >> (b)) & 1ULL)

static uint64_t zen_utag(const void *ptr)
{
    uint64_t va = (uint64_t)ptr;
    uint64_t u0 = BIT(va,12)^BIT(va,13)^BIT(va,14)^BIT(va,15)^BIT(va,16)
                 ^BIT(va,17)^BIT(va,18)^BIT(va,19)^BIT(va,20)^BIT(va,21)
                 ^BIT(va,22)^BIT(va,23)^BIT(va,24)^BIT(va,25)^BIT(va,26)^BIT(va,27);
    uint64_t u1 = BIT(va,13)^BIT(va,26);
    uint64_t u2 = BIT(va,14)^BIT(va,25);
    uint64_t u3 = BIT(va,19)^BIT(va,24);
    uint64_t u4 = BIT(va,18)^BIT(va,23);
    uint64_t u5 = BIT(va,17)^BIT(va,22);
    uint64_t u6 = BIT(va,16)^BIT(va,21);
    uint64_t u7 = BIT(va,15)^BIT(va,20);
    return (u0)|(u1<<1)|(u2<<2)|(u3<<3)|(u4<<4)|(u5<<5)|(u6<<6)|(u7<<7);
}

static double measure_fence_overhead(void)
{
    volatile void *tmp = NULL;
    unsigned int aux;

    _mm_lfence();
    uint64_t start = __rdtscp(&aux);
    _mm_lfence();

    for (int i = 0; i < MEASURE_ITERATIONS; i++) {
        _mm_lfence();
        tmp = tmp;
        _mm_lfence();
    }

    uint64_t end = __rdtscp(&aux);
    _mm_lfence();

    return (double)(end - start) / (MEASURE_ITERATIONS * 2.0);
}


static double measure_chase_latency(void *a, void *b)
{
    volatile void *tmp = NULL;
    unsigned int aux;
    double min_lat = 1e9;

    for (int t = 0; t < TRIALS; t++) {

        /* Warmup: alternate a/b to establish steady-state cache behavior */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            tmp = *(volatile void **)a;
            tmp = *(volatile void **)b;
        }

        _mm_mfence();
        _mm_lfence();
        uint64_t start = __rdtscp(&aux);
        _mm_lfence();

        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            tmp = *(volatile void **)a;
            _mm_lfence();
            tmp = *(volatile void **)b;
            _mm_lfence();
        }

        uint64_t end = __rdtscp(&aux);
        _mm_lfence();

        /* Prevent dead-code elimination */
        if (tmp) printf("x");

        /* 2 loads per iteration */
        double lat = (double)(end - start) / (MEASURE_ITERATIONS * 2.0) - measure_fence_overhead();

        if (lat < min_lat)
            min_lat = lat;
    }

    return min_lat;
}

int main(void)
{
    uint8_t *region = mmap((void *)BASE_VA, ALLOC_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 1; }

    for (size_t off = 0; off < ALLOC_SIZE; off += PAGE_SIZE)
        *(volatile uint8_t *)(region + off) = (uint8_t)off;
    _mm_mfence();

    /* Build address array */
    void *addrs[N_TOTAL];
    for (int k = 0; k < N_UNIQUE; k++)
        addrs[k] = region + (size_t)k * PAGE_SIZE;
    for (int k = 0; k < N_UNIQUE; k++)
        addrs[N_UNIQUE + k] = region + DELTA_PAIR + (size_t)k * PAGE_SIZE;

    /* Verify layout */
    printf("=== Address layout verification ===\n");
    printf("%-6s  %-18s  %-8s  %-6s  %s\n",
           "index", "VA", "set[11:6]", "µtag", "note");
    int ok = 1;
    for (int i = 0; i < N_TOTAL; i++) {
        uint64_t va   = (uint64_t)addrs[i];
        uint64_t set  = (va >> 6) & 0x3F;
        uint64_t utag = zen_utag(addrs[i]);
        const char *note = "";
        if (i >= N_UNIQUE) {
            uint64_t pu = zen_utag(addrs[i - N_UNIQUE]);
            note = (utag == pu) ? "<- collides" : "MISMATCH!";
            if (utag != pu) ok = 0;
        }
        printf("A[%2d]   0x%016lx  0x%02lx      0x%02lx    %s\n",
               i, va, set, utag, note);
    }
    uint64_t ref_set = ((uint64_t)addrs[0] >> 6) & 0x3F;
    for (int i = 1; i < N_TOTAL; i++) {
        if ((((uint64_t)addrs[i] >> 6) & 0x3F) != ref_set)
            { printf("SET MISMATCH A[%d]\n", i); ok = 0; }
    }
    printf("Verification: %s\n\n", ok ? "PASSED" : "FAILED");
    if (!ok) { munmap(region, ALLOC_SIZE); return 1; }

    printf("=== µtag collision experiment ===\n");
    printf("%-18s  %-18s  %-8s  %-8s  %8s  %s\n",
           "addr A", "addr B", "µtag A", "µtag B", "min cyc", "result");

    for (int k = 0; k < N_UNIQUE; k++) {
        void *a = addrs[k];              /* unique µtag  */
        void *b = addrs[N_UNIQUE + k];  /* same µtag    */

        double lat = measure_chase_latency(a, b);
        const char *verdict = (lat > HIT_THRESHOLD)
                              ? "MISS  <- µtag collision confirmed"
                              : "hit   (no collision)";

        printf("A[%2d]=0x%012lx  A[%2d]=0x%012lx  0x%02lx    0x%02lx    %8.2f  %s\n",
               k,          (uint64_t)a,
               N_UNIQUE+k, (uint64_t)b,
               zen_utag(a), zen_utag(b),
               lat, verdict);
    }

    /* Sanity check: two addresses with DIFFERENT µtags should NOT evict */
    printf("\n=== Sanity: different-µtag pairs (expect L1 hit) ===\n");
    for (int k = 0; k < N_UNIQUE - 1; k++) {
        void *a = addrs[k];
        void *b = addrs[k + 1];   /* adjacent page → different µtag */

        double lat = measure_chase_latency(a, b);
        const char *verdict = (lat <= HIT_THRESHOLD)
                              ? "hit   <- correct, no eviction"
                              : "MISS  (unexpected)";

        printf("A[%2d] vs A[%2d]  µtag 0x%02lx vs 0x%02lx  %8.2f  %s\n",
               k, k+1, zen_utag(a), zen_utag(b), lat, verdict);
    }

    munmap(region, ALLOC_SIZE);
    return 0;
}