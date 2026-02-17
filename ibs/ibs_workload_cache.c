// ibs_workload_cache.c
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static inline uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// Prevent compiler from optimizing away the work
static volatile uint64_t sink;

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    // Adjust these if needed:
    // hot bytes ~256KB (likely L2-ish depending on CPU/core config)
    // cold bytes ~256MB (likely DRAM)
    const size_t hot_bytes  = 256 * 1024;
    const size_t cold_bytes = 256 * 1024 * 1024;

    const size_t hot_len  = hot_bytes  / sizeof(uint64_t);
    const size_t cold_len = cold_bytes / sizeof(uint64_t);

    uint64_t *hot  = aligned_alloc(64, hot_len  * sizeof(uint64_t));
    uint64_t *cold = aligned_alloc(64, cold_len * sizeof(uint64_t));
    if (!hot || !cold) {
        perror("aligned_alloc");
        return 1;
    }

    // Touch memory once to map pages
    for (size_t i = 0; i < hot_len; i++)  hot[i]  = (uint64_t)i;
    for (size_t i = 0; i < cold_len; i++) cold[i] = (uint64_t)i;

    // Use a stride that tends to beat simple HW prefetchers (in bytes)
    const size_t stride_bytes = 4096; // 1 page
    const size_t stride = stride_bytes / sizeof(uint64_t);

    puts("Running cache workload. Watch IBS: hot phase should have fewer misses/lat; cold phase more.");
    fflush(stdout);

    while (1) {
        // -------- Phase A: HOT (small working set) --------
        uint64_t t0 = ns_now();
        for (int rep = 0; rep < 20000; rep++) {
            // mix loads + stores
            for (size_t i = 0; i < hot_len; i += 8) {
                uint64_t v = hot[i];
                hot[i] = v + 1;
                sink ^= v;
            }
        }
        uint64_t t1 = ns_now();
        printf("[HOT ] elapsed=%.3f ms sink=%llu\n", (t1 - t0) / 1e6, (unsigned long long)sink);
        fflush(stdout);
        usleep(200000);

        // -------- Phase B: COLD (large, strided) --------
        t0 = ns_now();
        for (int rep = 0; rep < 2000; rep++) {
            for (size_t i = 0; i < cold_len; i += stride) {
                uint64_t v = cold[i];
                cold[i] = v + 1;
                sink ^= v;
            }
        }
        t1 = ns_now();
        printf("[COLD] elapsed=%.3f ms sink=%llu\n", (t1 - t0) / 1e6, (unsigned long long)sink);
        fflush(stdout);
        usleep(200000);
    }

    // unreachable
    free(hot);
    free(cold);
    return 0;
}
