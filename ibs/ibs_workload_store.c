// ibs_workload_store.c
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile uint64_t sink;

int main(void) {
    const size_t bytes = 512 * 1024 * 1024; // 512MB
    const size_t len = bytes / sizeof(uint64_t);

    uint64_t *a = aligned_alloc(64, len * sizeof(uint64_t));
    if (!a) {
        perror("aligned_alloc");
        return 1;
    }

    // map pages
    for (size_t i = 0; i < len; i += 4096/8) a[i] = 0;

    puts("Store streaming: should produce lots of st_op samples.");
    fflush(stdout);

    uint64_t x = 0;
    while (1) {
        // big streaming stores
        for (size_t i = 0; i < len; i += 8) {
            a[i] = x + i;
            x += 1;
        }
        sink = x;
        printf("pass done sink=%llu\n", (unsigned long long)sink);
        fflush(stdout);
        usleep(100000);
    }

    free(a);
    return 0;
}
