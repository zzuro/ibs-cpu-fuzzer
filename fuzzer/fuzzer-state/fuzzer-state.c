#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "fuzzer-state.h"

#define DEVICE_NAME "/dev/svm_ibs_dev"
#define FUZZ_IOC_GET_STATE _IOR('a', 'c', fuzzer_state_t)
#define FUZZ_IOC_SET_STATE _IOW('a', 'd', fuzzer_state_t)

int main()
{
    int fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0)
    {
        perror("Failed to open device");
        return EXIT_FAILURE;
    }

    fuzzer_state_t fuzz_state = {
        .fuzz_mem1_host = NULL,
        .fuzz_mem1_guest = NULL,
        .fuzz_mem2_host = NULL,
        .fuzz_mem2_guest = NULL,

        .total_range = {
            .start = {
                .bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00},
                .len = 0,
            },
            .end = {
                .bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                .len = 0,
            },
            .started = false,
        },

        .inj = {
            .i = {
                .bytes = {0},
                .len = 1,
            },
            .index = 0,
            .last_len = 0,
        },

        .result = {
            .valid = 0,
            .length = 0,
            .ecxeption = 0,
        },

        .current_op = START,
        .fetch_counter = 0,

        .saved_state = {},

        .file_open = false,
    };

    if (ioctl(fd, FUZZ_IOC_SET_STATE, &fuzz_state) < 0)
    {
        perror("Failed to get state");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("Fuzzer state reseted successfully.\n");
}