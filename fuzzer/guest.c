
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <execinfo.h>
#include <limits.h>
#include <ucontext.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <assert.h>
#include <sched.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>


#include "include/instruction.h"
#include "include/compiler.h"


#define PAGE_SIZE KB(4)


uint8_t instr[MAX_INSN_LENGTH];
result_t result;

int inject(int insn_size)
{
    
}


int poll_instr(int fd)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, -1);
    if(ret > 0) {
        if(pfd.revents & POLLIN) {
            ssize_t n = read(fd, instr, MAX_INSN_LENGTH);
            if (n != MAX_INSN_LENGTH)
            {
                fprintf(stderr, "Failed to read instruction from socket: %s\n", strerror(errno));
                return 1;
            }
            return 0;
        } else {
            fprintf(stderr, "Unexpected poll event: %d\n", pfd.revents);
            return 1;
        }
    } else if (ret == 0) {
        fprintf(stderr, "Poll timed out\n");
        return 1;
    } else {
        fprintf(stderr, "Poll error: %s\n", strerror(errno));
        return 1;
    }

}

int main()
{
    int fd;
    void *packet_buffer;

    fd = open("/dev/virtio-ports/insnexec", O_RDWR);
    if (fd < 0)
    {
        perror("open");
        return 1;
    }

    if (posix_memalign(&packet_buffer, PAGE_SIZE, PAGE_SIZE * 3) != 0)
    {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    assert(!mprotect(packet_buffer, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    assert(!mprotect((uint8_t *)packet_buffer + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE));


    while (1)
    {
        if (poll_instr(fd))
        {
            fprintf(stderr, "Error during poll\n");
            break;
        }

        for(int i = 1; i <= MAX_INSN_LENGTH; i++) {
            inject(i);
        }

        result.length = 1;
        if (write(fd, &result, sizeof(result)) != sizeof(result))
        {
            fprintf(stderr, "Failed to write result to socket: %s\n", strerror(errno));
            break;
        }
    }
    

    close(fd);
    free(packet_buffer);
    return 0;
}
