
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


extern char resume;

#include "include/instruction.h"
#include "include/compiler.h"


#define PAGE_SIZE KB(4)
#define TF        0x100

char instr[MAX_INSN_LENGTH];
result_t result;

void* packet_buffer;
char* packet;

state_t inject_state={
	.rax=0,
	.rbx=0,
	.rcx=0,
	.rdx=0,
	.rsi=0,
	.rdi=0,
	.r8=0,
	.r9=0,
	.r10=0,
	.r11=0,
	.r12=0,
	.r13=0,
	.r14=0,
	.r15=0,
	.rbp=0,
	.rsp=0,
};

int inject(int insn_size)
{
    packet=(uint8_t*)packet_buffer+PAGE_SIZE-insn_size;


    for(int i=0; i<insn_size; i++) {
        packet[i]=instr[i];
    }

    __asm__ __volatile__ ("\
			mov %[rax], %%rax \n\
			mov %[rbx], %%rbx \n\
			mov %[rcx], %%rcx \n\
			mov %[rdx], %%rdx \n\
			mov %[rsi], %%rsi \n\
			mov %[rdi], %%rdi \n\
			mov %[r8],  %%r8  \n\
			mov %[r9],  %%r9  \n\
			mov %[r10], %%r10 \n\
			mov %[r11], %%r11 \n\
			mov %[r12], %%r12 \n\
			mov %[r13], %%r13 \n\
			mov %[r14], %%r14 \n\
			mov %[r15], %%r15 \n\
			mov %[rbp], %%rbp \n\
			jmp *%[packet]    \n\
            .global resume    \n\
			resume:           \n\
			"
			: /* no output */
			: [rax]"m"(inject_state.rax),
			  [rbx]"m"(inject_state.rbx),
			  [rcx]"m"(inject_state.rcx),
			  [rdx]"m"(inject_state.rdx),
			  [rsi]"m"(inject_state.rsi),
			  [rdi]"m"(inject_state.rdi),
			  [r8]"m"(inject_state.r8),
			  [r9]"m"(inject_state.r9),
			  [r10]"m"(inject_state.r10),
			  [r11]"m"(inject_state.r11),
			  [r12]"m"(inject_state.r12),
			  [r13]"m"(inject_state.r13),
			  [r14]"m"(inject_state.r14),
			  [r15]"m"(inject_state.r15),
			  [rbp]"m"(inject_state.rbp),
			  [packet]"m"(packet)
			);
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
    int fd = open("/dev/virtio-ports/insnexec", O_RDWR);
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
