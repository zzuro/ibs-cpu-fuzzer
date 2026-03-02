
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

extern char resume, preamble_start, preamble_end;

#include "include/instruction.h"
#include "include/compiler.h"

#define PAGE_SIZE KB(4)
#define TF 0x100
#define UD2_SIZE  2
#define IP REG_RIP
#define JMP_LENGTH 16 

char instr[MAX_INSN_LENGTH];
result_t result;

void *packet_buffer;
char *packet;

state_t inject_state = {
    .rax = 0,
    .rbx = 0,
    .rcx = 0,
    .rdx = 0,
    .rsi = 0,
    .rdi = 0,
    .r8 = 0,
    .r9 = 0,
    .r10 = 0,
    .r11 = 0,
    .r12 = 0,
    .r13 = 0,
    .r14 = 0,
    .r15 = 0,
    .rbp = 0,
    .rsp = 0,
};


static uint64_t dummy_stack[512] __attribute__ ((aligned(PAGE_SIZE)));

//holds a snapshot of the CPU state at the time of a fault, used for recovery after the fault
mcontext_t fault_context;

//capture the the fault_context
void state_handler(int signum, siginfo_t* si, void* p)
{
	fault_context=((ucontext_t*)p)->uc_mcontext;
	((ucontext_t*)p)->uc_mcontext.gregs[IP]+=UD2_SIZE;
}

void fault_handler(int signum, siginfo_t* si, void* p)
{
	int insn_length;
	ucontext_t* uc=(ucontext_t*)p;
	int preamble_length=(&preamble_end-&preamble_start);

	/* make an initial estimate on the instruction length from the fault address */
	insn_length=(uintptr_t)uc->uc_mcontext.gregs[IP]-(uintptr_t)packet-preamble_length;
    
    //inspect TRAPNO to check if #PF or #GP
    //printf("TrapNr %d\n", uc->uc_mcontext.gregs[REG_TRAPNO]);

    if(uc->uc_mcontext.gregs[REG_TRAPNO] == 13)
    {
        printf("Privilege violation\n");
    }

	if (insn_length<0) {
		insn_length=JMP_LENGTH;
	}
	else if (insn_length>MAX_INSN_LENGTH) {
		insn_length=JMP_LENGTH;
	}

	result=(result_t){
		1,
		insn_length,
		signum,
		si->si_code,
		(signum==SIGSEGV||signum==SIGBUS)?(uint32_t)(uintptr_t)si->si_addr:(uint32_t)-1
	};

	memcpy(uc->uc_mcontext.gregs, fault_context.gregs, sizeof(fault_context.gregs));
	uc->uc_mcontext.gregs[IP]=(uintptr_t)&resume;
	uc->uc_mcontext.gregs[REG_EFL]&=~TF; 
}



void configure_sig_handler(void (*handler)(int, siginfo_t*, void*))
{
	struct sigaction s;

	s.sa_sigaction=handler;
	s.sa_flags=SA_SIGINFO|SA_ONSTACK;

	sigfillset(&s.sa_mask);

	sigaction(SIGILL,  &s, NULL);
	sigaction(SIGSEGV, &s, NULL);
	sigaction(SIGFPE,  &s, NULL);
	sigaction(SIGBUS,  &s, NULL);
	sigaction(SIGTRAP, &s, NULL);
}


void preamble(void)
{

    __asm__ __volatile__("\
			.global preamble_start                    \n\
			preamble_start:                           \n\
			pushfq                                    \n\
			orq %0, (%%rsp)                           \n\
			popfq                                     \n\
			.global preamble_end                      \n\
			preamble_end:                             \n\
			"
                         :
                         : "i"(TF));
}

int inject(int insn_size)
{
    int i;
    int preamble_length = (&preamble_end - &preamble_start);
    packet = (uint8_t *)packet_buffer + PAGE_SIZE - insn_size - preamble_length;

    for (i = 0; i < preamble_length; i++)
    {
        ((char *)packet)[i] = ((char *)&preamble_start)[i];
    }

    for (i = 0; i < MAX_INSN_LENGTH && i < insn_size; i++)
    {
        ((char *)packet)[i + preamble_length] = instr[i];
    }

    void* p=NULL;
    memset(p, 0, PAGE_SIZE);

    inject_state.rsp=(uint64_t)(uintptr_t)dummy_stack+sizeof(dummy_stack);
    configure_sig_handler(state_handler);
	__asm__ __volatile__ ("ud2\n");

    configure_sig_handler(fault_handler);

    __asm__ __volatile__("\
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
            mov %[rsp], %%rsp \n\
			jmp *%[packet]    \n\
            .global resume    \n\
			resume:           \n\
			"
                         : /* no output */
                         : [rax] "m"(inject_state.rax),
                           [rbx] "m"(inject_state.rbx),
                           [rcx] "m"(inject_state.rcx),
                           [rdx] "m"(inject_state.rdx),
                           [rsi] "m"(inject_state.rsi),
                           [rdi] "m"(inject_state.rdi),
                           [r8] "m"(inject_state.r8),
                           [r9] "m"(inject_state.r9),
                           [r10] "m"(inject_state.r10),
                           [r11] "m"(inject_state.r11),
                           [r12] "m"(inject_state.r12),
                           [r13] "m"(inject_state.r13),
                           [r14] "m"(inject_state.r14),
                           [r15] "m"(inject_state.r15),
                           [rbp] "m"(inject_state.rbp),
                           [rsp]"m"(inject_state.rsp),
                           [packet] "m"(packet));
}

int poll_instr(int fd)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, -1);
    if (ret > 0)
    {
        if (pfd.revents & POLLIN)
        {
            ssize_t n = read(fd, instr, MAX_INSN_LENGTH);
            if (n != MAX_INSN_LENGTH)
            {
                fprintf(stderr, "Failed to read instruction from socket: %s\n", strerror(errno));
                return 1;
            }
            return 0;
        }
        else
        {
            fprintf(stderr, "Unexpected poll event: %d\n", pfd.revents);
            return 1;
        }
    }
    else if (ret == 0)
    {
        fprintf(stderr, "Poll timed out\n");
        return 1;
    }
    else
    {
        fprintf(stderr, "Poll error: %s\n", strerror(errno));
        return 1;
    }
}

int main()
{    
    int fd, i;
    void *null_p;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/insnexec.sock", sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }

    if (posix_memalign(&packet_buffer, PAGE_SIZE, PAGE_SIZE * 3) != 0)
    {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    assert(!mprotect(packet_buffer, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    assert(!mprotect((uint8_t *)packet_buffer + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE));

    null_p=mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(null_p == MAP_FAILED) {
        perror("mmap null page");
        return 1;
    }

    // register signal handler stack
    char* stack[SIGSTKSZ];
    stack_t ss = { .ss_size = SIGSTKSZ, .ss_sp = stack, };
    sigaltstack(&ss, 0);


    int count = 500;
    while (count-- > 0)
    {
        if (poll_instr(fd))
        {
            fprintf(stderr, "Error during poll\n");
            break;
        }
        printf("Received instruction: ");
        for (i = 0; i < MAX_INSN_LENGTH; i++)        {
            printf("%02x ", (unsigned char)instr[i]);
        }
        printf("\n");
        for (i = 1; i <= MAX_INSN_LENGTH; i++)
        {
            inject(i);
            //result.signum!=SIGSEGV very likely means the instruction executed successfully
            if(result.addr != (uint32_t)(uintptr_t)(packet_buffer+PAGE_SIZE))
            {
                break;
            }

        }

        result.length = i;
        if (write(fd, &result, sizeof(result)) != sizeof(result))
        {
            fprintf(stderr, "Failed to write result to socket: %s\n", strerror(errno));
            break;
        }
    }

    close(fd);
    munmap(null_p, PAGE_SIZE);
    free(packet_buffer);
    return 0;
}
