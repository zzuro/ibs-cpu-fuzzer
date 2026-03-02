
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

#include "include/compiler.h"
#include "include/instruction.h"

range_t total_range = {
    .start = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, .len = 0},
    .end = {.bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, .len = 0},
    .started = false};


inj_t inj;
result_t result; //observed result of the injected instruction, to be used for feedback


void init_inj(const insn_t* new_insn)
{
	inj.i=*new_insn;
	inj.index=-1; 
	inj.last_len=-1;
}

bool move_next_instruction(void)
{
    if (!total_range.started)
    {
        init_inj(&total_range.start);
        inj.index=total_range.start.len;
        total_range.started=true;
    }
    else
    {
        // If observed length changes, increment from the new end (tunnel deeper)
        if (result.length!=inj.last_len && inj.index<result.length-1) {
				inj.index++;
		}

        inj.last_len=result.length;
        inj.i.bytes[inj.index]++; //increment the byte at the end of the instruction


        //if inj.i.bytes[inj.index] == 0, it means we have overflowed the current byte and need to increment the next byte (tunnel up)
        while (inj.index >= 0 && inj.i.bytes[inj.index] == 0)
        {
            inj.index--;
            if (inj.index >= 0)
            {
                inj.i.bytes[inj.index]++;
            }
            /* new tunnel level, reset length */
            inj.last_len = -1;
        }
    }


	/* check if we are at, or past, the end instruction */
    return memcmp(inj.i.bytes, total_range.end.bytes, sizeof(inj.i.bytes)) < 0;
}

void inject(int fd)
{   
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;   
    
    ssize_t n = write(fd, inj.i.bytes, MAX_INSN_LENGTH);
    if (n != MAX_INSN_LENGTH)
    {
        fprintf(stderr, "Failed to write instruction to socket: %s\n", strerror(errno));
        return;
    }

    int ret = poll(&pfd, 1, -1);
    if(ret > 0) {
        if(pfd.revents & POLLIN) {
            n = read(fd, &result, sizeof(result));
            if (n != sizeof(result))
            {
                fprintf(stderr, "Failed to read result from socket: %s\n", strerror(errno));
            }
        } else {
            fprintf(stderr, "Unexpected poll event: %d\n", pfd.revents);
        }
    } else if (ret == 0) {
        fprintf(stderr, "Poll timed out\n");
    } else {
        fprintf(stderr, "Poll error: %s\n", strerror(errno));
    }
}

void print_result(void)
{
    printf("Result: valid=%u length=%u signal=%s si_code=%u addr=0x%08x\n",
           result.valid, result.length, strsignal(result.signum), result.si_code, result.addr);
}



int main()
{
    const char *path = "/tmp/insnexec.sock";

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

    unlink(path);                       // remove stale file if any
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(s, 16) < 0) { perror("listen"); return 1; }

    printf("listening on %s\n", path);
    int fd = accept(s, NULL, NULL);
    if (fd < 0) { perror("accept"); return 1; }

    while(move_next_instruction()) {
        inject(fd);
        print_result();
    }

    close(fd);
    return 0;
}