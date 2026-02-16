#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "ibs.h"


//src: https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/perf_event.h#L677
#define IBS_FETCH_DEFAULT	((1ULL<<57))
#define IBS_OP_DEFAULT		(1ULL<<19)


#define IBS_FETCH_SYSFS "/sys/bus/event_source/devices/ibs_fetch/type"
#define IBS_OP_SYSFS    "/sys/bus/event_source/devices/ibs_op/type"

struct sample_id
{
    uint32_t pid, tid;              /* if PERF_SAMPLE_TID set */
    uint64_t time;                  /* if PERF_SAMPLE_TIME set */
    uint64_t id;                    /* if PERF_SAMPLE_ID set */
    uint64_t stream_id;             /* if PERF_SAMPLE_STREAM_ID set  */
    uint32_t cpu, res;              /* if PERF_SAMPLE_CPU set */
    uint64_t identifier;            /* if PERF_SAMPLE_IDENTIFIER set */
};

struct perf_sample_event {
  struct perf_event_header hdr;
  uint64_t    sample_id;                // if PERF_SAMPLE_IDENTIFIER
  uint64_t    ip;                       // if PERF_SAMPLE_IP
  uint32_t    pid, tid;                 // if PERF_SAMPLE_TID
  uint64_t    time;                     // if PERF_SAMPLE_TIME
  uint64_t    addr;                     // if PERF_SAMPLE_ADDR
  uint64_t    id;                       // if PERF_SAMPLE_ID
  uint64_t    stream_id;                // if PERF_SAMPLE_STREAM_ID
  uint32_t    cpu, res;                 // if PERF_SAMPLE_CPU
  uint64_t    period;                   // if PERF_SAMPLE_PERIOD
  struct      read_format *v;           // if PERF_SAMPLE_READ
  uint64_t    nr;                       // if PERF_SAMPLE_CALLCHAIN
  uint64_t    *ips;                     // if PERF_SAMPLE_CALLCHAIN
  uint32_t    size_raw;                 // if PERF_SAMPLE_RAW
  char        *data_raw;                // if PERF_SAMPLE_RAW
  uint64_t    bnr;                      // if PERF_SAMPLE_BRANCH_STACK
  struct      perf_branch_entry *lbr;   // if PERF_SAMPLE_BRANCH_STACK
  uint64_t    abi;                      // if PERF_SAMPLE_REGS_USER
  uint64_t    *regs;                    // if PERF_SAMPLE_REGS_USER
  uint64_t    size_stack;               // if PERF_SAMPLE_STACK_USER
  char        *data_stack;              // if PERF_SAMPLE_STACK_USER
  uint64_t    dyn_size_stack;           // if PERF_SAMPLE_STACK_USER
  uint64_t    weight;                   // if PERF_SAMPLE_WEIGHT
  uint64_t    data_src;                 // if PERF_SAMPLE_DATA_SRC
  uint64_t    transaction;              // if PERF_SAMPLE_TRANSACTION
  uint64_t    abi_intr;                 // if PERF_SAMPLE_REGS_INTR
  uint64_t    *regs_intr;               // if PERF_SAMPLE_REGS_INTR
};


struct perf_record_lost {
    struct perf_event_header header;
    uint64_t    id;
    uint64_t    lost;
    struct sample_id sample_id;
};

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int sig) {
    (void)sig;
    g_stop = 1;
}

//there's no glibc wrapper for perf_event_open
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                            int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static inline uint64_t read_head(struct perf_event_mmap_page *meta) {
    __sync_synchronize();
    return meta->data_head; // points to head of data section
}

static inline void write_tail(struct perf_event_mmap_page *meta, uint64_t tail) {
    meta->data_tail = tail; //reflect the last read data
    __sync_synchronize();
}

static uint64_t read_uint64_t_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        exit(1);
    }
    buf[n] = '\0';
    // sysfs "type" files are usually decimal. Accept hex too.
    char *end = NULL;
    errno = 0;
    uint64_t v = strtoull(buf, &end, 0);
    if (errno != 0) {
        fprintf(stderr, "Failed to parse %s contents: %s\n", path, strerror(errno));
        exit(1);
    }
    return v;
}

static inline uint64_t rd_u64_unaligned(const void *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}


//src: https://github.com/torvalds/linux/blob/master/tools/perf/util/amd-sample-raw.c#L235
void decode_ibs_op(const uint8_t *raw, uint32_t raw_sz)
{
    if (raw_sz < 4 + 8*8) return;

    uint32_t caps;
    memcpy(&caps, raw, 4);

    uint64_t regs[8];
    for (int i = 0; i < 8; i++)
        regs[i] = rd_u64_unaligned(raw + 4 + i*8);

    union ibs_op_ctl   op_ctl   = { .val = regs[0] };
    uint64_t           op_rip   = regs[1];
    union ibs_op_data  op_data  = { .val = regs[2] };
    union ibs_op_data2 op_data2 = { .val = regs[3] };
    union ibs_op_data3 op_data3 = { .val = regs[4] };
    uint64_t           dc_lin   = regs[5];
    uint64_t           dc_phys  = regs[6];
    uint64_t           br_tgt   = regs[7];

    printf("caps=0x%08x\n", caps);
    printf("op_ctl=0x%016llx en=%d val=%d cnt_ctl=%d opmaxcnt=%u\n",
           (unsigned long long)op_ctl.val,
           (int)op_ctl.op_en, (int)op_ctl.op_val, (int)op_ctl.cnt_ctl,
           (unsigned)op_ctl.opmaxcnt);

    printf("rip=0x%016llx rip_invalid=%d\n",
           (unsigned long long)op_rip, (int)op_data.op_rip_invalid);

    printf("dc_lin_valid=%d dc_phys_valid=%d dc_lin=0x%016llx dc_phys=0x%016llx\n",
           (int)op_data3.dc_lin_addr_valid, (int)op_data3.dc_phy_addr_valid,
           (unsigned long long)dc_lin, (unsigned long long)dc_phys);

    printf("branch_target=0x%016llx\n", (unsigned long long)br_tgt);
}

int main() {

    int duration_s = 1;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
   
    // 1) Discover IBS Op PMU type dynamically, change path to get fetch instead of op if needed
    uint64_t ibs_type = read_uint64_t_file(IBS_OP_SYSFS);

    // 2) Configure perf_event_attr for IBS Op sampling
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);

    attr.type = (uint32_t)ibs_type;
    // cnt_ctl: set bit 19 in config => see amd_ibs_tool guide
    attr.config = IBS_OP_DEFAULT;
    // sample_period must have low 4 bits ignored by HW; set >= 0x10
    attr.sample_period = 0x1000; // tune this (lower => more samples, more overhead)

    // Get RAW IBS record + CPU number
    attr.sample_type =  PERF_SAMPLE_CPU | PERF_SAMPLE_RAW;

    // We want samples in an mmap ring buffer (not read() counts)
    attr.disabled = 1;
    attr.inherit = 1;

    // IBS in kernel historically may ignore exclude_* (your doc notes this),
    // but set them all to 0 to match.
    attr.exclude_kernel = 0;
    attr.exclude_user   = 0;
    attr.exclude_hv     = 0;
    attr.exclude_guest  = 0;
    attr.exclude_idle   = 0;

    // Ask for precise IP when possible (may be ignored for IBS; harmless)
    attr.pinned = 0;
    attr.precise_ip = 1;
    attr.mmap = 1;
    attr.comm = 1;
    attr.task = 1;
    attr.sample_id_all = 1;
    attr.comm_exec = 1;
    attr.read_format = 0; // no extra read format data, we get raw samples in the ring buffer

    //exclude_host might be intresting for later

    // 3) Open the event. Use system-wide (-1 pid, cpu = 0..N) or per-process see https://man7.org/linux/man-pages/man2/perf_event_open.2.html
    //
    // This example does per-process (pid = 0 means "calling process") and any CPU (-1).
    // If you want system-wide, use pid = -1 and a specific CPU >= 0 (and likely open per CPU).
    pid_t pid = -1;
    int cpu = 0;
    int group_fd = -1;
    unsigned long flags = PERF_FLAG_FD_CLOEXEC;

    int fd = (int)perf_event_open(&attr, pid, cpu, group_fd, flags);
    if (fd < 0) {
        fprintf(stderr, "perf_event_open failed: %s\n", strerror(errno));
        return 1;
    }

    // 4) mmap the perf ring buffer, the layout out of the ring buffer is documented under MMAP layout
    // One metadata page + N data pages. N must be power of two.
    const size_t data_pages = 256; 
    const size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);
    const size_t mmap_sz = (data_pages + 1) * page_sz; // +1 for metadata page

    void *base = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
    uint8_t *data = (uint8_t *)base + page_sz;
    const size_t data_sz = data_pages * page_sz;

    uint64_t tail = meta->data_tail;

    // 5) Start sampling
    // In the example i've seen, they reset the counter first
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) != 0) {
        fprintf(stderr, "ioctl RESET failed: %s\n", strerror(errno));
    }

    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        fprintf(stderr, "ioctl ENABLE failed: %s\n", strerror(errno));
        munmap(base, mmap_sz);
        close(fd);
        return 1;
    }

    
    time_t end_time = time(NULL) + duration_s;

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;

    while (!g_stop && time(NULL) < end_time) {
        (void)poll(&pfd, 1, 250);

        uint64_t head = read_head(meta);

        while (tail < head) {
            size_t off = (size_t)(tail % data_sz); //read until now

            struct perf_event_header hdr; //mmap values start with perf_event_header
            if (off + sizeof(hdr) <= data_sz) {
                memcpy(&hdr, data + off, sizeof(hdr));
            } else {
                size_t first = data_sz - off;
                memcpy(&hdr, data + off, first);
                memcpy(((uint8_t *)&hdr) + first, data, sizeof(hdr) - first);
            }

            uint8_t *rec = (uint8_t *)malloc(hdr.size);
            size_t rec_sz = hdr.size;
            if (!rec) {
                perror("malloc");
                g_stop = 1;
                break;
            }


            if (off + hdr.size <= data_sz) { //record is stashed just after the perf_event_header
                memcpy(rec, data + off, hdr.size);
            } else {
                size_t first = data_sz - off;
                memcpy(rec, data + off, first);
                memcpy(rec + first, data, hdr.size - first);
            }

            tail += hdr.size;

            if (hdr.type == PERF_RECORD_SAMPLE) {
                const uint8_t *p = rec;
                const uint8_t *end = rec + rec_sz;

                if (rec_sz < sizeof(struct perf_event_header))
                {
                    fprintf(stderr, "Record too small for header\n");
                    free(rec);
                    continue;
                }
                    
                p += sizeof(struct perf_event_header);

                if (attr.sample_type & PERF_SAMPLE_CPU)
                {
                    if (p + 8 > end)
                        return -1;
                    uint32_t cpu = *(const uint32_t *)p;
                    p += 4;
                    uint32_t res = *(const uint32_t *)p;
                    p += 4;
                    (void)res;
                    printf("cpu=%u ", cpu);
                    (void)cpu;
                }

                if (attr.sample_type & PERF_SAMPLE_RAW)
                {
                    if (p + 4 > end)
                        return -1;
                    uint32_t raw_sz = *(const uint32_t *)p;
                    p += 4;
                    if (p + raw_sz > end)
                        return -1;

                    const uint8_t *raw = p; // <-- THIS IS THE RAW PAYLOAD
                    printf("raw_sz=%u raw=%p\n", raw_sz, (void *)raw);

                    decode_ibs_op(raw, raw_sz);

                    p += raw_sz;
                }
            } else {
                printf("Non-sample event: type=%u size=%u\n", hdr.type, hdr.size);
            }

            free(rec);
        }

        write_tail(meta, tail);
    }


    // 6) Stop sampling
    if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) != 0) {
        fprintf(stderr, "ioctl DISABLE failed: %s\n", strerror(errno));
    }

    munmap(base, mmap_sz);
    close(fd);

    printf("\nDone.\n");
    return 0;

    return 0;
}