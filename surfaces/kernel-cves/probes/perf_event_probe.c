/*
 * perf_event_probe.c — Test perf_event_open access with security.perf_harden=0
 * Probes kernel perf subsystem for attack surface.
 * 
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o perf_event_probe perf_event_probe.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>

/* perf_event definitions for kernel 3.10 */
#define PERF_TYPE_HARDWARE     0
#define PERF_TYPE_SOFTWARE     1
#define PERF_TYPE_TRACEPOINT   2
#define PERF_TYPE_HW_CACHE     3
#define PERF_TYPE_RAW          4
#define PERF_TYPE_BREAKPOINT   5

#define PERF_COUNT_HW_CPU_CYCLES          0
#define PERF_COUNT_HW_INSTRUCTIONS        1
#define PERF_COUNT_HW_CACHE_REFERENCES    2
#define PERF_COUNT_HW_CACHE_MISSES        3
#define PERF_COUNT_HW_BRANCH_INSTRUCTIONS 4
#define PERF_COUNT_HW_BRANCH_MISSES       5

#define PERF_COUNT_SW_CPU_CLOCK        0
#define PERF_COUNT_SW_TASK_CLOCK       1
#define PERF_COUNT_SW_PAGE_FAULTS      2
#define PERF_COUNT_SW_CONTEXT_SWITCHES 3
#define PERF_COUNT_SW_CPU_MIGRATIONS   4

#define PERF_EVENT_IOC_ENABLE   0x2400
#define PERF_EVENT_IOC_DISABLE  0x2401
#define PERF_EVENT_IOC_REFRESH  0x2402
#define PERF_EVENT_IOC_RESET    0x2403
#define PERF_EVENT_IOC_SET_OUTPUT 0x2405
#define PERF_EVENT_IOC_SET_FILTER 0x40042406

struct perf_event_attr {
    unsigned int type;
    unsigned int size;
    unsigned long long config;
    union {
        unsigned long long sample_period;
        unsigned long long sample_freq;
    };
    unsigned long long sample_type;
    unsigned long long read_format;
    unsigned long long flags;  /* disabled, inherit, pinned, exclusive, etc. */
    unsigned int wakeup_events;
    unsigned int wakeup_watermark;
    unsigned int bp_type;
    union {
        unsigned long long bp_addr;
        unsigned long long config1;
    };
    union {
        unsigned long long bp_len;
        unsigned long long config2;
    };
    unsigned long long branch_sample_type;
    unsigned long long sample_regs_user;
    unsigned long long sample_stack_user;
};

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

#define PERF_FLAG_FD_OUTPUT   (1U << 0)
#define PERF_FLAG_FD_NO_GROUP (1U << 1)
#define PERF_FLAG_FD_CLOEXEC  (1U << 2)

/* Test basic perf_event_open access */
int test_basic_access(void) {
    struct perf_event_attr attr;
    int fd;

    printf("[*] TEST 1: Basic perf_event_open (SW CPU_CLOCK)\n");
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.flags = 1; /* disabled */

    fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("    FAILED: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("    SUCCESS: fd=%d\n", fd);
    
    /* Read counter */
    unsigned long long count = 0;
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(10000); /* 10ms */
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    read(fd, &count, sizeof(count));
    printf("    Counter value: %llu\n", count);
    
    close(fd);
    return 0;
}

/* Test hardware counter access */
int test_hw_counters(void) {
    struct perf_event_attr attr;
    int fd;
    const char *names[] = {
        "CPU_CYCLES", "INSTRUCTIONS", "CACHE_REFS", "CACHE_MISSES",
        "BRANCH_INSNS", "BRANCH_MISSES"
    };
    
    printf("\n[*] TEST 2: Hardware performance counters\n");
    for (int i = 0; i < 6; i++) {
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_HARDWARE;
        attr.size = sizeof(attr);
        attr.config = i;
        attr.flags = 1;
        
        fd = perf_event_open(&attr, 0, -1, -1, 0);
        if (fd < 0) {
            printf("    %s: FAILED (errno=%d)\n", names[i], errno);
        } else {
            ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
            /* Do some work */
            volatile int x = 0;
            for (int j = 0; j < 100000; j++) x += j;
            ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            unsigned long long count = 0;
            read(fd, &count, sizeof(count));
            printf("    %s: fd=%d, count=%llu\n", names[i], fd, count);
            close(fd);
        }
    }
    return 0;
}

/* Test mmap ring buffer — needed for some exploits */
int test_mmap_buffer(void) {
    struct perf_event_attr attr;
    int fd;
    void *map;
    
    printf("\n[*] TEST 3: perf_event mmap ring buffer\n");
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 1;
    attr.sample_type = 1; /* PERF_SAMPLE_IP */
    attr.flags = 1; /* disabled */
    
    fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("    FAILED to open: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    
    /* mmap: 1 page header + 2^n pages data (1 page = 4096) */
    size_t mmap_size = (1 + 4) * 4096; /* 5 pages */
    map = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        printf("    mmap FAILED: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("    mmap SUCCESS: addr=%p, size=%zu\n", map, mmap_size);
    
    /* Read header info — struct perf_event_mmap_page */
    unsigned int *header = (unsigned int *)map;
    printf("    Header: version=%u, compat=%u, lock=%u\n",
           header[0], header[1], header[2]);
    printf("    data_head=%u, data_tail=%u, data_offset=%u, data_size=%u\n",
           header[16], header[17], header[18], header[19]);
    
    munmap(map, mmap_size);
    close(fd);
    return 0;
}

/* Test SET_OUTPUT ioctl — relevant to CVE-2016-6786/6787 */
int test_set_output(void) {
    struct perf_event_attr attr;
    int fd1, fd2;
    int ret;
    
    printf("\n[*] TEST 4: PERF_EVENT_IOC_SET_OUTPUT (CVE-2016-6786 surface)\n");
    
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 1;
    attr.sample_type = 1;
    attr.flags = 1;
    
    fd1 = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd1 < 0) {
        printf("    FAILED to open fd1: errno=%d\n", errno);
        return -1;
    }
    
    /* Map fd1's buffer */
    size_t mmap_size = (1 + 4) * 4096;
    void *map = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
    if (map == MAP_FAILED) {
        printf("    FAILED to mmap fd1: errno=%d\n", errno);
        close(fd1);
        return -1;
    }
    
    fd2 = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd2 < 0) {
        printf("    FAILED to open fd2: errno=%d\n", errno);
        munmap(map, mmap_size);
        close(fd1);
        return -1;
    }
    
    /* Try SET_OUTPUT: redirect fd2's output to fd1's mmap buffer */
    ret = ioctl(fd2, PERF_EVENT_IOC_SET_OUTPUT, fd1);
    printf("    SET_OUTPUT fd2->fd1: ret=%d, errno=%d\n", ret, errno);
    
    if (ret == 0) {
        printf("    [!] SET_OUTPUT succeeded — CVE-2016-6786 race surface ACCESSIBLE\n");
    }
    
    close(fd2);
    munmap(map, mmap_size);
    close(fd1);
    return ret;
}

/* Test event group creation — needed for CVE-2017-6001 */
int test_event_groups(void) {
    struct perf_event_attr attr;
    int group_fd, child_fd;
    
    printf("\n[*] TEST 5: Event groups (CVE-2017-6001 surface)\n");
    
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.flags = 1;
    
    /* Create group leader */
    group_fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (group_fd < 0) {
        printf("    FAILED to open group leader: errno=%d\n", errno);
        return -1;
    }
    printf("    Group leader: fd=%d\n", group_fd);
    
    /* Create child event in the group */
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    child_fd = perf_event_open(&attr, 0, -1, group_fd, 0);
    if (child_fd < 0) {
        printf("    Child event FAILED: errno=%d (%s)\n", errno, strerror(errno));
        close(group_fd);
        return -1;
    }
    printf("    Child event: fd=%d\n", child_fd);
    printf("    [!] Event groups WORK — CVE-2017-6001 move_group race surface ACCESSIBLE\n");
    
    close(child_fd);
    close(group_fd);
    return 0;
}

/* Test tracepoint access — can we read kernel function traces? */
int test_tracepoint(void) {
    struct perf_event_attr attr;
    int fd;
    
    printf("\n[*] TEST 6: Tracepoint access (kernel function monitoring)\n");
    
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = 1; /* tracepoint ID — may need to find valid ID from tracefs */
    attr.sample_period = 1;
    attr.sample_type = 1;
    attr.flags = 1;
    
    fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("    Tracepoint id=1 FAILED: errno=%d (%s)\n", errno, strerror(errno));
        /* Try to find valid tracepoint IDs */
        printf("    Checking /sys/kernel/debug/tracing/events/...\n");
    } else {
        printf("    [!] Tracepoint ACCESSIBLE: fd=%d\n", fd);
        close(fd);
    }
    return 0;
}

/* Test breakpoint access — hardware breakpoints for kernel monitoring */
int test_breakpoint(void) {
    struct perf_event_attr attr;
    int fd;
    
    printf("\n[*] TEST 7: Hardware breakpoint\n");
    
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = 1; /* HW_BREAKPOINT_X */
    attr.bp_addr = 0xC0054328; /* commit_creds — will fail from userspace */
    attr.bp_len = 4; /* HW_BREAKPOINT_LEN_4 */
    attr.flags = 1;
    
    fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("    Breakpoint on 0xC0054328 FAILED: errno=%d (%s)\n", errno, strerror(errno));
    } else {
        printf("    [!] Breakpoint on kernel address ACCESSIBLE: fd=%d\n", fd);
        close(fd);
    }
    return 0;
}

/* Probe how many perf events can be opened (resource limits) */
int test_resource_limits(void) {
    struct perf_event_attr attr;
    int fds[1024];
    int count = 0;
    
    printf("\n[*] TEST 8: Resource limits (max perf events)\n");
    
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.flags = 1;
    
    for (int i = 0; i < 1024; i++) {
        fds[i] = perf_event_open(&attr, 0, -1, -1, 0);
        if (fds[i] < 0) {
            printf("    Max events: %d (errno=%d at event %d)\n", count, errno, i);
            break;
        }
        count++;
    }
    
    /* Close all */
    for (int i = 0; i < count; i++) close(fds[i]);
    printf("    Opened and closed %d perf events\n", count);
    return count;
}

int main(void) {
    printf("=== perf_event_open Probe ===\n");
    printf("PID=%d, UID=%d\n", getpid(), getuid());
    printf("Kernel: ");
    fflush(stdout);
    system("uname -r");
    printf("\n");
    
    int basic = test_basic_access();
    if (basic < 0) {
        printf("\n[!] Basic access FAILED — perf_event_open not available\n");
        printf("    Check: getprop security.perf_harden (should be 0)\n");
        return 1;
    }
    
    test_hw_counters();
    test_mmap_buffer();
    test_set_output();
    test_event_groups();
    test_tracepoint();
    test_breakpoint();
    test_resource_limits();
    
    printf("\n=== Summary ===\n");
    printf("perf_event_open is ACCESSIBLE from unprivileged shell.\n");
    printf("Check which CVEs apply to kernel 3.10.9.\n");
    
    return 0;
}
