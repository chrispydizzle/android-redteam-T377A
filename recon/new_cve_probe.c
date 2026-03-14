/*
 * new_cve_probe.c — Probe for untested kernel CVEs on 3.10.9
 * Tests: DCCP (CVE-2017-8890), timerfd (CVE-2017-10661), 
 *        UDP race (CVE-2017-1000112), perf sampling fix
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o new_cve_probe new_cve_probe.c -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>

/* Protocol numbers */
#include <time.h>

#ifndef TFD_TIMER_ABSTIME
#define TFD_TIMER_ABSTIME       (1 << 0)
#endif
#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

/* perf_event */
#define PERF_TYPE_SOFTWARE    1
#define PERF_COUNT_SW_CPU_CLOCK  0
#define PERF_SAMPLE_IP        (1 << 0)
#define PERF_EVENT_IOC_ENABLE   0x2400
#define PERF_EVENT_IOC_DISABLE  0x2401

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
    union { unsigned long long bp_addr; unsigned long long config1; };
    union { unsigned long long bp_len; unsigned long long config2; };
    unsigned long long branch_sample_type;
    unsigned long long sample_regs_user;
    unsigned long long sample_stack_user;
};

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* ========== TEST 1: DCCP socket availability (CVE-2017-8890) ========== */
void test_dccp(void) {
    int fd;
    printf("[*] TEST 1: DCCP socket (CVE-2017-8890 surface)\n");
    
    /* Try DCCP over IPv4 */
    fd = socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP);
    if (fd >= 0) {
        printf("    [!] DCCP IPv4 AVAILABLE: fd=%d\n", fd);
        close(fd);
        
        /* Try DCCP over IPv6 — this is the CVE-2017-8890 vector */
        fd = socket(AF_INET6, SOCK_DCCP, IPPROTO_DCCP);
        if (fd >= 0) {
            printf("    [!!!] DCCP IPv6 AVAILABLE: fd=%d — CVE-2017-8890 REACHABLE!\n", fd);
            close(fd);
        } else {
            printf("    DCCP IPv6 FAILED: errno=%d (%s)\n", errno, strerror(errno));
        }
    } else {
        printf("    DCCP not compiled: errno=%d (%s)\n", errno, strerror(errno));
    }
}

/* ========== TEST 2: SCTP availability (CVE-2017-9075) ========== */
void test_sctp(void) {
    int fd;
    printf("\n[*] TEST 2: SCTP socket (CVE-2017-9075 surface)\n");
    
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd >= 0) {
        printf("    [!] SCTP AVAILABLE: fd=%d\n", fd);
        close(fd);
        
        fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
        if (fd >= 0) {
            printf("    [!!!] SCTP IPv6 AVAILABLE: fd=%d — CVE-2017-9075 REACHABLE!\n", fd);
            close(fd);
        } else {
            printf("    SCTP IPv6 FAILED: errno=%d (%s)\n", errno, strerror(errno));
        }
    } else {
        printf("    SCTP not compiled: errno=%d (%s)\n", errno, strerror(errno));
    }
}

/* ========== TEST 3: timerfd (CVE-2017-10661) ========== */
void test_timerfd(void) {
    int fd;
    printf("\n[*] TEST 3: timerfd (CVE-2017-10661 surface)\n");
    
    /* timerfd_create syscall */
    fd = syscall(__NR_timerfd_create, 0 /* CLOCK_REALTIME */, 0);
    if (fd >= 0) {
        printf("    [!] timerfd AVAILABLE: fd=%d\n", fd);
        
        /* Test timerfd_settime with TFD_TIMER_CANCEL_ON_SET */
        struct itimerspec its;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_sec = 999999;
        
        int ret = syscall(__NR_timerfd_settime, fd,
                         TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
                         &its, NULL);
        if (ret == 0) {
            printf("    [!!!] timerfd CANCEL_ON_SET works — CVE-2017-10661 REACHABLE!\n");
            printf("    Race: timerfd_settime(CANCEL_ON_SET) vs clock_settime\n");
        } else {
            printf("    timerfd_settime CANCEL_ON_SET: errno=%d (%s)\n", errno, strerror(errno));
        }
        
        close(fd);
    } else {
        printf("    timerfd not available: errno=%d (%s)\n", errno, strerror(errno));
    }
}

/* ========== TEST 4: UDP sendmsg race (CVE-2017-1000112) ========== */
void test_udp_race(void) {
    int fd;
    printf("\n[*] TEST 4: UDP socket (CVE-2017-1000112 surface)\n");
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("    UDP socket FAILED: errno=%d\n", errno);
        return;
    }
    printf("    UDP socket: fd=%d\n", fd);
    
    /* Bind to any port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    addr.sin_port = htons(0);
    
    int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        printf("    bind FAILED: errno=%d (%s)\n", errno, strerror(errno));
        /* SELinux might block */
    } else {
        printf("    bind SUCCESS — UDP sendmsg race surface accessible\n");
        
        /* Test cork + sendmsg (the CVE path) */
        int on = 1;
        ret = setsockopt(fd, IPPROTO_UDP, 10 /* UDP_CORK */, &on, sizeof(on));
        printf("    UDP_CORK: %s (ret=%d, errno=%d)\n",
               ret == 0 ? "WORKS" : "FAILED", ret, errno);
    }
    
    close(fd);
    
    /* Also test raw sockets */
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (fd >= 0) {
        printf("    [!] RAW socket AVAILABLE: fd=%d\n", fd);
        close(fd);
    } else {
        printf("    RAW socket: errno=%d (%s)\n", errno, strerror(errno));
    }
}

/* ========== TEST 5: IPv6 availability (multiple CVEs) ========== */
void test_ipv6(void) {
    printf("\n[*] TEST 5: IPv6 sockets (CVE-2017-9074/9075/9076)\n");
    
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd >= 0) {
        printf("    [!] IPv6 TCP AVAILABLE: fd=%d\n", fd);
        close(fd);
    } else {
        printf("    IPv6 TCP: errno=%d (%s)\n", errno, strerror(errno));
    }
    
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd >= 0) {
        printf("    [!] IPv6 UDP AVAILABLE: fd=%d\n", fd);
        close(fd);
    } else {
        printf("    IPv6 UDP: errno=%d (%s)\n", errno, strerror(errno));
    }
    
    fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd >= 0) {
        printf("    [!!!] IPv6 RAW AVAILABLE: fd=%d — fragmentation CVEs reachable!\n", fd);
        close(fd);
    } else {
        printf("    IPv6 RAW: errno=%d (%s)\n", errno, strerror(errno));
    }
}

/* ========== TEST 6: Fixed perf_event sampling ========== */
void test_perf_sampling(void) {
    struct perf_event_attr attr;
    int fd;
    
    printf("\n[*] TEST 6: Fixed perf_event sampling (freq-based)\n");
    
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_freq = 1000; /* 1000 Hz */
    attr.sample_type = PERF_SAMPLE_IP;
    /* flags: disabled=1 (bit 0), freq=1 (bit 10) */
    attr.flags = (1ULL << 0) | (1ULL << 10);
    attr.wakeup_events = 100;
    
    fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("    open FAILED: errno=%d (%s)\n", errno, strerror(errno));
        
        /* Try without freq flag */
        attr.flags = 1; /* just disabled */
        attr.sample_period = 100000; /* every 100K events */
        attr.sample_freq = 0;
        fd = perf_event_open(&attr, 0, -1, -1, 0);
        if (fd < 0) {
            printf("    Fallback open also FAILED: errno=%d\n", errno);
            return;
        }
        printf("    Fallback (period-based) opened: fd=%d\n", fd);
    } else {
        printf("    Freq-based opened: fd=%d\n", fd);
    }
    
    /* mmap ring buffer */
    size_t mmap_size = (1 + 16) * 4096;
    void *map = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        printf("    mmap FAILED: errno=%d\n", errno);
        close(fd);
        return;
    }
    
    /* Enable and generate work */
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    
    volatile unsigned long long x = 0;
    for (int i = 0; i < 5000000; i++) {
        x += i * 7;
        if (i % 100000 == 0) sched_yield();
    }
    
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    
    /* Check what we got */
    unsigned long long *header64 = (unsigned long long *)map;
    unsigned int *header32 = (unsigned int *)map;
    unsigned long long data_head = header64[8]; /* offset 64 = data_head */
    
    printf("    data_head (offset 64): %llu\n", data_head);
    printf("    data_head (offset 128): %llu\n", header64[16]);
    
    /* Dump first 128 bytes of header for debugging */
    printf("    Header dump (first 32 u32s):\n");
    for (int i = 0; i < 32; i += 4) {
        printf("    [%3d] %08x %08x %08x %08x\n",
               i*4, header32[i], header32[i+1], header32[i+2], header32[i+3]);
    }
    
    /* Also read counter value directly */
    unsigned long long count = 0;
    read(fd, &count, sizeof(count));
    printf("    Counter read: %llu\n", count);
    
    /* Scan data area for any non-zero content */
    unsigned char *data = (unsigned char *)map + 4096;
    int nonzero = 0;
    for (size_t i = 0; i < 16 * 4096; i++) {
        if (data[i]) nonzero++;
    }
    printf("    Non-zero data bytes: %d / %zu\n", nonzero, (size_t)(16 * 4096));
    
    if (nonzero > 0) {
        /* Print first few records */
        printf("    First data bytes: ");
        for (int i = 0; i < 64 && i < nonzero; i++) {
            printf("%02x ", data[i]);
            if ((i+1) % 16 == 0) printf("\n                      ");
        }
        printf("\n");
    }
    
    munmap(map, mmap_size);
    close(fd);
}

/* ========== TEST 7: netlink socket (kernel surface) ========== */
void test_netlink(void) {
    printf("\n[*] TEST 7: Netlink sockets\n");
    
    int types[] = { 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22 };
    const char *names[] = { "ROUTE", "UNUSED", "USERSOCK", "FIREWALL", "SOCK_DIAG",
        "NFLOG", "XFRM", "SELINUX", "ISCSI", "AUDIT", "FIB_LOOKUP",
        "CONNECTOR", "NETFILTER", "IP6_FW", "DNRTMSG", "KOBJECT_UEVENT",
        "GENERIC", "SCSITRANSPORT", "ECRYPTFS", "RDMA", "CRYPTO", "SMC" };
    
    for (int i = 0; i < 22; i++) {
        int fd = socket(AF_NETLINK, SOCK_RAW, types[i]);
        if (fd >= 0) {
            printf("    NETLINK_%s (%d): fd=%d ✓\n", names[i], types[i], fd);
            close(fd);
        }
    }
}

/* ========== TEST 8: Check interesting /proc entries ========== */
void test_proc_access(void) {
    printf("\n[*] TEST 8: Interesting /proc entries\n");
    
    const char *paths[] = {
        "/proc/slabinfo",
        "/proc/vmstat",
        "/proc/buddyinfo",
        "/proc/pagetypeinfo",
        "/proc/zoneinfo",
        "/proc/vmallocinfo",
        "/proc/iomem",
        "/proc/ioports",
        "/proc/modules",
        "/proc/kallsyms",
        "/proc/keys",
        "/proc/key-users",
        "/proc/softirqs",
        "/proc/interrupts",
        NULL
    };
    
    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            char buf[128];
            int n = read(fd, buf, sizeof(buf)-1);
            if (n > 0) {
                buf[n] = '\0';
                /* Check if addresses are visible (not zeroed) */
                char *p = strstr(buf, "0xc0");
                if (p || strstr(buf, " c0")) {
                    printf("    %-25s READABLE + HAS ADDRESSES!\n", paths[i]);
                } else {
                    printf("    %-25s readable\n", paths[i]);
                }
            }
            close(fd);
        } else {
            if (errno != ENOENT)
                printf("    %-25s blocked (errno=%d)\n", paths[i], errno);
        }
    }
}

int main(void) {
    printf("=== New CVE Surface Probe ===\n");
    printf("PID=%d, UID=%d\n\n", getpid(), getuid());
    
    test_dccp();
    test_sctp();
    test_timerfd();
    test_udp_race();
    test_ipv6();
    test_perf_sampling();
    test_netlink();
    test_proc_access();
    
    printf("\n=== Done ===\n");
    return 0;
}
