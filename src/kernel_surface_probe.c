/*
 * kernel_surface_probe.c — Deep kernel attack surface prober
 *
 * Tests: /dev/alarm ioctls, socket creation (netlink, raw, packet),
 *        /proc/net reads, ftrace event manipulation, misc kernel interfaces.
 *
 * Build: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -Wall -o kernel_surface_probe kernel_surface_probe.c
 * Run:   /data/local/tmp/kernel_surface_probe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/netlink.h>

/* Android alarm driver ioctls (from kernel source) */
#define ANDROID_ALARM_BASE_CMD(cmd)   (cmd & ~(_IOC(0, 0, 0xf0, 0)))
#define ANDROID_ALARM_SET_AND_WAIT(type)   _IOW('a', 2 | ((type) << 4), struct timespec)
#define ANDROID_ALARM_SET(type)            _IOW('a', 3 | ((type) << 4), struct timespec)
#define ANDROID_ALARM_GET_TIME(type)       _IOW('a', 4 | ((type) << 4), struct timespec)
#define ANDROID_ALARM_CLEAR(type)          _IO ('a', 2 | ((type) << 4))
#define ANDROID_ALARM_SET_RTC              _IOW('a', 5, struct timespec)

/* Alarm types */
#define ANDROID_ALARM_RTC_WAKEUP        0
#define ANDROID_ALARM_RTC               1
#define ANDROID_ALARM_ELAPSED_REALTIME_WAKEUP  2
#define ANDROID_ALARM_ELAPSED_REALTIME  3
#define ANDROID_ALARM_SYSTEMTIME        4

static int test_passed = 0, test_failed = 0, test_blocked = 0;

#define TEST(name, expr) do { \
    errno = 0; \
    int _r = (expr); \
    if (_r >= 0) { \
        printf("  [PASS] %s (ret=%d)\n", name, _r); \
        test_passed++; \
    } else if (errno == EACCES || errno == EPERM) { \
        printf("  [BLOCK] %s (%s)\n", name, strerror(errno)); \
        test_blocked++; \
    } else { \
        printf("  [FAIL] %s (ret=%d, %s)\n", name, _r, strerror(errno)); \
        test_failed++; \
    } \
} while(0)

/* ===== /dev/alarm ===== */
static void test_alarm(void) {
    printf("\n=== /dev/alarm ===\n");

    int fd = open("/dev/alarm", O_RDWR);
    if (fd < 0) {
        fd = open("/dev/alarm", O_RDONLY);
        if (fd < 0) {
            printf("  Cannot open /dev/alarm: %s\n", strerror(errno));
            test_blocked++;
            return;
        }
        printf("  Opened /dev/alarm read-only (fd=%d)\n", fd);
    } else {
        printf("  Opened /dev/alarm read-write (fd=%d)\n", fd);
    }

    /* GET_TIME for each alarm type */
    for (int type = 0; type <= 4; type++) {
        struct timespec ts = {0};
        char name[64];
        snprintf(name, sizeof(name), "GET_TIME(type=%d)", type);
        int ret = ioctl(fd, ANDROID_ALARM_GET_TIME(type), &ts);
        if (ret >= 0) {
            printf("  [PASS] %s → %ld.%09ld\n", name, (long)ts.tv_sec, ts.tv_nsec);
            test_passed++;
        } else {
            printf("  [FAIL] %s (%s)\n", name, strerror(errno));
            test_failed++;
        }
    }

    /* SET alarm - may be denied */
    struct timespec ts = {0, 0};
    TEST("SET(RTC_WAKEUP, 0)", ioctl(fd, ANDROID_ALARM_SET(ANDROID_ALARM_RTC_WAKEUP), &ts));
    TEST("CLEAR(RTC_WAKEUP)", ioctl(fd, ANDROID_ALARM_CLEAR(ANDROID_ALARM_RTC_WAKEUP)));

    /* SET_RTC - highly privileged */
    ts.tv_sec = 0; ts.tv_nsec = 0;
    TEST("SET_RTC(0,0)", ioctl(fd, ANDROID_ALARM_SET_RTC, &ts));

    /* Random ioctl numbers */
    TEST("ioctl(0xDEAD)", ioctl(fd, 0xDEAD, NULL));
    TEST("ioctl(0)", ioctl(fd, 0, NULL));

    close(fd);
}

/* ===== Socket creation ===== */
static void test_sockets(void) {
    printf("\n=== Socket Creation ===\n");
    int fd;

    /* TCP */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) { printf("  [PASS] TCP socket (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [FAIL] TCP: %s\n", strerror(errno)); test_failed++; }

    /* UDP */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) { printf("  [PASS] UDP socket (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [FAIL] UDP: %s\n", strerror(errno)); test_failed++; }

    /* ICMP (ping) */
    fd = socket(AF_INET, SOCK_DGRAM, 1 /* IPPROTO_ICMP */);
    if (fd >= 0) { printf("  [PASS] ICMP socket (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] ICMP: %s\n", strerror(errno)); test_blocked++; }

    /* RAW IP */
    fd = socket(AF_INET, SOCK_RAW, 255);
    if (fd >= 0) { printf("  [PASS] RAW socket (fd=%d) *** SECURITY ISSUE ***\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] RAW: %s\n", strerror(errno)); test_blocked++; }

    /* PACKET */
    fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd >= 0) { printf("  [PASS] PACKET socket (fd=%d) *** SECURITY ISSUE ***\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] PACKET: %s\n", strerror(errno)); test_blocked++; }

    /* Netlink ROUTE */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd >= 0) { printf("  [PASS] NETLINK_ROUTE (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] NETLINK_ROUTE: %s\n", strerror(errno)); test_blocked++; }

    /* Netlink KOBJECT_UEVENT */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (fd >= 0) { printf("  [PASS] NETLINK_UEVENT (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] NETLINK_UEVENT: %s\n", strerror(errno)); test_blocked++; }

    /* Netlink AUDIT */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
    if (fd >= 0) { printf("  [PASS] NETLINK_AUDIT (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] NETLINK_AUDIT: %s\n", strerror(errno)); test_blocked++; }

    /* Netlink SELINUX */
    fd = socket(AF_NETLINK, SOCK_RAW, 7 /* NETLINK_SELINUX */);
    if (fd >= 0) { printf("  [PASS] NETLINK_SELINUX (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] NETLINK_SELINUX: %s\n", strerror(errno)); test_blocked++; }

    /* Netlink CONNECTOR */
    fd = socket(AF_NETLINK, SOCK_RAW, 11 /* NETLINK_CONNECTOR */);
    if (fd >= 0) { printf("  [PASS] NETLINK_CONNECTOR (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] NETLINK_CONNECTOR: %s\n", strerror(errno)); test_blocked++; }

    /* Netlink GENERIC */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd >= 0) { printf("  [PASS] NETLINK_GENERIC (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] NETLINK_GENERIC: %s\n", strerror(errno)); test_blocked++; }

    /* IPv6 RAW */
    fd = socket(AF_INET6, SOCK_RAW, 58 /* ICMPv6 */);
    if (fd >= 0) { printf("  [PASS] ICMPv6 RAW (fd=%d)\n", fd); test_passed++; close(fd); }
    else { printf("  [BLOCK] ICMPv6 RAW: %s\n", strerror(errno)); test_blocked++; }
}

/* ===== /proc readable entries ===== */
static void test_proc_read(const char *path, const char *name) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[64];
        int n = read(fd, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n < 32 ? n : 32] = '\0';
            /* Strip newlines */
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';
            printf("  [READ] %-40s → %.30s\n", name, buf);
            test_passed++;
        } else {
            printf("  [EMPTY] %s\n", name);
            test_passed++;
        }
        close(fd);
    } else {
        printf("  [DENIED] %-40s (%s)\n", name, strerror(errno));
        test_blocked++;
    }
}

static void test_proc(void) {
    printf("\n=== /proc Kernel Info ===\n");

    test_proc_read("/proc/version", "/proc/version");
    test_proc_read("/proc/uptime", "/proc/uptime");
    test_proc_read("/proc/loadavg", "/proc/loadavg");
    test_proc_read("/proc/stat", "/proc/stat");
    test_proc_read("/proc/vmstat", "/proc/vmstat");
    test_proc_read("/proc/meminfo", "/proc/meminfo");
    test_proc_read("/proc/slabinfo", "/proc/slabinfo");
    test_proc_read("/proc/kallsyms", "/proc/kallsyms");
    test_proc_read("/proc/cmdline", "/proc/cmdline");
    test_proc_read("/proc/iomem", "/proc/iomem");
    test_proc_read("/proc/ioports", "/proc/ioports");
    test_proc_read("/proc/interrupts", "/proc/interrupts");
    test_proc_read("/proc/softirqs", "/proc/softirqs");
    test_proc_read("/proc/timer_list", "/proc/timer_list");
    test_proc_read("/proc/sched_debug", "/proc/sched_debug");
    test_proc_read("/proc/pagetypeinfo", "/proc/pagetypeinfo");
    test_proc_read("/proc/vmallocinfo", "/proc/vmallocinfo");
    test_proc_read("/proc/buddyinfo", "/proc/buddyinfo");
    test_proc_read("/proc/diskstats", "/proc/diskstats");
    test_proc_read("/proc/partitions", "/proc/partitions");
    test_proc_read("/proc/crypto", "/proc/crypto");
    test_proc_read("/proc/locks", "/proc/locks");
    test_proc_read("/proc/keys", "/proc/keys");
    test_proc_read("/proc/key-users", "/proc/key-users");
    test_proc_read("/proc/zoneinfo", "/proc/zoneinfo");
    test_proc_read("/proc/modules", "/proc/modules");

    printf("\n=== /proc/sys Kernel Tunables ===\n");
    test_proc_read("/proc/sys/kernel/kptr_restrict", "kptr_restrict");
    test_proc_read("/proc/sys/kernel/dmesg_restrict", "dmesg_restrict");
    test_proc_read("/proc/sys/kernel/randomize_va_space", "randomize_va_space");
    test_proc_read("/proc/sys/kernel/perf_event_paranoid", "perf_event_paranoid");
    test_proc_read("/proc/sys/vm/mmap_min_addr", "mmap_min_addr");
    test_proc_read("/proc/sys/net/ipv4/ip_forward", "ip_forward");
    test_proc_read("/proc/sys/net/ipv4/ping_group_range", "ping_group_range");
    test_proc_read("/proc/sys/kernel/yama/ptrace_scope", "ptrace_scope");
    test_proc_read("/proc/sys/kernel/core_pattern", "core_pattern");
    test_proc_read("/proc/sys/kernel/modules_disabled", "modules_disabled");
    test_proc_read("/proc/sys/kernel/sched_child_runs_first", "sched_child_runs_first");
}

/* ===== Misc kernel surfaces ===== */
static void test_misc(void) {
    printf("\n=== Misc Kernel Surfaces ===\n");

    /* mmap /dev/null */
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p != MAP_FAILED) {
            printf("  [PASS] mmap /dev/null succeeded (%p)\n", p);
            test_passed++;
            munmap(p, 4096);
        } else {
            printf("  [FAIL] mmap /dev/null: %s\n", strerror(errno));
            test_failed++;
        }
        close(fd);
    }

    /* mmap NULL page (mmap_min_addr check) */
    void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (p != MAP_FAILED) {
        printf("  [PASS] mmap(NULL, FIXED) succeeded *** SECURITY ISSUE - null deref possible ***\n");
        test_passed++;
        munmap(p, 4096);
    } else {
        printf("  [BLOCK] mmap(NULL, FIXED): %s (good - mmap_min_addr protects)\n", strerror(errno));
        test_blocked++;
    }

    /* Try mmap at page 0 explicitly */
    p = mmap((void*)0x1000, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (p != MAP_FAILED) {
        printf("  [PASS] mmap(0x1000, FIXED) succeeded\n");
        test_passed++;
        munmap(p, 4096);
    } else {
        printf("  [BLOCK] mmap(0x1000, FIXED): %s\n", strerror(errno));
        test_blocked++;
    }

    /* /proc/self/mem read */
    fd = open("/proc/self/mem", O_RDONLY);
    if (fd >= 0) {
        printf("  [PASS] open /proc/self/mem\n");
        test_passed++;
        close(fd);
    } else {
        printf("  [BLOCK] /proc/self/mem: %s\n", strerror(errno));
        test_blocked++;
    }

    /* /proc/1/status - can we read init's info? */
    test_proc_read("/proc/1/status", "/proc/1/status (init)");
    test_proc_read("/proc/1/cmdline", "/proc/1/cmdline (init)");
    test_proc_read("/proc/1/environ", "/proc/1/environ (init)");
    test_proc_read("/proc/1/maps", "/proc/1/maps (init)");
    test_proc_read("/proc/1/smaps", "/proc/1/smaps (init)");
    test_proc_read("/proc/1/wchan", "/proc/1/wchan (init)");
    test_proc_read("/proc/1/stack", "/proc/1/stack (init)");
}

int main(void) {
    printf("=== Kernel Surface Probe ===\n");
    printf("uid=%d gid=%d\n", getuid(), getgid());

    test_alarm();
    test_sockets();
    test_proc();
    test_misc();

    printf("\n=== SUMMARY ===\n");
    printf("Passed:  %d\n", test_passed);
    printf("Failed:  %d\n", test_failed);
    printf("Blocked: %d\n", test_blocked);

    return 0;
}
