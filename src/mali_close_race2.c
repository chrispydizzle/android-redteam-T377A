/*
 * mali_close_race2.c — Aggressive close+ioctl race with tight synchronization
 *
 * Previous version had ~3.8K close ops vs ~1.3M ioctl ops (too unbalanced).
 * This version:
 * - Uses barriers for tight synchronization
 * - Multiple close+ioctl patterns per iteration
 * - Tests ALL Mali vendor functions, not just import
 * - Also tests concurrent context init + destroy
 * - Higher iteration counts
 *
 * Build: .\qemu\build-arm.bat src\mali_close_race2.c mali_close_race2
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

static int mali_open_raw(void) {
    return open("/dev/mali0", O_RDWR | O_CLOEXEC);
}

static int mali_init_ctx(int fd) {
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0;
    hb[8] = 10;
    if (ioctl(fd, make_cmd_std(16), hb) < 0) return -1;
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd_std(16), hb) < 0) return -1;
    return 0;
}

static int mali_open_ctx(void) {
    int fd = mali_open_raw();
    if (fd < 0) return -1;
    if (mali_init_ctx(fd) < 0) { close(fd); return -1; }
    return fd;
}

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

/* ========== T1: Tight close during vendor ioctl ========== */
/*
 * Pattern: one thread does ioctl in tight loop, other thread closes
 * at a precise moment. The goal is to hit the window where the ioctl
 * has obtained the file/kbase_context pointer but close frees the context.
 */
static void test1_tight_close(void) {
    printf("\n=== T1: Tight close during vendor ioctl (5000 iterations) ===\n");
    fflush(stdout);

    int dma_fd = ion_alloc_dmabuf();
    if (dma_fd < 0) { printf("  SKIP: no dma_buf\n"); return; }

    int hits = 0, ok = 0, badf = 0;
    for (int iter = 0; iter < 5000; iter++) {
        int mali_fd = mali_open_ctx();
        if (mali_fd < 0) continue;

        /* Fork a child that does the close */
        pid_t pid = fork();
        if (pid == 0) {
            /* Child: immediately close then exit */
            /* Small delay to let parent start ioctl */
            for (volatile int i = 0; i < 100; i++);
            close(mali_fd);
            _exit(0);
        }

        /* Parent: spam vendor ioctls */
        for (int i = 0; i < 20; i++) {
            uint8_t ibuf[48];
            memset(ibuf, 0, 48);
            ((struct uk_header*)ibuf)->id = 513;
            *(uint64_t*)(ibuf + 8) = (uint64_t)(uintptr_t)&dma_fd;
            *(uint32_t*)(ibuf + 16) = 2;
            *(uint64_t*)(ibuf + 24) = 0xF;
            int r = ioctl(mali_fd, make_cmd_vendor(48), ibuf);
            if (r < 0 && errno == EBADF) { badf++; break; }
            if (r == 0 && ((struct uk_header*)ibuf)->id == 0) ok++;
        }

        int status;
        waitpid(pid, &status, 0);
        close(mali_fd); /* might already be closed */
        hits++;
    }
    close(dma_fd);
    printf("  %d iterations, %d EBADF hits, %d successful imports\n", hits, badf, ok);
}

/* ========== T2: Context init + destroy race ========== */
/*
 * Thread A: open mali, start version check + func 530
 * Thread B: close the mali fd mid-initialization
 * This races context creation with context destruction.
 */
static void test2_init_destroy_race(void) {
    printf("\n=== T2: Context init + close race (5000 iterations) ===\n");
    fflush(stdout);

    int badf = 0, init_ok = 0;
    for (int iter = 0; iter < 5000; iter++) {
        int mali_fd = mali_open_raw();
        if (mali_fd < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {
            /* Child: close after tiny delay */
            for (volatile int i = 0; i < 50; i++);
            close(mali_fd);
            _exit(0);
        }

        /* Parent: try to initialize context */
        uint8_t hb[16];
        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 0;
        hb[8] = 10;
        int r = ioctl(mali_fd, make_cmd_std(16), hb);
        if (r == 0) {
            memset(hb, 0, 16);
            ((struct uk_header*)hb)->id = 530;
            r = ioctl(mali_fd, make_cmd_std(16), hb);
            if (r == 0) init_ok++;
        }
        if (r < 0 && errno == EBADF) badf++;

        int status;
        waitpid(pid, &status, 0);
        close(mali_fd);
    }
    printf("  5000 iterations, %d EBADF, %d init_ok\n", badf, init_ok);
}

/* ========== T3: Multiple vendor funcs during close ========== */
/*
 * Thread A: rapid vendor ioctls (import, free, flags_change, alias, etc.)
 * Thread B: close(mali_fd)
 * Tests ALL vendor dispatch functions for close races.
 */

static volatile int t3_mali_fd = -1;
static volatile int t3_go = 0, t3_stop = 0;

static void *t3_vendor_hammer(void *arg) {
    while (!t3_go) sched_yield();
    int dma_fd = ion_alloc_dmabuf();
    int ops = 0;

    /* Mali vendor function IDs to fuzz */
    uint32_t funcs[] = {
        512, /* MEM_ALLOC */
        513, /* MEM_IMPORT */
        514, /* MEM_FREE */
        515, /* MEM_ALIAS */
        516, /* MEM_FLAGS_CHANGE */
        517, /* MEM_COMMIT */
        518, /* ? */
        519, /* ? */
        520, /* ? */
        521, /* ? */
        529, /* JOB_SUBMIT */
        530, /* CONTEXT_INIT (already done) */
        531, /* ? */
        532, /* ? */
    };
    int nfuncs = sizeof(funcs) / sizeof(funcs[0]);

    while (!t3_stop) {
        int fd = t3_mali_fd;
        if (fd < 0) { sched_yield(); continue; }

        uint32_t func = funcs[ops % nfuncs];
        uint8_t buf[64];
        memset(buf, 0, 64);
        ((struct uk_header*)buf)->id = func;

        if (func == 513 && dma_fd >= 0) {
            /* Import needs valid phandle */
            *(uint64_t*)(buf + 8) = (uint64_t)(uintptr_t)&dma_fd;
            *(uint32_t*)(buf + 16) = 2;
            *(uint64_t*)(buf + 24) = 0xF;
        } else if (func == 512) {
            /* MEM_ALLOC: 1 page */
            *(uint64_t*)(buf + 8) = 1; /* pages */
            *(uint64_t*)(buf + 16) = 1; /* pages */
            *(uint64_t*)(buf + 24) = 0xF; /* flags */
        } else if (func == 514) {
            /* MEM_FREE: gpu_va */
            *(uint64_t*)(buf + 8) = 0x102000000ULL;
        }

        ioctl(fd, make_cmd_vendor(64), buf);
        ops++;
    }

    if (dma_fd >= 0) close(dma_fd);
    return (void*)(long)ops;
}

static void *t3_closer_thread(void *arg) {
    while (!t3_go) sched_yield();
    int ops = 0;
    while (!t3_stop) {
        int fd = t3_mali_fd;
        if (fd >= 0) {
            close(fd);
            t3_mali_fd = -1;
        }
        usleep(1); /* tiny delay */
        int nfd = mali_open_ctx();
        t3_mali_fd = nfd;
        ops++;
    }
    return (void*)(long)ops;
}

static void test3_all_vendor_funcs_race(int duration) {
    printf("\n=== T3: All vendor funcs + close race (%d sec) ===\n", duration);
    fflush(stdout);

    t3_mali_fd = mali_open_ctx();
    if (t3_mali_fd < 0) { printf("  SKIP: can't open mali\n"); return; }

    t3_go = 0; t3_stop = 0;
    pthread_t th[5], tc;

    /* 4 ioctl hammers + 1 closer */
    for (int i = 0; i < 4; i++)
        pthread_create(&th[i], NULL, t3_vendor_hammer, NULL);
    pthread_create(&tc, NULL, t3_closer_thread, NULL);

    t3_go = 1;
    sleep(duration);
    t3_stop = 1;

    void *r;
    long total = 0;
    for (int i = 0; i < 4; i++) {
        pthread_join(th[i], &r);
        total += (long)r;
    }
    pthread_join(tc, &r);
    printf("  ioctl total: %ld, closer: %ld\n", total, (long)r);

    int fd = t3_mali_fd;
    if (fd >= 0) close(fd);
    t3_mali_fd = -1;
}

/* ========== T4: Same-fd concurrent standard + vendor ioctl ========== */
/*
 * Multiple threads do different ioctls on the SAME mali fd simultaneously.
 * No close — tests internal locking of the Mali driver.
 */
static volatile int t4_mali_fd = -1;
static volatile int t4_go = 0, t4_stop = 0;

static void *t4_std_ioctl(void *arg) {
    while (!t4_go) sched_yield();
    int ops = 0;
    while (!t4_stop) {
        int fd = t4_mali_fd;
        if (fd < 0) break;

        /* Rapidly query version info */
        uint8_t hb[16];
        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 0;
        hb[8] = 10;
        ioctl(fd, make_cmd_std(16), hb);
        ops++;
    }
    return (void*)(long)ops;
}

static void *t4_vendor_ioctl(void *arg) {
    while (!t4_go) sched_yield();
    int dma_fd = ion_alloc_dmabuf();
    int ops = 0;
    while (!t4_stop) {
        int fd = t4_mali_fd;
        if (fd < 0) break;

        /* Import + free cycle */
        uint8_t ibuf[48];
        memset(ibuf, 0, 48);
        ((struct uk_header*)ibuf)->id = 513;
        if (dma_fd >= 0)
            *(uint64_t*)(ibuf + 8) = (uint64_t)(uintptr_t)&dma_fd;
        *(uint32_t*)(ibuf + 16) = 2;
        *(uint64_t*)(ibuf + 24) = 0xF;
        ioctl(fd, make_cmd_vendor(48), ibuf);

        uint64_t gpu_va = *(uint64_t*)(ibuf + 32);
        if (((struct uk_header*)ibuf)->id == 0 && gpu_va) {
            /* Free the imported region */
            memset(ibuf, 0, 48);
            ((struct uk_header*)ibuf)->id = 514;
            *(uint64_t*)(ibuf + 8) = gpu_va;
            ioctl(fd, make_cmd_vendor(48), ibuf);
        }
        ops++;
    }
    if (dma_fd >= 0) close(dma_fd);
    return (void*)(long)ops;
}

static void test4_concurrent_ioctls(int duration) {
    printf("\n=== T4: Concurrent standard + vendor ioctl (%d sec) ===\n", duration);
    fflush(stdout);

    t4_mali_fd = mali_open_ctx();
    if (t4_mali_fd < 0) { printf("  SKIP\n"); return; }

    t4_go = 0; t4_stop = 0;
    pthread_t ts[2], tv[2];
    for (int i = 0; i < 2; i++) {
        pthread_create(&ts[i], NULL, t4_std_ioctl, NULL);
        pthread_create(&tv[i], NULL, t4_vendor_ioctl, NULL);
    }

    t4_go = 1;
    sleep(duration);
    t4_stop = 1;

    long std_total = 0, vendor_total = 0;
    void *r;
    for (int i = 0; i < 2; i++) {
        pthread_join(ts[i], &r); std_total += (long)r;
        pthread_join(tv[i], &r); vendor_total += (long)r;
    }
    printf("  std: %ld, vendor: %ld\n", std_total, vendor_total);
    close(t4_mali_fd);
    t4_mali_fd = -1;
}

/* ========== T5: Import+free race (use-after-free in GPU memory) ========== */
/*
 * Thread A: import dma_buf → get gpu_va
 * Thread B: free gpu_va immediately
 * Thread C: use (flags_change/alias) on the freed gpu_va
 * Tests internal reference counting of Mali memory regions.
 */
static volatile uint64_t shared_gpu_va = 0;
static volatile int t5_go = 0, t5_stop = 0;
static volatile int t5_mali_fd = -1;

static void *t5_importer(void *arg) {
    while (!t5_go) sched_yield();
    int dma_fd = ion_alloc_dmabuf();
    int ops = 0;
    while (!t5_stop) {
        int fd = t5_mali_fd;
        if (fd < 0 || dma_fd < 0) { sched_yield(); continue; }

        uint8_t ibuf[48];
        memset(ibuf, 0, 48);
        ((struct uk_header*)ibuf)->id = 513;
        *(uint64_t*)(ibuf + 8) = (uint64_t)(uintptr_t)&dma_fd;
        *(uint32_t*)(ibuf + 16) = 2;
        *(uint64_t*)(ibuf + 24) = 0xF;
        ioctl(fd, make_cmd_vendor(48), ibuf);
        if (((struct uk_header*)ibuf)->id == 0)
            shared_gpu_va = *(uint64_t*)(ibuf + 32);
        ops++;
    }
    if (dma_fd >= 0) close(dma_fd);
    return (void*)(long)ops;
}

static void *t5_freer(void *arg) {
    while (!t5_go) sched_yield();
    int ops = 0;
    while (!t5_stop) {
        uint64_t va = shared_gpu_va;
        int fd = t5_mali_fd;
        if (fd < 0 || !va) { sched_yield(); continue; }

        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 514;
        *(uint64_t*)(buf + 8) = va;
        ioctl(fd, make_cmd_vendor(48), buf);
        if (((struct uk_header*)buf)->id == 0)
            shared_gpu_va = 0;
        ops++;
    }
    return (void*)(long)ops;
}

static void *t5_user(void *arg) {
    while (!t5_go) sched_yield();
    int ops = 0;
    while (!t5_stop) {
        uint64_t va = shared_gpu_va;
        int fd = t5_mali_fd;
        if (fd < 0 || !va) { sched_yield(); continue; }

        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 516; /* FLAGS_CHANGE */
        *(uint64_t*)(buf + 8) = va;
        *(uint64_t*)(buf + 16) = 0xF;
        ioctl(fd, make_cmd_vendor(48), buf);
        ops++;
    }
    return (void*)(long)ops;
}

static void test5_import_free_race(int duration) {
    printf("\n=== T5: Import + free + use race (%d sec) ===\n", duration);
    fflush(stdout);

    t5_mali_fd = mali_open_ctx();
    if (t5_mali_fd < 0) { printf("  SKIP\n"); return; }

    shared_gpu_va = 0;
    t5_go = 0; t5_stop = 0;
    pthread_t ti, tf, tu;
    pthread_create(&ti, NULL, t5_importer, NULL);
    pthread_create(&tf, NULL, t5_freer, NULL);
    pthread_create(&tu, NULL, t5_user, NULL);

    t5_go = 1;
    sleep(duration);
    t5_stop = 1;

    void *ri, *rf, *ru;
    pthread_join(ti, &ri);
    pthread_join(tf, &rf);
    pthread_join(tu, &ru);
    printf("  import:%ld free:%ld use:%ld\n", (long)ri, (long)rf, (long)ru);
    close(t5_mali_fd);
    t5_mali_fd = -1;
}

/* ========== MAIN ========== */

static void sighandler(int sig) {
    printf("  *** SIGNAL %d ***\n", sig);
    fflush(stdout);
    _exit(128 + sig);
}

int main(int argc, char **argv) {
    int duration = 5;
    if (argc > 1) duration = atoi(argv[1]);
    if (duration < 1) duration = 1;
    if (duration > 60) duration = 60;

    printf("=== Aggressive Close+Ioctl Race Fuzzer v2 ===\n");
    printf("Duration: %d sec/test, PID=%d\n", duration, getpid());
    fflush(stdout);

    struct {
        const char *name;
        void (*func_d)(int);
        void (*func)(void);
        int needs_duration;
    } tests[] = {
        { "tight close during import", NULL, test1_tight_close, 0 },
        { "init+close race",           NULL, test2_init_destroy_race, 0 },
        { "all vendor funcs + close",  test3_all_vendor_funcs_race, NULL, 1 },
        { "concurrent std+vendor",     test4_concurrent_ioctls, NULL, 1 },
        { "import+free+use race",      test5_import_free_race, NULL, 1 },
        { NULL, NULL, NULL, 0 }
    };

    for (int i = 0; tests[i].name; i++) {
        printf("\n--- %s ---\n", tests[i].name);
        fflush(stdout);

        pid_t pid = fork();
        if (pid == 0) {
            signal(SIGSEGV, sighandler);
            signal(SIGBUS, sighandler);
            alarm(duration + 30);
            if (tests[i].needs_duration)
                tests[i].func_d(duration);
            else
                tests[i].func();
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("*** %s: CRASHED sig=%d ***\n", tests[i].name, sig);
        } else if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code >= 128)
                printf("*** %s: SIGNAL exit=%d ***\n", tests[i].name, code);
            else if (code != 0)
                printf("*** %s: exit=%d ***\n", tests[i].name, code);
            else
                printf("  %s: OK\n", tests[i].name);
        }
        usleep(500000);
    }

    printf("\n=== All v2 race tests complete ===\n");
    return 0;
}
