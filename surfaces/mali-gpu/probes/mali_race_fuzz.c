/*
 * mali_race_fuzz.c — Mali GPU driver race condition fuzzer
 *
 * Now that ION struct is fixed, Mali MEM_IMPORT actually WORKS.
 * Previous "all fail" results were from wrong ION struct layout.
 *
 * Target races:
 *   1. close(mali_fd) vs concurrent ioctl → context teardown UAF
 *   2. mmap + munmap racing with MEM_FREE/MEM_COMMIT
 *   3. Two threads doing MEM_IMPORT + MEM_FREE on same handle
 *   4. Fork + close in child while parent does operations
 *   5. Concurrent MEM_IMPORT from two contexts on same dma_buf
 *
 * Safety: all tests in forked child with alarm(5).
 * Build: .\qemu\build-arm.bat src\mali_race_fuzz.c mali_race_fuzz
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
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>

struct uk_header { uint32_t id; uint32_t ret; };

static int make_cmd(int magic, int sz) { return _IOC(3, magic, 0, sz); }
static volatile int g_stop = 0;

/* ===== ION helpers (correct ARM32 struct) ===== */

static int ion_alloc_fd(void) {
    int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (ion < 0) return -1;
    struct { uint32_t len, align, heap_id_mask, flags, handle; } alloc = {4096, 4096, 1, 0, 0};
    int r = ioctl(ion, 0xC0144900, &alloc);
    if (r < 0 || alloc.handle == 0) { close(ion); return -1; }
    struct { uint32_t handle; int32_t fd; } share = { alloc.handle, -1 };
    r = ioctl(ion, 0xC0084904, &share);
    close(ion);
    return (r < 0 || share.fd < 0) ? -1 : share.fd;
}

/* ===== Mali helpers ===== */

static int mali_open_and_handshake(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16]; memset(hb, 0, 16);
    ((struct uk_header *)hb)->id = 0; hb[8] = 10;
    if (ioctl(fd, make_cmd('M', 16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header *)hb)->id = 530;
    if (ioctl(fd, make_cmd('M', 16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static int mali_mem_import(int mali_fd, int dma_fd, uint64_t *gpu_va_out) {
    uint8_t buf[48]; memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;                /* MEM_IMPORT (UK_FUNC_ID + 1) */
    *(uint64_t *)(buf + 8) = (uintptr_t)&dma_fd; /* phandle = ptr to fd */
    *(uint32_t *)(buf + 16) = 2;                  /* type = UMM */
    *(uint64_t *)(buf + 24) = 0x0F;              /* flags: CPU+GPU RW */
    int r = ioctl(mali_fd, make_cmd('M', 48), buf);
    uint32_t result_id = *(uint32_t *)(buf + 0);
    if (gpu_va_out) *gpu_va_out = *(uint64_t *)(buf + 32);
    return (r >= 0 && result_id == 0) ? 0 : -1;
}

/* MEM_FREE: func_id = 515 (UK_FUNC_ID + 3) */
static int mali_mem_free(int mali_fd, uint64_t gpu_va) {
    uint8_t buf[16]; memset(buf, 0, 16);
    *(uint32_t *)(buf + 0) = 515;
    *(uint64_t *)(buf + 8) = gpu_va;
    int r = ioctl(mali_fd, make_cmd('M', 16), buf);
    return (r >= 0 && *(uint32_t *)buf == 0) ? 0 : -1;
}

/* MEM_ALLOC: func_id = 514 (UK_FUNC_ID + 2) */
static int mali_mem_alloc(int mali_fd, uint32_t pages, uint64_t *gpu_va_out) {
    uint8_t buf[48]; memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 514;
    *(uint64_t *)(buf + 8) = pages;  /* va_pages */
    *(uint64_t *)(buf + 16) = pages; /* commit_pages */
    *(uint64_t *)(buf + 24) = 0x0F;  /* flags: CPU+GPU RW */
    int r = ioctl(mali_fd, make_cmd('M', 48), buf);
    uint32_t result_id = *(uint32_t *)(buf + 0);
    if (gpu_va_out) *gpu_va_out = *(uint64_t *)(buf + 32);
    return (r >= 0 && result_id == 0) ? 0 : -1;
}

/* MEM_QUERY: func_id = 531 (UK_FUNC_ID + 19) */
static int mali_mem_query(int mali_fd, uint64_t gpu_va) {
    uint8_t buf[48]; memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 531;
    *(uint64_t *)(buf + 8) = gpu_va;
    *(uint64_t *)(buf + 16) = 1;  /* query = VA_SIZE */
    int r = ioctl(mali_fd, make_cmd('M', 48), buf);
    return (r >= 0 && *(uint32_t *)buf == 0) ? 0 : -1;
}

/* ===== TEST 1: Close + ioctl race ===== */

struct close_race_args {
    int mali_fd;
    int dma_fd;
};

static void *close_thread(void *arg) {
    struct close_race_args *a = arg;
    usleep(50); /* tiny delay to let ioctl start */
    close(a->mali_fd);
    return NULL;
}

static void *ioctl_thread(void *arg) {
    struct close_race_args *a = arg;
    for (int i = 0; i < 10 && !g_stop; i++) {
        uint64_t gpu_va;
        mali_mem_import(a->mali_fd, a->dma_fd, &gpu_va);
        usleep(10);
    }
    return NULL;
}

static void test_close_ioctl_race(void) {
    printf("=== TEST 1: close(mali) vs concurrent ioctl ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 200; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int mali_fd = mali_open_and_handshake();
            if (mali_fd < 0) _exit(99);
            int dma_fd = ion_alloc_fd();
            if (dma_fd < 0) { close(mali_fd); _exit(98); }

            /* First, do a successful import so the context has active allocations */
            uint64_t gpu_va;
            mali_mem_import(mali_fd, dma_fd, &gpu_va);

            struct close_race_args args = { mali_fd, dma_fd };
            pthread_t t1, t2;
            g_stop = 0;
            pthread_create(&t1, NULL, close_thread, &args);
            pthread_create(&t2, NULL, ioctl_thread, &args);
            pthread_join(t1, NULL);
            g_stop = 1;
            pthread_join(t2, NULL);
            close(dma_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGALRM)
                printf("  [%d] HANG!\n", trial);
            else
                printf("  [%d] CRASH sig=%d *** POTENTIAL BUG ***\n", trial, sig);
            anomalies++;
        }
        if ((trial + 1) % 50 == 0)
            printf("  [%d/200] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 200 trials\n\n", anomalies);
}

/* ===== TEST 2: MEM_FREE + MEM_QUERY race (double-operation on same region) ===== */

struct free_query_args {
    int mali_fd;
    uint64_t gpu_va;
    volatile int freed;
};

static void *free_thread(void *arg) {
    struct free_query_args *a = arg;
    usleep(20);
    mali_mem_free(a->mali_fd, a->gpu_va);
    a->freed = 1;
    return NULL;
}

static void *query_thread(void *arg) {
    struct free_query_args *a = arg;
    for (int i = 0; i < 50 && !a->freed; i++) {
        mali_mem_query(a->mali_fd, a->gpu_va);
        usleep(5);
    }
    return NULL;
}

static void test_free_query_race(void) {
    printf("=== TEST 2: MEM_FREE vs MEM_QUERY race ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 200; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int mali_fd = mali_open_and_handshake();
            if (mali_fd < 0) _exit(99);
            int dma_fd = ion_alloc_fd();
            if (dma_fd < 0) { close(mali_fd); _exit(98); }

            uint64_t gpu_va;
            if (mali_mem_import(mali_fd, dma_fd, &gpu_va) < 0)
                { close(dma_fd); close(mali_fd); _exit(97); }

            struct free_query_args args = { mali_fd, gpu_va, 0 };
            pthread_t t1, t2;
            pthread_create(&t1, NULL, free_thread, &args);
            pthread_create(&t2, NULL, query_thread, &args);
            pthread_join(t1, NULL);
            pthread_join(t2, NULL);
            close(dma_fd);
            close(mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 50 == 0)
            printf("  [%d/200] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 200 trials\n\n", anomalies);
}

/* ===== TEST 3: mmap + munmap racing with MEM_FREE ===== */

static void test_mmap_free_race(void) {
    printf("=== TEST 3: Mali mmap vs MEM_FREE race ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 200; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int mali_fd = mali_open_and_handshake();
            if (mali_fd < 0) _exit(99);

            /* Use MEM_ALLOC (not import) for mmap-able regions */
            uint64_t gpu_va;
            if (mali_mem_alloc(mali_fd, 1, &gpu_va) < 0)
                { close(mali_fd); _exit(97); }

            /* Try to mmap the Mali context (offset=gpu_va in pages) */
            void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
                            mali_fd, gpu_va);

            /* Race: free while mapped */
            pthread_t t;
            struct free_query_args args = { mali_fd, gpu_va, 0 };
            pthread_create(&t, NULL, free_thread, &args);

            /* Touch mapped memory while free may be happening */
            if (map != MAP_FAILED) {
                for (int i = 0; i < 100; i++) {
                    volatile char *p = (volatile char *)map;
                    *p = (char)i;
                    usleep(1);
                }
                munmap(map, 4096);
            }

            pthread_join(t, NULL);
            close(mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 50 == 0)
            printf("  [%d/200] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 200 trials\n\n", anomalies);
}

/* ===== TEST 4: Rapid alloc+free race (trigger SLUB reuse) ===== */

static void test_rapid_alloc_free(void) {
    printf("=== TEST 4: Rapid MEM_ALLOC + MEM_FREE (SLUB pressure) ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int mali_fd = mali_open_and_handshake();
            if (mali_fd < 0) _exit(99);

            /* Rapid alloc/free cycles */
            for (int i = 0; i < 500; i++) {
                uint64_t gpu_va;
                if (mali_mem_alloc(mali_fd, 1, &gpu_va) == 0)
                    mali_mem_free(mali_fd, gpu_va);
            }

            close(mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
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

/* ===== TEST 5: Double-free (free same gpu_va twice) ===== */

static void test_double_free(void) {
    printf("=== TEST 5: Double MEM_FREE (same gpu_va) ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 50; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int mali_fd = mali_open_and_handshake();
            if (mali_fd < 0) _exit(99);
            int dma_fd = ion_alloc_fd();
            if (dma_fd < 0) { close(mali_fd); _exit(98); }

            uint64_t gpu_va;
            if (mali_mem_import(mali_fd, dma_fd, &gpu_va) < 0)
                { close(dma_fd); close(mali_fd); _exit(97); }

            /* Free once */
            mali_mem_free(mali_fd, gpu_va);

            /* Alloc new region (reclaim freed slab) */
            uint64_t gpu_va2;
            mali_mem_alloc(mali_fd, 1, &gpu_va2);

            /* Free AGAIN with old gpu_va — may corrupt new allocation */
            mali_mem_free(mali_fd, gpu_va);

            close(dma_fd);
            close(mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 25 == 0)
            printf("  [%d/50] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 50 trials\n\n", anomalies);
}

/* ===== TEST 6: Concurrent import+free from two threads ===== */

struct import_free_args {
    int mali_fd;
    int dma_fd;
    volatile int do_free;
};

static void *import_loop(void *arg) {
    struct import_free_args *a = arg;
    for (int i = 0; i < 100 && !g_stop; i++) {
        uint64_t gpu_va;
        if (mali_mem_import(a->mali_fd, a->dma_fd, &gpu_va) == 0) {
            a->do_free = 1; /* signal free thread */
            usleep(10);
        }
    }
    return NULL;
}

static void *free_loop(void *arg) {
    struct import_free_args *a = arg;
    for (int i = 0; i < 100 && !g_stop; i++) {
        if (a->do_free) {
            /* Try to free regions — we don't know exact gpu_va but try common ones */
            uint64_t try_va;
            for (try_va = 0x100000; try_va < 0x200000; try_va += 0x1000)
                mali_mem_free(a->mali_fd, try_va);
            a->do_free = 0;
        }
        usleep(5);
    }
    return NULL;
}

static void test_import_free_race(void) {
    printf("=== TEST 6: Import + Free race (concurrent threads) ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int mali_fd = mali_open_and_handshake();
            if (mali_fd < 0) _exit(99);
            int dma_fd = ion_alloc_fd();
            if (dma_fd < 0) { close(mali_fd); _exit(98); }

            struct import_free_args args = { mali_fd, dma_fd, 0 };
            pthread_t t1, t2;
            g_stop = 0;
            pthread_create(&t1, NULL, import_loop, &args);
            pthread_create(&t2, NULL, free_loop, &args);
            sleep(1);
            g_stop = 1;
            pthread_join(t1, NULL);
            pthread_join(t2, NULL);
            close(dma_fd);
            close(mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
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

/* ===== TEST 7: Multi-context import of same dma_buf ===== */

static void test_multi_context_import(void) {
    printf("=== TEST 7: Multi-context import + close race ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int dma_fd = ion_alloc_fd();
            if (dma_fd < 0) _exit(98);

            /* Open 5 Mali contexts, import same dma_buf into each */
            int fds[5];
            uint64_t vas[5];
            for (int i = 0; i < 5; i++) {
                fds[i] = mali_open_and_handshake();
                if (fds[i] >= 0)
                    mali_mem_import(fds[i], dma_fd, &vas[i]);
            }

            /* Rapidly close contexts in different order */
            close(fds[2]); /* middle first */
            close(fds[0]); /* first */
            close(fds[4]); /* last */
            usleep(100);
            /* Try to use remaining contexts */
            for (int i = 0; i < 3; i++) {
                if (fds[1] >= 0) mali_mem_query(fds[1], vas[1]);
                if (fds[3] >= 0) mali_mem_query(fds[3], vas[3]);
            }
            close(fds[1]);
            close(fds[3]);
            close(dma_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
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

/* ===== TEST 8: MEM_ALLOC + mmap + close race (tight loop) ===== */

static void test_alloc_mmap_close_race(void) {
    printf("=== TEST 8: Alloc + mmap + immediate close race ===\n");

    int anomalies = 0;
    for (int trial = 0; trial < 200; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            for (int iter = 0; iter < 50; iter++) {
                int mali_fd = mali_open_and_handshake();
                if (mali_fd < 0) continue;

                uint64_t gpu_va;
                if (mali_mem_alloc(mali_fd, 1, &gpu_va) == 0) {
                    /* Try mmap + close in tight sequence */
                    void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, mali_fd, gpu_va);
                    close(mali_fd); /* close while mmap might still be setting up */
                    if (map != MAP_FAILED) {
                        volatile char *p = (volatile char *)map;
                        *p = 0x41; /* write to possibly-freed mapping */
                        munmap(map, 4096);
                    }
                } else {
                    close(mali_fd);
                }
            }
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 50 == 0)
            printf("  [%d/200] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 200 trials\n\n", anomalies);
}

/* ===== MAIN ===== */

int main(int argc, char **argv) {
    printf("=== Mali GPU Race Fuzzer ===\n");
    printf("Device: SM-T377A | Kernel 3.10.9 | Mali T720 r7p0\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    /* Validate Mali + ION work */
    {
        int mfd = mali_open_and_handshake();
        if (mfd < 0) { printf("FATAL: Mali handshake failed\n"); return 1; }
        int dfd = ion_alloc_fd();
        if (dfd < 0) { printf("FATAL: ION alloc failed\n"); close(mfd); return 1; }
        uint64_t gva;
        int r = mali_mem_import(mfd, dfd, &gva);
        printf("Validation: Mali=%d ION=%d import=%s gpu_va=0x%llx\n\n",
               mfd, dfd, r == 0 ? "OK" : "FAIL", (unsigned long long)gva);
        if (r < 0) { printf("FATAL: MEM_IMPORT failed\n"); return 1; }
        close(dfd); close(mfd);
    }

    int test = -1;
    if (argc > 1) test = atoi(argv[1]);

    if (test < 0 || test == 1) test_close_ioctl_race();
    if (test < 0 || test == 2) test_free_query_race();
    if (test < 0 || test == 3) test_mmap_free_race();
    if (test < 0 || test == 4) test_rapid_alloc_free();
    if (test < 0 || test == 5) test_double_free();
    if (test < 0 || test == 6) test_import_free_race();
    if (test < 0 || test == 7) test_multi_context_import();
    if (test < 0 || test == 8) test_alloc_mmap_close_race();

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -iE 'mali|kbase|gpu|oops|BUG|panic|fault' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
