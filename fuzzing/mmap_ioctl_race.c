/*
 * mmap_ioctl_race.c — Zero-day race condition fuzzer for kernel 3.10.9
 *
 * Tests UNTESTED race conditions between mmap/munmap and ioctl
 * operations on ION, binder, and ptmx device fds. These concurrent
 * paths are notorious for UAF/double-free bugs in 3.10 kernels.
 *
 * Test matrix:
 *   T1: ION mmap+munmap vs ION_IOC_ALLOC/FREE/SHARE/SYNC
 *   T2: Binder mmap+munmap vs BINDER_WRITE_READ
 *   T3: Concurrent close(fd) vs ioctl(fd) on ION/binder
 *   T4: fork() + shared fd: parent mmap, child ioctl simultaneously
 *   T5: Concurrent ION ALLOC+mmap+FREE (triple race)
 *
 * SAFETY: All dangerous ops run in forked children with alarm(5).
 *         Parent monitors for crashes via waitpid + dmesg.
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o mmap_ioctl_race mmap_ioctl_race.c -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

/* ION ioctls */
#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_SYNC    _IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;
};

struct ion_handle_data {
    int handle;
};

struct ion_fd_data {
    int handle;
    int fd;
};

/* Binder ioctls */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE        (128 * 1024)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

/* Shared state for race threads */
static volatile int go = 0;
static volatile int stop = 0;
static volatile int crashes = 0;
static int ion_fd = -1;
static int binder_fd = -1;

static void sighandler(int sig) {
    /* Catch SIGSEGV/SIGBUS in child — indicates kernel corruption */
    printf("  *** SIGNAL %d — potential kernel corruption! ***\n", sig);
    fflush(stdout);
    _exit(128 + sig);
}

/* ========== TEST 1: ION mmap vs ioctl race ========== */

static void *ion_mmap_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        /* Allocate ION buffer */
        struct ion_allocation_data alloc = {
            .len = 4096,
            .align = 4096,
            .heap_id_mask = 1,  /* system heap — SAFE */
            .flags = 0
        };
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) continue;

        /* Get shared fd */
        struct ion_fd_data share = { .handle = alloc.handle };
        if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) {
            struct ion_handle_data hd = { .handle = alloc.handle };
            ioctl(ion_fd, ION_IOC_FREE, &hd);
            continue;
        }

        /* mmap the shared fd */
        void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_SHARED, share.fd, 0);
        if (ptr != MAP_FAILED) {
            /* Touch the page — force page fault */
            *(volatile char *)ptr = 'X';
            /* Rapid unmap while other thread may be operating on it */
            munmap(ptr, 4096);
        }

        close(share.fd);
        struct ion_handle_data hd = { .handle = alloc.handle };
        ioctl(ion_fd, ION_IOC_FREE, &hd);
        ops++;
        if (ops % 500 == 0) usleep(100);
    }
    return (void*)(long)ops;
}

static void *ion_ioctl_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        /* Rapid alloc/free/share/sync — races with mmap thread */
        struct ion_allocation_data alloc = {
            .len = 4096,
            .align = 4096,
            .heap_id_mask = 1,  /* system heap — SAFE */
            .flags = 0
        };
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) continue;

        /* Share immediately */
        struct ion_fd_data share = { .handle = alloc.handle };
        ioctl(ion_fd, ION_IOC_SHARE, &share);

        /* Sync */
        struct ion_fd_data sync_d = { .fd = share.fd };
        ioctl(ion_fd, ION_IOC_SYNC, &sync_d);

        /* Free handle while share fd is still open */
        struct ion_handle_data hd = { .handle = alloc.handle };
        ioctl(ion_fd, ION_IOC_FREE, &hd);

        if (share.fd >= 0) close(share.fd);
        ops++;
        if (ops % 500 == 0) usleep(100);
    }
    return (void*)(long)ops;
}

static void test_ion_mmap_race(int iterations) {
    printf("\n=== TEST 1: ION mmap vs ioctl race (%d iterations) ===\n", iterations);
    fflush(stdout);

    ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("  open ion"); return; }

    go = 0; stop = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, ion_mmap_thread, NULL);
    pthread_create(&t2, NULL, ion_ioctl_thread, NULL);

    go = 1;
    /* Run for a fixed number of seconds based on iteration count */
    int runtime = iterations / 1000;
    if (runtime < 2) runtime = 2;
    if (runtime > 10) runtime = 10;
    sleep(runtime);
    stop = 1;

    void *r1, *r2;
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    printf("  mmap_thread: %ld ops, ioctl_thread: %ld ops\n",
           (long)r1, (long)r2);
    close(ion_fd);
}

/* ========== TEST 2: Binder mmap vs WRITE_READ race ========== */

static void *binder_mmap_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        void *ptr = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                         MAP_PRIVATE, binder_fd, 0);
        if (ptr != MAP_FAILED) {
            /* Read first byte — trigger page fault in binder vma */
            volatile char c = *(volatile char *)ptr;
            (void)c;
            munmap(ptr, BINDER_MMAP_SIZE);
        }
        ops++;
        usleep(10);  /* Small delay — binder mmap is expensive */
    }
    return (void*)(long)ops;
}

static void *binder_ioctl_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    char wbuf[256], rbuf[256];
    while (!stop) {
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_buffer = (unsigned long)wbuf;
        bwr.write_size = sizeof(wbuf);
        bwr.read_buffer = (unsigned long)rbuf;
        bwr.read_size = sizeof(rbuf);

        /* This will likely fail but exercises the binder code path */
        ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        ops++;
        usleep(10);
    }
    return (void*)(long)ops;
}

static void test_binder_mmap_race(int iterations) {
    printf("\n=== TEST 2: Binder mmap vs WRITE_READ race ===\n");
    fflush(stdout);

    binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("  open binder"); return; }

    uint32_t z = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &z);

    go = 0; stop = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, binder_mmap_thread, NULL);
    pthread_create(&t2, NULL, binder_ioctl_thread, NULL);

    go = 1;
    sleep(3);
    stop = 1;

    void *r1, *r2;
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    printf("  mmap_thread: %ld ops, ioctl_thread: %ld ops\n",
           (long)r1, (long)r2);
    close(binder_fd);
}

/* ========== TEST 3: Close+ioctl race (fd reuse) ========== */

struct close_race_ctx {
    const char *dev;
    int open_flags;
    unsigned long ioctl_cmd;
    void *ioctl_arg;
    int ioctl_arglen;
};

static volatile int race_fd = -1;
static volatile int fd_generation = 0;

static void *close_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        int fd = race_fd;
        if (fd >= 0) {
            close(fd);
            race_fd = -1;
            __sync_fetch_and_add(&fd_generation, 1);
        }
        usleep(1);
        ops++;
    }
    return (void*)(long)ops;
}

static void *reopen_thread(void *arg) {
    struct close_race_ctx *ctx = (struct close_race_ctx *)arg;
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        if (race_fd < 0) {
            int fd = open(ctx->dev, ctx->open_flags);
            if (fd >= 0) {
                race_fd = fd;
                /* For binder, do initial mmap */
                if (!strcmp(ctx->dev, "/dev/binder")) {
                    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                         MAP_PRIVATE, fd, 0);
                }
            }
        }
        usleep(1);
        ops++;
    }
    return (void*)(long)ops;
}

static void *ioctl_race_thread(void *arg) {
    struct close_race_ctx *ctx = (struct close_race_ctx *)arg;
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        int fd = race_fd;
        if (fd >= 0) {
            /* Issue ioctl on fd that might be closed simultaneously */
            if (ctx->ioctl_arg) {
                char buf[256];
                memcpy(buf, ctx->ioctl_arg, ctx->ioctl_arglen);
                ioctl(fd, ctx->ioctl_cmd, buf);
            } else {
                ioctl(fd, ctx->ioctl_cmd, NULL);
            }
        }
        ops++;
    }
    return (void*)(long)ops;
}

static void test_close_ioctl_race(const char *dev, unsigned long cmd,
                                   void *arg, int arglen, int flags) {
    printf("\n=== TEST 3: close+ioctl race on %s ===\n", dev);
    fflush(stdout);

    struct close_race_ctx ctx = {
        .dev = dev,
        .open_flags = flags,
        .ioctl_cmd = cmd,
        .ioctl_arg = arg,
        .ioctl_arglen = arglen
    };

    race_fd = open(dev, flags);
    if (race_fd < 0) { perror("  open"); return; }
    if (!strcmp(dev, "/dev/binder")) {
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, race_fd, 0);
    }

    go = 0; stop = 0;
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, close_thread, NULL);
    pthread_create(&t2, NULL, reopen_thread, (void*)&ctx);
    pthread_create(&t3, NULL, ioctl_race_thread, (void*)&ctx);

    go = 1;
    sleep(3);
    stop = 1;

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    if (race_fd >= 0) close(race_fd);
    printf("  Completed, checking dmesg...\n");
}

/* ========== TEST 4: ION ALLOC+mmap+FREE triple race ========== */

static volatile int triple_handle = -1;
static volatile int triple_sharefd = -1;

static void *triple_alloc_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        struct ion_allocation_data alloc = {
            .len = 4096, .align = 4096,
            .heap_id_mask = 1, .flags = 0
        };
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) == 0) {
            triple_handle = alloc.handle;
            struct ion_fd_data share = { .handle = alloc.handle };
            if (ioctl(ion_fd, ION_IOC_SHARE, &share) == 0) {
                triple_sharefd = share.fd;
            }
        }
        ops++;
        usleep(50);
    }
    return (void*)(long)ops;
}

static void *triple_mmap_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        int fd = triple_sharefd;
        if (fd >= 0) {
            void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_SHARED, fd, 0);
            if (ptr != MAP_FAILED) {
                *(volatile char *)ptr = 'Z';
                munmap(ptr, 4096);
            }
        }
        ops++;
    }
    return (void*)(long)ops;
}

static void *triple_free_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        int h = triple_handle;
        int fd = triple_sharefd;
        if (h >= 0) {
            struct ion_handle_data hd = { .handle = h };
            ioctl(ion_fd, ION_IOC_FREE, &hd);
            triple_handle = -1;
        }
        if (fd >= 0) {
            close(fd);
            triple_sharefd = -1;
        }
        ops++;
        usleep(50);
    }
    return (void*)(long)ops;
}

static void test_ion_triple_race(void) {
    printf("\n=== TEST 4: ION ALLOC+mmap+FREE triple race ===\n");
    fflush(stdout);

    ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("  open ion"); return; }

    go = 0; stop = 0;
    triple_handle = -1;
    triple_sharefd = -1;

    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, triple_alloc_thread, NULL);
    pthread_create(&t2, NULL, triple_mmap_thread, NULL);
    pthread_create(&t3, NULL, triple_free_thread, NULL);

    go = 1;
    sleep(5);
    stop = 1;

    void *r1, *r2, *r3;
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    pthread_join(t3, &r3);
    printf("  alloc: %ld, mmap: %ld, free: %ld\n",
           (long)r1, (long)r2, (long)r3);
    close(ion_fd);
}

/* ========== TEST 5: Fork + shared ION fd race ========== */

static void test_fork_ion_race(void) {
    printf("\n=== TEST 5: fork() + shared ION fd race ===\n");
    fflush(stdout);

    ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("  open ion"); return; }

    /* Pre-allocate a buffer */
    struct ion_allocation_data alloc = {
        .len = 4096, .align = 4096,
        .heap_id_mask = 1, .flags = 0
    };
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        perror("  alloc"); close(ion_fd); return;
    }

    struct ion_fd_data share = { .handle = alloc.handle };
    if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) {
        perror("  share"); close(ion_fd); return;
    }

    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED, share.fd, 0);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: rapidly free + re-alloc while parent mmaps */
        alarm(5);
        signal(SIGSEGV, sighandler);
        signal(SIGBUS, sighandler);

        for (int i = 0; i < 2000; i++) {
            struct ion_handle_data hd = { .handle = alloc.handle };
            ioctl(ion_fd, ION_IOC_FREE, &hd);

            struct ion_allocation_data a2 = {
                .len = 4096, .align = 4096,
                .heap_id_mask = 1, .flags = 0
            };
            ioctl(ion_fd, ION_IOC_ALLOC, &a2);

            /* Also try to mmap the shared fd */
            void *p2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_SHARED, share.fd, 0);
            if (p2 != MAP_FAILED) {
                *(volatile char *)p2 = 'C';
                munmap(p2, 4096);
            }
        }
        printf("  [child] 2000 iterations, no crash\n");
        _exit(0);
    }

    /* Parent: rapidly read/write the mmap'd region */
    for (int i = 0; i < 2000; i++) {
        if (ptr != MAP_FAILED) {
            *(volatile char *)ptr = 'P';
            volatile char c = *(volatile char *)ptr;
            (void)c;
        }

        /* Also do SYNC */
        struct ion_fd_data sync_d = { .fd = share.fd };
        ioctl(ion_fd, ION_IOC_SYNC, &sync_d);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("  *** CHILD CRASHED sig=%d — possible kernel corruption! ***\n",
               WTERMSIG(status));
    } else {
        printf("  Child exited normally (rc=%d)\n", WEXITSTATUS(status));
    }

    if (ptr != MAP_FAILED) munmap(ptr, 4096);
    close(share.fd);
    close(ion_fd);
}

/* ========== TEST 6: madvise + ION mmap race ========== */

static void test_madvise_ion_race(void) {
    printf("\n=== TEST 6: madvise(DONTNEED) + ION mmap race ===\n");
    fflush(stdout);

    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) { perror("  open ion"); return; }

    int ops = 0;
    for (int i = 0; i < 500; i++) {
        struct ion_allocation_data alloc = {
            .len = 4096 * 4, .align = 4096,
            .heap_id_mask = 1, .flags = 0
        };
        if (ioctl(fd, ION_IOC_ALLOC, &alloc) < 0) continue;

        struct ion_fd_data share = { .handle = alloc.handle };
        if (ioctl(fd, ION_IOC_SHARE, &share) < 0) {
            struct ion_handle_data hd = { .handle = alloc.handle };
            ioctl(fd, ION_IOC_FREE, &hd);
            continue;
        }

        void *ptr = mmap(NULL, 4096 * 4, PROT_READ | PROT_WRITE,
                         MAP_SHARED, share.fd, 0);
        if (ptr != MAP_FAILED) {
            /* Touch pages */
            memset(ptr, 'A', 4096 * 4);

            /* madvise DONTNEED on ION pages — may confuse ION's page tracking */
            int r = madvise(ptr, 4096 * 4, MADV_DONTNEED);

            /* Try to access after DONTNEED */
            volatile char c = *(volatile char *)ptr;
            (void)c;

            /* Also try MADV_REMOVE (punch hole) */
            madvise(ptr, 4096, 9 /* MADV_REMOVE */);

            munmap(ptr, 4096 * 4);
        }

        close(share.fd);
        struct ion_handle_data hd = { .handle = alloc.handle };
        ioctl(fd, ION_IOC_FREE, &hd);
        ops++;
    }
    printf("  %d iterations completed\n", ops);
    close(fd);
}

/* ========== MAIN ========== */

static void check_dmesg(void) {
    printf("\n--- dmesg (last 20, filtered) ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -iE "
           "'oops|bug|panic|fault|corrupt|poison|Backtrace|Unable|"
           "slab|list_del|use.after|double.free|null.ptr|bad.page' 2>/dev/null");
}

int main(int argc, char *argv[]) {
    printf("=== mmap/ioctl Race Condition Fuzzer ===\n");
    printf("Kernel zero-day research — SM-T377A (3.10.9)\n");
    printf("PID=%d UID=%d\n", getpid(), getuid());
    printf("WARNING: Tests run in forked children with alarm(5)\n\n");

    int iters = 2000;
    if (argc > 1) iters = atoi(argv[1]);

    signal(SIGSEGV, sighandler);
    signal(SIGBUS, sighandler);

    /* Pin to CPU 0 for SLUB locality */
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    /* Run each test in a forked child for crash safety */
    struct {
        const char *name;
        void (*func)(void);
    } tests[] = {
        { "ION mmap vs ioctl", NULL },  /* special: takes iters arg */
        { "Binder mmap vs WRITE_READ", NULL },
        { "ION triple race", test_ion_triple_race },
        { "Fork + ION race", test_fork_ion_race },
        { "madvise + ION race", test_madvise_ion_race },
    };

    /* Test 1: ION mmap race */
    {
        pid_t p = fork();
        if (p == 0) {
            alarm(15);
            test_ion_mmap_race(iters);
            _exit(0);
        }
        int status;
        waitpid(p, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** TEST 1 CRASHED sig=%d ***\n", WTERMSIG(status));
    }

    /* Test 2: Binder mmap race */
    {
        pid_t p = fork();
        if (p == 0) {
            alarm(10);
            test_binder_mmap_race(iters);
            _exit(0);
        }
        int status;
        waitpid(p, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** TEST 2 CRASHED sig=%d ***\n", WTERMSIG(status));
    }

    /* Test 3: Close+ioctl race on ION */
    {
        struct ion_allocation_data alloc = {
            .len = 4096, .align = 4096,
            .heap_id_mask = 1, .flags = 0
        };
        pid_t p = fork();
        if (p == 0) {
            alarm(10);
            test_close_ioctl_race("/dev/ion", ION_IOC_ALLOC,
                                   &alloc, sizeof(alloc), O_RDWR);
            _exit(0);
        }
        int status;
        waitpid(p, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** TEST 3a CRASHED sig=%d ***\n", WTERMSIG(status));
    }

    /* Test 3b: Close+ioctl race on binder */
    {
        pid_t p = fork();
        if (p == 0) {
            alarm(10);
            uint32_t z = 0;
            test_close_ioctl_race("/dev/binder", BINDER_SET_MAX_THREADS,
                                   &z, sizeof(z), O_RDWR);
            _exit(0);
        }
        int status;
        waitpid(p, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** TEST 3b CRASHED sig=%d ***\n", WTERMSIG(status));
    }

    /* Test 4: ION triple race */
    {
        pid_t p = fork();
        if (p == 0) {
            alarm(12);
            test_ion_triple_race();
            _exit(0);
        }
        int status;
        waitpid(p, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** TEST 4 CRASHED sig=%d ***\n", WTERMSIG(status));
    }

    /* Test 5: Fork + shared ION fd */
    {
        pid_t p = fork();
        if (p == 0) {
            alarm(10);
            test_fork_ion_race();
            _exit(0);
        }
        int status;
        waitpid(p, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** TEST 5 CRASHED sig=%d ***\n", WTERMSIG(status));
    }

    /* Test 6: madvise + ION */
    {
        pid_t p = fork();
        if (p == 0) {
            alarm(10);
            test_madvise_ion_race();
            _exit(0);
        }
        int status;
        waitpid(p, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** TEST 6 CRASHED sig=%d ***\n", WTERMSIG(status));
    }

    check_dmesg();

    printf("\n=== All tests complete ===\n");
    return 0;
}
