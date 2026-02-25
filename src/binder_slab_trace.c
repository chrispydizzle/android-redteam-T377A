/*
 * binder_slab_trace.c — Precise binder_thread slab identification
 *
 * Diffs ALL slab caches before/after binder operations to find
 * exactly which cache binder_thread lives in, and verify whether
 * BINDER_THREAD_EXIT actually frees it.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_WRITE_READ      _IOWR('b', 1, struct bwr)
#define BINDER_MMAP_SIZE       (128 * 1024)

struct bwr {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};

#define MAX_CACHES 256
struct cache_info {
    char name[64];
    int active;
    int total;
    int objsize;
};

static int read_slabinfo(struct cache_info *caches) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    fgets(line, sizeof(line), f); /* header */
    fgets(line, sizeof(line), f); /* header */
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < MAX_CACHES) {
        if (sscanf(line, "%63s %d %d %d",
                   caches[n].name, &caches[n].active,
                   &caches[n].total, &caches[n].objsize) == 4) {
            n++;
        }
    }
    fclose(f);
    return n;
}

static void diff_slabs(struct cache_info *before, int nb,
                       struct cache_info *after, int na,
                       const char *label) {
    printf("  [%s] Slab changes:\n", label);
    int found = 0;
    for (int i = 0; i < na; i++) {
        for (int j = 0; j < nb; j++) {
            if (strcmp(after[i].name, before[j].name) == 0) {
                int diff = after[i].active - before[j].active;
                if (diff != 0) {
                    printf("    %-24s: %+d (size=%d, %d→%d)\n",
                           after[i].name, diff, after[i].objsize,
                           before[j].active, after[i].active);
                    found++;
                }
                break;
            }
        }
    }
    if (!found) printf("    (no changes)\n");
}

int main(void) {
    printf("=== Binder Thread Slab Trace ===\n\n");

    struct cache_info s1[MAX_CACHES], s2[MAX_CACHES], s3[MAX_CACHES];
    struct cache_info s4[MAX_CACHES], s5[MAX_CACHES];
    int n1, n2, n3, n4, n5;

    /* --- Test 1: Identify binder_thread slab --- */
    printf("--- Test 1: Single binder open + epoll (creates binder_thread) ---\n");

    n1 = read_slabinfo(s1);

    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    void *m = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

    /* Just opening binder creates binder_proc */
    n2 = read_slabinfo(s2);
    diff_slabs(s1, n1, s2, n2, "after open+mmap");

    /* epoll_ctl ADD calls binder_poll → creates binder_thread */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    n3 = read_slabinfo(s3);
    diff_slabs(s2, n2, s3, n3, "after epoll ADD (creates thread)");

    /* BINDER_THREAD_EXIT → should free thread */
    int32_t dummy = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

    n4 = read_slabinfo(s4);
    diff_slabs(s3, n3, s4, n4, "after THREAD_EXIT");

    /* epoll_ctl DEL → accesses freed memory */
    epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);

    n5 = read_slabinfo(s5);
    diff_slabs(s4, n4, s5, n5, "after epoll DEL");

    close(bfd);
    close(epfd);

    /* --- Test 2: Multiple binder_threads via multiple ioctl calls --- */
    printf("\n--- Test 2: Bulk binder_thread creation ---\n");

    n1 = read_slabinfo(s1);

    /* Open 20 binders, each with epoll → 20 binder_procs + 20 binder_threads */
    int bfds[20], epfds[20];
    for (int i = 0; i < 20; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfds[i], 0);
        z = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &z);
        epfds[i] = epoll_create1(0);
        epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
    }

    n2 = read_slabinfo(s2);
    diff_slabs(s1, n1, s2, n2, "after 20 binder+epoll");

    /* THREAD_EXIT all 20 */
    for (int i = 0; i < 20; i++) {
        ioctl(bfds[i], BINDER_THREAD_EXIT, &dummy);
    }

    n3 = read_slabinfo(s3);
    diff_slabs(s2, n2, s3, n3, "after 20 THREAD_EXIT");

    /* DEL all 20 */
    for (int i = 0; i < 20; i++) {
        epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
    }

    n4 = read_slabinfo(s4);
    diff_slabs(s3, n3, s4, n4, "after 20 epoll DEL");

    /* Close all */
    for (int i = 0; i < 20; i++) {
        close(bfds[i]);
        close(epfds[i]);
    }

    n5 = read_slabinfo(s5);
    diff_slabs(s4, n4, s5, n5, "after close all");

    /* --- Test 3: Verify thread creation via ioctl --- */
    printf("\n--- Test 3: Does a raw ioctl create a thread? ---\n");

    n1 = read_slabinfo(s1);

    bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    m = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

    n2 = read_slabinfo(s2);
    diff_slabs(s1, n1, s2, n2, "after open (no epoll, no ioctl thread)");

    /* A simple BINDER_WRITE_READ with 0 sizes will create a thread via binder_get_thread */
    struct bwr bwr = {0};
    ioctl(bfd, BINDER_WRITE_READ, &bwr);

    n3 = read_slabinfo(s3);
    diff_slabs(s2, n2, s3, n3, "after WRITE_READ (creates thread)");

    /* THREAD_EXIT */
    ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

    n4 = read_slabinfo(s4);
    diff_slabs(s3, n3, s4, n4, "after THREAD_EXIT");

    close(bfd);

    /* --- Test 4: Check if THREAD_EXIT actually returns success --- */
    printf("\n--- Test 4: THREAD_EXIT return value ---\n");
    bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    m = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

    /* Create thread via epoll */
    epfd = epoll_create1(0);
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    int ret = ioctl(bfd, BINDER_THREAD_EXIT, &dummy);
    printf("  THREAD_EXIT ioctl returned: %d (errno=%d)\n", ret, errno);

    /* Try second THREAD_EXIT (no thread should exist) */
    ret = ioctl(bfd, BINDER_THREAD_EXIT, &dummy);
    printf("  Second THREAD_EXIT: %d (errno=%d)\n", ret, errno);

    /* Try third (creates new thread, then frees it) */
    ret = ioctl(bfd, BINDER_THREAD_EXIT, &dummy);
    printf("  Third THREAD_EXIT: %d (errno=%d)\n", ret, errno);

    close(bfd);
    close(epfd);

    printf("\n=== Done ===\n");
    return 0;
}
