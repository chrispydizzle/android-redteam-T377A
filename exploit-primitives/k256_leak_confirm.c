/*
 * k256_leak_confirm.c — Precision kmalloc-256 leak confirmation
 *
 * Tests whether the BPF filter slab leak is:
 *   A) Monotonic (true leak — grows without bound → exploitable for OOM/spray)
 *   B) Bounded (SLUB per-CPU caching noise → not exploitable)
 *
 * Also tests additional untested zero-day surfaces:
 *   - recvmsg MSG_ERRQUEUE + concurrent close (historic UAF source)
 *   - timer_create/delete race (POSIX timer cleanup)
 *   - concurrent mprotect + read/write (page table race)
 *   - prctl PR_SET_NAME from multiple threads (task_struct write race)
 *   - signalfd + signal delivery race
 *   - concurrent dup2 + read/write on same fd
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o k256_leak_confirm k256_leak_confirm.c -lpthread
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
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

static struct sock_fprog make_bpf_k256(void) {
    static struct sock_filter insns[22];
    for (int i = 0; i < 21; i++)
        insns[i] = (struct sock_filter){ BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 };
    insns[21] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF };
    struct sock_fprog prog = { .len = 22, .filter = insns };
    return prog;
}

/* ========== TEST 1: Precision monotonic leak test ========== */

static void test_monotonic_leak(void) {
    printf("=== TEST 1: Precision monotonic k256 leak test ===\n");
    printf("  Phase A: 50K sequential attach/detach with periodic measurement\n");

    struct sock_fprog prog = make_bpf_k256();
    int samples[21];
    int k256_base = get_slab("kmalloc-256");
    int total = 50000;

    for (int i = 0; i < total; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;
        setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
        setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        close(sv[0]); close(sv[1]);

        if ((i + 1) % 2500 == 0) {
            usleep(50000); /* Let RCU grace periods expire */
            int k = get_slab("kmalloc-256") - k256_base;
            int idx = (i + 1) / 2500 - 1;
            if (idx < 21) samples[idx] = k;
            printf("  [%5d] k256 delta: %+d\n", i + 1, k);
            fflush(stdout);
        }
    }

    /* Analyze: is the trend monotonically increasing? */
    int increasing = 0, decreasing = 0;
    for (int i = 1; i < 20; i++) {
        if (samples[i] > samples[i-1]) increasing++;
        if (samples[i] < samples[i-1]) decreasing++;
    }

    printf("  Trend: %d increasing, %d decreasing intervals\n", increasing, decreasing);
    if (increasing > 14) {
        printf("  *** MONOTONIC LEAK CONFIRMED! ***\n");
    } else {
        printf("  Likely SLUB caching noise (non-monotonic)\n");
    }

    /* Phase B: flush CPU caches with allocation burst, then re-measure */
    printf("  Phase B: Flush SLUB caches and re-measure\n");
    usleep(500000); /* 500ms grace period */
    int k256_after_grace = get_slab("kmalloc-256");
    printf("  After 500ms grace: k256 delta=%+d\n", k256_after_grace - k256_base);

    /* Allocate many k256 objects to flush per-CPU cache */
    int flush_socks[200];
    int flush_count = 0;
    for (int i = 0; i < 100; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            flush_socks[flush_count++] = sv[0];
            flush_socks[flush_count++] = sv[1];
        }
    }
    for (int i = 0; i < flush_count; i++) close(flush_socks[i]);
    usleep(200000);

    int k256_flushed = get_slab("kmalloc-256");
    printf("  After cache flush: k256 delta=%+d\n", k256_flushed - k256_base);
    printf("  TRUE LEAK estimate: ~%d objects from %d cycles\n\n",
           k256_flushed - k256_base, total);
}

/* ========== TEST 2: Dual attach leak amplification ========== */

struct dual_args {
    int fd;
    volatile int go;
};

static void *dual_attach_worker(void *arg) {
    struct dual_args *a = (struct dual_args *)arg;
    struct sock_fprog prog = make_bpf_k256();
    while (!a->go) sched_yield();
    setsockopt(a->fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    return NULL;
}

static void test_dual_attach_amplify(void) {
    printf("=== TEST 2: Dual attach leak amplification (5000 cycles) ===\n");

    int k256_start = get_slab("kmalloc-256");
    int iters = 5000;

    for (int i = 0; i < iters; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;

        struct dual_args a1 = { .fd = sv[0], .go = 0 };
        struct dual_args a2 = { .fd = sv[0], .go = 0 };
        pthread_t t1, t2;
        pthread_create(&t1, NULL, dual_attach_worker, &a1);
        pthread_create(&t2, NULL, dual_attach_worker, &a2);
        a1.go = 1; a2.go = 1;
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        setsockopt(sv[0], SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        close(sv[0]); close(sv[1]);

        if ((i + 1) % 1000 == 0) {
            usleep(50000);
            int k = get_slab("kmalloc-256") - k256_start;
            printf("  [%d/%d] k256 delta: %+d (%.2f per cycle)\n",
                   i + 1, iters, k, (float)k / (i + 1));
            fflush(stdout);
        }
    }

    usleep(500000);
    int k256_end = get_slab("kmalloc-256");
    printf("  Final k256 delta: %+d after %d dual-attach cycles\n",
           k256_end - k256_start, iters);
    if (k256_end - k256_start > 100) {
        printf("  *** SIGNIFICANT k256 ACCUMULATION! ***\n");
    }
    printf("\n");
}

/* ========== TEST 3: recvmsg MSG_ERRQUEUE + close race ========== */

static void test_errqueue_close_race(void) {
    printf("=== TEST 3: recvmsg MSG_ERRQUEUE + close() race ===\n");

    int anomalies = 0;
    int iters = 2000;

    for (int i = 0; i < iters; i++) {
        int sk = socket(AF_INET, SOCK_DGRAM, 0);
        if (sk < 0) continue;

        /* Enable IP_RECVERR to get error queue */
        int val = 1;
        setsockopt(sk, SOL_IP, 11 /* IP_RECVERR */, &val, sizeof(val));

        /* Send to unreachable addr to generate ICMP error */
        struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(1) };
        addr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
        sendto(sk, "x", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));

        pid_t pid = fork();
        if (pid == 0) {
            /* Child: try to read error queue */
            char buf[256];
            char cbuf[256];
            struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
            struct msghdr msg = { 0 };
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);

            for (int j = 0; j < 100; j++) {
                recvmsg(sk, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
            }
            _exit(0);
        }

        /* Parent: close while child reads error queue */
        usleep(1);
        close(sk);
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            printf("  [%d] CHILD CRASHED sig=%d\n", i, WTERMSIG(status));
            anomalies++;
        }

        if ((i + 1) % 500 == 0) {
            printf("  [%d/%d] anomalies=%d\n", i + 1, iters, anomalies);
            fflush(stdout);
        }
    }

    printf("  Result: %d anomalies in %d iterations\n\n", anomalies, iters);
}

/* ========== TEST 4: concurrent mprotect + page fault ========== */

static volatile int mprotect_stop = 0;

static void *mprotect_flipper(void *arg) {
    void *addr = arg;
    while (!mprotect_stop) {
        mprotect(addr, 4096, PROT_READ | PROT_WRITE);
        mprotect(addr, 4096, PROT_NONE);
    }
    return NULL;
}

static void test_mprotect_fault_race(void) {
    printf("=== TEST 4: Concurrent mprotect + page fault race ===\n");

    int faults = 0;
    int crashes = 0;
    int iters = 20;

    for (int i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) _exit(1);

            /* Write initial data */
            memset(addr, 'M', 4096);

            mprotect_stop = 0;
            pthread_t t;
            pthread_create(&t, NULL, mprotect_flipper, addr);

            /* Read/write while mprotect flips permissions */
            int local_faults = 0;
            for (int j = 0; j < 100000; j++) {
                volatile char *p = (volatile char *)addr;
                /* This may SIGSEGV if mprotect set PROT_NONE */
                /* We fork into child so SIGSEGV just kills child */
                char c = p[j % 4096];
                p[(j + 1) % 4096] = c + 1;
            }

            mprotect_stop = 1;
            pthread_join(t, NULL);
            munmap(addr, 4096);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            if (WTERMSIG(status) == 11) faults++;  /* SIGSEGV expected */
            else {
                printf("  [%d] UNEXPECTED signal %d\n", i, WTERMSIG(status));
                crashes++;
            }
        }
    }

    printf("  Result: %d SIGSEGV (expected), %d unexpected crashes in %d iterations\n\n",
           faults, crashes, iters);
}

/* ========== TEST 5: prctl PR_SET_NAME race ========== */

static volatile int prctl_stop = 0;

static void *prctl_writer(void *arg) {
    int id = (int)(long)arg;
    char name[16];
    while (!prctl_stop) {
        snprintf(name, sizeof(name), "thread_%d_%d", id, rand() % 1000);
        prctl(PR_SET_NAME, name, 0, 0, 0);
    }
    return NULL;
}

static void test_prctl_name_race(void) {
    printf("=== TEST 5: Concurrent PR_SET_NAME from 4 threads ===\n");

    int anomalies = 0;
    prctl_stop = 0;

    pthread_t threads[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, prctl_writer, (void *)(long)i);

    /* Run for 3 seconds */
    sleep(3);
    prctl_stop = 1;

    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    /* Verify task name is readable */
    char name[16] = {0};
    prctl(PR_GET_NAME, name, 0, 0, 0);
    printf("  Final name: '%s' (should be valid ASCII)\n", name);

    /* Check for NUL or garbage */
    for (int i = 0; i < 15 && name[i]; i++) {
        if (name[i] < 0x20 || name[i] > 0x7e) {
            printf("  *** CORRUPTION at byte %d: 0x%02x ***\n", i, (unsigned char)name[i]);
            anomalies++;
        }
    }

    printf("  Result: %d anomalies\n\n", anomalies);
}

/* ========== TEST 6: signalfd + concurrent signal race ========== */

static void test_signalfd_race(void) {
    printf("=== TEST 6: signalfd read + concurrent signal delivery ===\n");

    int anomalies = 0;
    int iters = 500;

    for (int i = 0; i < iters; i++) {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGUSR1);
        sigprocmask(SIG_BLOCK, &mask, NULL);

        int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
        if (sfd < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {
            /* Child: read signalfd while parent sends signals */
            struct signalfd_siginfo si;
            for (int j = 0; j < 50; j++) {
                read(sfd, &si, sizeof(si));
                usleep(1);
            }
            close(sfd);
            _exit(0);
        }

        /* Parent: send signals rapidly */
        for (int j = 0; j < 50; j++) {
            kill(pid, SIGUSR1);
        }

        /* Close signalfd while child might be reading */
        close(sfd);

        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status) && WTERMSIG(status) != SIGUSR1) {
            printf("  [%d] CHILD CRASHED sig=%d\n", i, WTERMSIG(status));
            anomalies++;
        }
    }

    /* Unblock */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    printf("  Result: %d anomalies in %d iterations\n\n", anomalies, iters);
}

/* ========== TEST 7: dup2 + read race (fd table race) ========== */

struct dup2_race_args {
    int fd;
    int newfd;
    volatile int stop;
    int dup_count;
};

static void *dup2_thread(void *arg) {
    struct dup2_race_args *a = (struct dup2_race_args *)arg;
    while (!a->stop) {
        dup2(a->fd, a->newfd);
        a->dup_count++;
        usleep(1);
    }
    return NULL;
}

static void test_dup2_read_race(void) {
    printf("=== TEST 7: dup2 + read/write race on same fd ===\n");

    int anomalies = 0;

    int p1[2], p2[2];
    pipe(p1); pipe(p2);

    /* Write known data to both pipes */
    char d1[32], d2[32];
    memset(d1, 'D', sizeof(d1));
    memset(d2, 'E', sizeof(d2));
    write(p1[1], d1, sizeof(d1));
    write(p2[1], d2, sizeof(d2));

    struct dup2_race_args args = {
        .fd = p2[0],    /* dup p2's read end */
        .newfd = p1[0], /* onto p1's read end */
        .stop = 0, .dup_count = 0
    };

    pthread_t t;
    pthread_create(&t, NULL, dup2_thread, &args);

    /* Read from p1[0] while dup2 switches what fd p1[0] points to */
    int read_count = 0, mixed = 0;
    for (int i = 0; i < 100000; i++) {
        char buf[1];
        int n = read(p1[0], buf, 1);
        if (n == 1) {
            read_count++;
            if (buf[0] != 'D' && buf[0] != 'E') {
                printf("  *** UNEXPECTED DATA: 0x%02x at read %d ***\n",
                       (unsigned char)buf[0], i);
                anomalies++;
                break;
            }
        }
        /* Refill pipes periodically */
        if (i % 100 == 0) {
            write(p1[1], d1, 1);
            write(p2[1], d2, 1);
        }
    }

    args.stop = 1;
    pthread_join(t, NULL);

    printf("  %d reads, %d dup2 calls, %d anomalies\n",
           read_count, args.dup_count, anomalies);

    close(p1[0]); close(p1[1]);
    close(p2[0]); close(p2[1]);
    printf("\n");
}

/* ========== TEST 8: POSIX timer create/delete race ========== */

static void test_timer_race(void) {
    printf("=== TEST 8: POSIX timer create/delete race ===\n");

    int anomalies = 0;
    int iters = 2000;

    for (int i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            timer_t tid;
            struct sigevent sev = { 0 };
            sev.sigev_notify = SIGEV_SIGNAL;
            sev.sigev_signo = SIGUSR1;

            /* Create and arm timer, then exit immediately (race cleanup) */
            if (timer_create(CLOCK_REALTIME, &sev, &tid) == 0) {
                struct itimerspec its = {
                    .it_value = { .tv_sec = 0, .tv_nsec = 1000 },
                    .it_interval = { .tv_sec = 0, .tv_nsec = 1000 }
                };
                timer_settime(tid, 0, &its, NULL);
                /* Exit WITHOUT timer_delete — force kernel cleanup */
            }
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            printf("  [%d] CRASHED sig=%d\n", i, WTERMSIG(status));
            anomalies++;
        }
    }

    printf("  Result: %d anomalies in %d iterations\n\n", anomalies, iters);
}

int main(void) {
    printf("=== Zero-Day Surface Fuzzer + k256 Leak Confirmation ===\n");
    printf("SM-T377A kernel 3.10.9\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(600);  /* 10 min safety */
    srand(time(NULL));

    test_monotonic_leak();
    test_dual_attach_amplify();
    test_errqueue_close_race();
    test_mprotect_fault_race();
    test_prctl_name_race();
    test_signalfd_race();
    test_dup2_read_race();
    test_timer_race();

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -40 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|WARNING|"
           "slab|list_del|use.after|double|sk_filter|timer|signal' "
           "2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
