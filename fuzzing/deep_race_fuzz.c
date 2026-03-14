/*
 * deep_race_fuzz.c — Focused zero-day fuzzer for remaining untested surfaces
 *
 * Targets:
 *   T1: tee() deadlock reproduction — pipe locking bug (hung in prev test)
 *   T2: sendfile from /proc/* and device fds to pipes
 *   T3: writev with 32 iovecs (FASTIOV boundary) + misaligned sizes
 *   T4: dup2 racing with ioctl on same fd number
 *   T5: fcntl(F_SETFL) racing with read/write
 *   T6: ION_IOC_CUSTOM (Samsung-specific undocumented ioctl)
 *   T7: Concurrent signal delivery during ION/binder operations
 *   T8: recvmsg MSG_ERRQUEUE + concurrent socket ops
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o deep_race_fuzz deep_race_fuzz.c -lpthread
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
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

/* ION ioctls */
#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_CUSTOM  _IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

struct ion_allocation_data {
    size_t len; size_t align;
    unsigned int heap_id_mask; unsigned int flags;
    int handle;
};
struct ion_handle_data { int handle; };
struct ion_fd_data { int handle; int fd; };
struct ion_custom_data {
    unsigned int cmd;
    unsigned long arg;
};

/* Binder */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
struct binder_write_read {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};

#ifndef __NR_tee
#define __NR_tee 342
#endif

static volatile int go = 0, stop = 0;

static void sighandler(int sig) {
    if (sig == SIGALRM) {
        printf("  [ALARM] timeout — possible deadlock!\n");
        fflush(stdout);
        _exit(14);
    }
    printf("  *** SIGNAL %d ***\n", sig);
    fflush(stdout);
    _exit(128 + sig);
}

/* ========== TEST 1: tee() deadlock reproduction ========== */

static void test_tee_deadlock(void) {
    printf("=== TEST 1: tee() deadlock reproduction ===\n");
    fflush(stdout);

    /* The previous test showed tee hung when combined with concurrent
     * writer + reader. Let's narrow down: does tee deadlock when the
     * source pipe is full and dest pipe is also full? */

    int p1[2], p2[2];
    pipe(p1); pipe(p2);

    /* Set small pipe sizes if possible */
    fcntl(p1[0], 1031 /* F_SETPIPE_SZ */, 4096);
    fcntl(p2[0], 1031 /* F_SETPIPE_SZ */, 4096);

    /* Fill p1 write end */
    fcntl(p1[1], F_SETFL, O_NONBLOCK);
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    while (write(p1[1], buf, sizeof(buf)) > 0);

    /* Fill p2 write end */
    fcntl(p2[1], F_SETFL, O_NONBLOCK);
    while (write(p2[1], buf, sizeof(buf)) > 0);

    printf("  Both pipes full. Testing tee variants...\n");

    /* Test A: tee from full pipe to full pipe (should fail quickly) */
    {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            fcntl(p1[0], F_SETFL, O_NONBLOCK);
            fcntl(p2[1], F_SETFL, O_NONBLOCK);
            long r = syscall(__NR_tee, p1[0], p2[1], 4096, 0x01 /* SPLICE_F_NONBLOCK */);
            printf("  [A] tee full→full: r=%ld errno=%d\n", r, errno);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == 14)
            printf("  [A] DEADLOCKED!\n");
    }

    /* Test B: tee with blocking and concurrent drain */
    {
        /* Drain p2 in background */
        pid_t drain_pid = fork();
        if (drain_pid == 0) {
            alarm(5);
            char d[4096];
            fcntl(p2[0], F_SETFL, 0);  /* blocking */
            while (read(p2[0], d, sizeof(d)) > 0);
            _exit(0);
        }

        /* tee from p1 to p2 — p2 is being drained */
        pid_t tee_pid = fork();
        if (tee_pid == 0) {
            alarm(3);
            fcntl(p1[0], F_SETFL, 0);
            fcntl(p2[1], F_SETFL, 0);
            for (int i = 0; i < 100; i++) {
                long r = syscall(__NR_tee, p1[0], p2[1], 4096, 0);
                if (r <= 0) break;
            }
            printf("  [B] tee + drain: completed\n");
            _exit(0);
        }

        int status;
        waitpid(tee_pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == 14)
            printf("  [B] DEADLOCKED!\n");

        kill(drain_pid, SIGKILL);
        waitpid(drain_pid, &status, 0);
    }

    /* Test C: Concurrent tee in both directions (circular) */
    {
        printf("  [C] Testing circular tee...\n");
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            /* Drain both pipes first */
            char d[4096];
            fcntl(p1[0], F_SETFL, O_NONBLOCK);
            while (read(p1[0], d, sizeof(d)) > 0);
            fcntl(p2[0], F_SETFL, O_NONBLOCK);
            while (read(p2[0], d, sizeof(d)) > 0);

            /* Fill p1 with small data */
            fcntl(p1[1], F_SETFL, O_NONBLOCK);
            write(p1[1], "hello", 5);

            /* Now tee p1→p2 and p2→p1 in threads */
            /* For simplicity, do sequentially but rapidly */
            for (int i = 0; i < 200; i++) {
                fcntl(p1[0], F_SETFL, O_NONBLOCK);
                fcntl(p2[1], F_SETFL, O_NONBLOCK);
                syscall(__NR_tee, p1[0], p2[1], 4096, 0x01);

                fcntl(p2[0], F_SETFL, O_NONBLOCK);
                fcntl(p1[1], F_SETFL, O_NONBLOCK);
                syscall(__NR_tee, p2[0], p1[1], 4096, 0x01);
            }
            printf("  [C] Circular tee: 200 iterations OK\n");
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == 14)
            printf("  [C] DEADLOCKED!\n");
    }

    close(p1[0]); close(p1[1]);
    close(p2[0]); close(p2[1]);
}

/* ========== TEST 2: sendfile from /proc/* to pipes ========== */

static void test_sendfile_proc(void) {
    printf("\n=== TEST 2: sendfile from /proc and devices ===\n");
    fflush(stdout);

    const char *srcs[] = {
        "/proc/self/stat", "/proc/self/maps", "/proc/self/status",
        "/proc/slabinfo", "/proc/version", "/proc/cpuinfo",
        "/proc/self/cmdline", "/proc/self/auxv",
        "/proc/vmstat", "/proc/interrupts",
        NULL
    };

    int pfd[2];
    pipe(pfd);

    for (int i = 0; srcs[i]; i++) {
        int src = open(srcs[i], O_RDONLY);
        if (src < 0) {
            printf("  %s: cannot open (%s)\n", srcs[i], strerror(errno));
            continue;
        }

        /* Drain pipe first */
        fcntl(pfd[0], F_SETFL, O_NONBLOCK);
        char drain[8192];
        while (read(pfd[0], drain, sizeof(drain)) > 0);
        fcntl(pfd[0], F_SETFL, 0);

        off_t off = 0;
        ssize_t r = sendfile(pfd[1], src, &off, 4096);
        printf("  sendfile %s → pipe: %zd (errno=%d)\n", srcs[i], r, r < 0 ? errno : 0);

        /* Also try with NULL offset (uses file position) */
        lseek(src, 0, SEEK_SET);
        r = sendfile(pfd[1], src, NULL, 4096);
        printf("  sendfile %s (NULL off): %zd\n", srcs[i], r);

        close(src);
    }

    /* sendfile from ION shared fd */
    {
        int ion = open("/dev/ion", O_RDWR);
        if (ion >= 0) {
            struct ion_allocation_data alloc = {
                .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0
            };
            if (ioctl(ion, ION_IOC_ALLOC, &alloc) == 0) {
                struct ion_fd_data share = { .handle = alloc.handle };
                if (ioctl(ion, ION_IOC_SHARE, &share) == 0) {
                    off_t off = 0;
                    ssize_t r = sendfile(pfd[1], share.fd, &off, 4096);
                    printf("  sendfile ION_SHARE_fd → pipe: %zd (errno=%d)\n",
                           r, r < 0 ? errno : 0);
                    close(share.fd);
                }
                struct ion_handle_data hd = { .handle = alloc.handle };
                ioctl(ion, ION_IOC_FREE, &hd);
            }
            close(ion);
        }
    }

    close(pfd[0]); close(pfd[1]);
}

/* ========== TEST 3: writev FASTIOV boundary ========== */

static void test_writev_fastiov(void) {
    printf("\n=== TEST 3: writev at FASTIOV=32 boundary ===\n");
    fflush(stdout);

    int pfd[2];
    pipe(pfd);

    char data[4096];
    memset(data, 'W', sizeof(data));

    /* Test with exactly 32 iovecs (should use stack) */
    struct iovec iov32[32];
    for (int i = 0; i < 32; i++) {
        iov32[i].iov_base = data + i * 128;
        iov32[i].iov_len = 128;
    }
    ssize_t r = writev(pfd[1], iov32, 32);
    printf("  writev(32 iovecs, 128 each): %zd\n", r);

    /* Drain pipe */
    char drain[65536];
    fcntl(pfd[0], F_SETFL, O_NONBLOCK);
    while (read(pfd[0], drain, sizeof(drain)) > 0);

    /* Test with 33 iovecs (should trigger kmalloc) */
    struct iovec iov33[33];
    for (int i = 0; i < 33; i++) {
        iov33[i].iov_base = data + (i % 32) * 128;
        iov33[i].iov_len = 128;
    }
    r = writev(pfd[1], iov33, 33);
    printf("  writev(33 iovecs, 128 each): %zd (errno=%d)\n", r, r < 0 ? errno : 0);

    /* Drain */
    while (read(pfd[0], drain, sizeof(drain)) > 0);

    /* Test with EXACTLY 32 iovecs with boundary sizes */
    size_t sizes[] = { 0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 4096, 0 };
    for (int s = 0; sizes[s] || s == 0; s++) {
        for (int i = 0; i < 32; i++) {
            iov32[i].iov_base = data;
            iov32[i].iov_len = 128;
        }
        /* Set last iov to boundary size */
        iov32[31].iov_len = sizes[s];
        r = writev(pfd[1], iov32, 32);
        printf("  writev(32, last_len=0x%lx): %zd (errno=%d)\n",
               (unsigned long)sizes[s], r, r < 0 ? errno : 0);

        while (read(pfd[0], drain, sizeof(drain)) > 0);
    }

    /* Test total size overflow: 32 iovecs × 0x10000000 each */
    for (int i = 0; i < 32; i++) {
        iov32[i].iov_base = data;
        iov32[i].iov_len = 0x10000000;
    }
    r = writev(pfd[1], iov32, 32);
    printf("  writev(32, each=256MB total overflow): %zd (errno=%d)\n",
           r, r < 0 ? errno : 0);

    close(pfd[0]); close(pfd[1]);
}

/* ========== TEST 4: dup2 racing with ioctl ========== */

static volatile int dup_target_fd = -1;
static volatile int dup_running = 1;

static void *dup2_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    int devnull = open("/dev/null", O_RDWR);
    while (!stop) {
        /* dup2 overwrites dup_target_fd with /dev/null */
        int fd = dup_target_fd;
        if (fd >= 0) {
            dup2(devnull, fd);
            /* Immediately reopen the original device on same fd */
            int newfd = open("/dev/ion", O_RDWR);
            if (newfd >= 0 && newfd != fd) {
                dup2(newfd, fd);
                close(newfd);
            }
        }
        ops++;
    }
    close(devnull);
    return (void*)(long)ops;
}

static void *ioctl_on_dup_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        int fd = dup_target_fd;
        if (fd >= 0) {
            struct ion_allocation_data alloc = {
                .len = 4096, .align = 4096,
                .heap_id_mask = 1, .flags = 0
            };
            int r = ioctl(fd, ION_IOC_ALLOC, &alloc);
            if (r == 0) {
                struct ion_handle_data hd = { .handle = alloc.handle };
                ioctl(fd, ION_IOC_FREE, &hd);
            }
        }
        ops++;
    }
    return (void*)(long)ops;
}

static void test_dup2_race(void) {
    printf("\n=== TEST 4: dup2 vs ioctl race ===\n");
    fflush(stdout);

    dup_target_fd = open("/dev/ion", O_RDWR);
    if (dup_target_fd < 0) { perror("  open ion"); return; }

    go = 0; stop = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, dup2_thread, NULL);
    pthread_create(&t2, NULL, ioctl_on_dup_thread, NULL);

    go = 1;
    sleep(3);
    stop = 1;

    void *r1, *r2;
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    printf("  dup2: %ld ops, ioctl: %ld ops\n", (long)r1, (long)r2);

    if (dup_target_fd >= 0) close(dup_target_fd);
}

/* ========== TEST 5: ION_IOC_CUSTOM (Samsung vendor) ========== */

static void test_ion_custom(void) {
    printf("\n=== TEST 5: ION_IOC_CUSTOM (Samsung vendor ioctl) ===\n");
    fflush(stdout);

    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) { perror("  open ion"); return; }

    int ok = 0, fail = 0;

    /* Scan custom command values */
    for (unsigned int cmd = 0; cmd < 32; cmd++) {
        char argbuf[256];
        memset(argbuf, 0, sizeof(argbuf));

        struct ion_custom_data custom = {
            .cmd = cmd,
            .arg = (unsigned long)argbuf
        };

        int r = ioctl(fd, ION_IOC_CUSTOM, &custom);
        if (r == 0) {
            printf("  cmd=%u: SUCCESS!\n", cmd);
            ok++;
        } else {
            if (errno != ENOTTY && errno != EINVAL) {
                printf("  cmd=%u: errno=%d (%s)\n", cmd, errno, strerror(errno));
            }
            fail++;
        }
    }

    /* Also try with large command values */
    unsigned int large_cmds[] = { 0x100, 0x1000, 0xFFFFFFFF, 0x80000000, 0 };
    for (int i = 0; large_cmds[i]; i++) {
        char argbuf[256];
        memset(argbuf, 0, sizeof(argbuf));
        struct ion_custom_data custom = {
            .cmd = large_cmds[i],
            .arg = (unsigned long)argbuf
        };
        int r = ioctl(fd, ION_IOC_CUSTOM, &custom);
        if (r == 0) {
            printf("  cmd=0x%x: SUCCESS!\n", large_cmds[i]);
        }
    }

    /* Try with arg=NULL */
    for (unsigned int cmd = 0; cmd < 8; cmd++) {
        struct ion_custom_data custom = { .cmd = cmd, .arg = 0 };
        int r = ioctl(fd, ION_IOC_CUSTOM, &custom);
        if (r == 0) {
            printf("  cmd=%u arg=NULL: SUCCESS!\n", cmd);
        }
    }

    printf("  Scanned 32+4+8 commands: ok=%d fail=%d\n", ok, fail);
    close(fd);
}

/* ========== TEST 6: Signal during ION operation ========== */

static volatile int signal_received = 0;
static void sigusr_handler(int sig) { signal_received++; }

static void test_signal_during_ioctl(void) {
    printf("\n=== TEST 6: Signal interruption during ION ops ===\n");
    fflush(stdout);

    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) { perror("  open ion"); return; }

    signal(SIGUSR1, sigusr_handler);
    signal_received = 0;

    pid_t child = fork();
    if (child == 0) {
        /* Child: bombard parent with signals */
        alarm(5);
        pid_t parent = getppid();
        for (int i = 0; i < 10000; i++) {
            kill(parent, SIGUSR1);
            usleep(100);
        }
        _exit(0);
    }

    /* Parent: do ION ops while receiving signals */
    int ops = 0, alloc_ok = 0, intr = 0;
    for (int i = 0; i < 5000; i++) {
        struct ion_allocation_data alloc = {
            .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0
        };
        int r = ioctl(fd, ION_IOC_ALLOC, &alloc);
        if (r == 0) {
            alloc_ok++;
            struct ion_fd_data share = { .handle = alloc.handle };
            ioctl(fd, ION_IOC_SHARE, &share);
            if (share.fd >= 0) close(share.fd);
            struct ion_handle_data hd = { .handle = alloc.handle };
            ioctl(fd, ION_IOC_FREE, &hd);
        } else if (errno == EINTR) {
            intr++;
        }
        ops++;
    }

    int status;
    kill(child, SIGKILL);
    waitpid(child, &status, 0);

    printf("  %d ops, %d alloc_ok, %d EINTR, %d signals received\n",
           ops, alloc_ok, intr, signal_received);
    close(fd);
}

/* ========== TEST 7: fcntl F_SETFL race with I/O ========== */

static void test_fcntl_race(void) {
    printf("\n=== TEST 7: fcntl(F_SETFL) race with I/O ===\n");
    fflush(stdout);

    int pfd[2];
    pipe(pfd);

    char data[4096];
    memset(data, 'F', sizeof(data));

    /* Fill pipe */
    fcntl(pfd[1], F_SETFL, O_NONBLOCK);
    while (write(pfd[1], data, sizeof(data)) > 0);

    pid_t pid = fork();
    if (pid == 0) {
        alarm(5);
        /* Child: toggle blocking/nonblocking on read end */
        for (int i = 0; i < 10000; i++) {
            fcntl(pfd[0], F_SETFL, (i % 2) ? O_NONBLOCK : 0);
            char buf[128];
            read(pfd[0], buf, sizeof(buf));
            /* Refill pipe */
            fcntl(pfd[1], F_SETFL, O_NONBLOCK);
            write(pfd[1], data, 128);
        }
        printf("  [child] 10000 toggle iterations OK\n");
        _exit(0);
    }

    /* Parent: concurrent read */
    for (int i = 0; i < 10000; i++) {
        char buf[128];
        read(pfd[0], buf, sizeof(buf));
        write(pfd[1], data, 128);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));
    else
        printf("  Completed OK\n");

    close(pfd[0]); close(pfd[1]);
}

/* ========== TEST 8: Concurrent setsockopt + sendmsg race ========== */

static void test_setsockopt_race(void) {
    printf("\n=== TEST 8: setsockopt + sendmsg race ===\n");
    fflush(stdout);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("  socketpair"); return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        alarm(5);
        /* Child: rapidly change socket options */
        for (int i = 0; i < 5000; i++) {
            int val = 4096 + (i % 8) * 1024;
            setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
            setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));

            /* Toggle nonblocking */
            int flags = fcntl(sv[0], F_GETFL);
            fcntl(sv[0], F_SETFL, flags ^ O_NONBLOCK);
        }
        _exit(0);
    }

    /* Parent: concurrent sendmsg/recvmsg */
    char data[1024];
    memset(data, 'S', sizeof(data));
    int sent = 0, recv_ok = 0;
    for (int i = 0; i < 5000; i++) {
        struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
        if (sendmsg(sv[0], &msg, MSG_DONTWAIT) > 0) sent++;

        char rbuf[2048];
        struct iovec riov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
        struct msghdr rmsg = { .msg_iov = &riov, .msg_iovlen = 1 };
        if (recvmsg(sv[1], &rmsg, MSG_DONTWAIT) > 0) recv_ok++;
    }

    int status;
    waitpid(pid, &status, 0);
    printf("  sent=%d recv=%d\n", sent, recv_ok);
    if (WIFSIGNALED(status))
        printf("  *** CRASH sig=%d ***\n", WTERMSIG(status));

    close(sv[0]); close(sv[1]);
}

/* ========== MAIN ========== */

static void check_dmesg(void) {
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE "
           "'oops|bug|panic|fault|corrupt|poison|Backtrace|Unable|"
           "slab|list_del|use.after|double|bad.page|WARNING' 2>/dev/null");
}

int main(void) {
    printf("=== Deep Race Condition Fuzzer ===\n");
    printf("SM-T377A kernel 3.10.9 zero-day research\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    signal(SIGSEGV, sighandler);
    signal(SIGBUS, sighandler);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    struct {
        const char *name;
        void (*func)(void);
    } tests[] = {
        { "tee deadlock", test_tee_deadlock },
        { "sendfile /proc", test_sendfile_proc },
        { "writev FASTIOV", test_writev_fastiov },
        { "dup2 vs ioctl", test_dup2_race },
        { "ION_IOC_CUSTOM", test_ion_custom },
        { "signal during ION", test_signal_during_ioctl },
        { "fcntl F_SETFL race", test_fcntl_race },
        { "setsockopt+sendmsg", test_setsockopt_race },
        { NULL, NULL }
    };

    for (int i = 0; tests[i].name; i++) {
        printf("--- %s ---\n", tests[i].name);
        fflush(stdout);

        pid_t pid = fork();
        if (pid == 0) {
            alarm(25);
            tests[i].func();
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == 14) printf("*** %s: HUNG (SIGALRM) ***\n", tests[i].name);
            else printf("*** %s: CRASHED sig=%d ***\n", tests[i].name, sig);
        }
        check_dmesg();
        printf("\n");
    }

    printf("=== All deep race tests complete ===\n");
    return 0;
}
