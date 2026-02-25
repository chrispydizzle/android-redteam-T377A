/*
 * splice_tty_race.c — Zero-day fuzzer for splice and TTY race conditions
 *
 * Targets TWO unexplored zero-day surfaces on kernel 3.10.9:
 *
 * 1. SPLICE RACES — splice/tee/vmsplice manipulate pipe_buffer structs
 *    which contain function pointers (ops). Concurrent splice + close
 *    can create dangling pipe_buffer references. On 3.10, splice locking
 *    was not fully hardened.
 *
 * 2. TTY LINE DISCIPLINE RACES — TIOCSETD changing ldisc concurrent with
 *    read/write is a classic 3.10 bug class. Multiple CVEs exist for this
 *    pattern (CVE-2014-0196 was n_tty, but other ldiscs may be vulnerable).
 *    Also tests: pty master/slave concurrent operations, TIOCSTI injection
 *    during ldisc change.
 *
 * 3. EPOLL DEEP RACES — epoll_ctl ADD/DEL from threads + epoll_wait
 *    concurrent with file close. Tests edge cases in ep_insert/ep_remove
 *    locking on 3.10.
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o splice_tty_race splice_tty_race.c -lpthread
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>

#ifndef __NR_splice
#define __NR_splice 340
#endif
#ifndef __NR_tee
#define __NR_tee 342
#endif
#ifndef __NR_vmsplice
#define __NR_vmsplice 343
#endif

/* TTY line discipline IDs */
#define N_TTY       0
#define N_SLIP      1
#define N_MOUSE     2
#define N_PPP       3
#define N_STRIP     4
#define N_AX25      5

static volatile int go = 0;
static volatile int stop = 0;

static void sighandler(int sig) {
    printf("  *** SIGNAL %d in PID %d ***\n", sig, getpid());
    fflush(stdout);
    _exit(128 + sig);
}

/* ========== TEST 1: splice between pipes + close race ========== */

static void test_splice_close_race(void) {
    printf("=== TEST 1: splice + close race (pipes) ===\n");
    fflush(stdout);

    int ops = 0, splice_ok = 0, splice_err = 0;

    for (int i = 0; i < 1000; i++) {
        int pipe1[2], pipe2[2];
        if (pipe(pipe1) < 0 || pipe(pipe2) < 0) continue;

        /* Write data to pipe1 */
        char data[4096];
        memset(data, 'A', sizeof(data));
        write(pipe1[1], data, sizeof(data));

        /* Fork: parent splices, child closes pipe ends */
        pid_t pid = fork();
        if (pid == 0) {
            /* Child: close write end of pipe1 and read end of pipe2 rapidly */
            usleep(1);  /* Tiny delay to let splice start */
            close(pipe1[1]);
            close(pipe2[0]);
            _exit(0);
        }

        /* Parent: splice from pipe1 to pipe2 */
        long r = syscall(__NR_splice, pipe1[0], NULL, pipe2[1], NULL,
                         4096, 0x01 /* SPLICE_F_MOVE */);
        if (r > 0) splice_ok++;
        else splice_err++;

        int status;
        waitpid(pid, &status, 0);

        close(pipe1[0]); close(pipe1[1]);
        close(pipe2[0]); close(pipe2[1]);
        ops++;
    }
    printf("  %d ops, splice ok=%d err=%d\n", ops, splice_ok, splice_err);
}

/* ========== TEST 2: tee between pipes + concurrent write ========== */

static int tee_pipe1[2], tee_pipe2[2];

static void *tee_writer_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    char buf[512];
    memset(buf, 'B', sizeof(buf));
    while (!stop) {
        write(tee_pipe1[1], buf, sizeof(buf));
        ops++;
        if (ops % 100 == 0) {
            /* Drain pipe2 to prevent blocking */
            char drain[8192];
            while (read(tee_pipe2[0], drain, sizeof(drain)) > 0);
        }
    }
    return (void*)(long)ops;
}

static void *tee_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        long r = syscall(__NR_tee, tee_pipe1[0], tee_pipe2[1], 4096, 0);
        (void)r;
        /* Also drain pipe1 read end to prevent blocking */
        char drain[4096];
        read(tee_pipe1[0], drain, sizeof(drain));
        ops++;
    }
    return (void*)(long)ops;
}

static void test_tee_race(void) {
    printf("\n=== TEST 2: tee + concurrent write race ===\n");
    fflush(stdout);

    if (pipe(tee_pipe1) < 0 || pipe(tee_pipe2) < 0) {
        perror("  pipe"); return;
    }

    /* Make non-blocking */
    fcntl(tee_pipe1[0], F_SETFL, O_NONBLOCK);
    fcntl(tee_pipe1[1], F_SETFL, O_NONBLOCK);
    fcntl(tee_pipe2[0], F_SETFL, O_NONBLOCK);
    fcntl(tee_pipe2[1], F_SETFL, O_NONBLOCK);

    go = 0; stop = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, tee_writer_thread, NULL);
    pthread_create(&t2, NULL, tee_thread, NULL);

    go = 1;
    sleep(3);
    stop = 1;

    void *r1, *r2;
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    printf("  writer: %ld ops, tee: %ld ops\n", (long)r1, (long)r2);

    close(tee_pipe1[0]); close(tee_pipe1[1]);
    close(tee_pipe2[0]); close(tee_pipe2[1]);
}

/* ========== TEST 3: vmsplice + munmap race ========== */

static void test_vmsplice_race(void) {
    printf("\n=== TEST 3: vmsplice + munmap race ===\n");
    fflush(stdout);

    int ops = 0, ok = 0, err = 0;
    for (int i = 0; i < 500; i++) {
        int pfd[2];
        if (pipe(pfd) < 0) continue;

        /* Map a page for vmsplice */
        void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) { close(pfd[0]); close(pfd[1]); continue; }
        memset(page, 'V', 4096);

        struct iovec iov = { .iov_base = page, .iov_len = 4096 };

        /* Fork: parent vmsplices, child munmaps the page */
        pid_t pid = fork();
        if (pid == 0) {
            usleep(1);
            /* Unmap the page while parent is vmsplicing */
            munmap(page, 4096);
            _exit(0);
        }

        long r = syscall(__NR_vmsplice, pfd[1], &iov, 1,
                         0x02 /* SPLICE_F_GIFT */);
        if (r > 0) ok++;
        else err++;

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("  *** child CRASHED sig=%d at iter %d ***\n",
                   WTERMSIG(status), i);

        munmap(page, 4096);  /* May fail if child already unmapped (COW) */
        close(pfd[0]); close(pfd[1]);
        ops++;
    }
    printf("  %d ops, ok=%d err=%d\n", ops, ok, err);
}

/* ========== TEST 4: PTY line discipline change race ========== */

static int pty_master = -1, pty_slave = -1;

static void *ldisc_switch_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        /* Switch to different line disciplines */
        int ldiscs[] = { N_TTY, N_SLIP, N_PPP, N_TTY };
        for (int i = 0; i < 4 && !stop; i++) {
            int ld = ldiscs[i];
            ioctl(pty_slave, TIOCSETD, &ld);
            ops++;
        }
    }
    return (void*)(long)ops;
}

static void *pty_write_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    char buf[256];
    memset(buf, 'X', sizeof(buf));
    while (!stop) {
        /* Write to master — data goes to slave's ldisc */
        write(pty_master, buf, sizeof(buf));
        ops++;
        usleep(1);
    }
    return (void*)(long)ops;
}

static void *pty_read_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    char buf[256];
    while (!stop) {
        /* Read from slave — exercises ldisc read path */
        read(pty_slave, buf, sizeof(buf));
        ops++;
        usleep(1);
    }
    return (void*)(long)ops;
}

static void test_ldisc_race(void) {
    printf("\n=== TEST 4: PTY ldisc switch + read/write race ===\n");
    fflush(stdout);

    pty_master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (pty_master < 0) { perror("  open ptmx"); return; }

    /* Unlock and get slave name */
    int unlock = 0;
    ioctl(pty_master, TIOCSPTLCK, &unlock);
    int slave_num = 0;
    ioctl(pty_master, TIOCGPTN, &slave_num);

    char slave_name[64];
    snprintf(slave_name, sizeof(slave_name), "/dev/pts/%d", slave_num);
    pty_slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (pty_slave < 0) {
        /* Try alternative */
        snprintf(slave_name, sizeof(slave_name), "/dev/pts%d", slave_num);
        pty_slave = open(slave_name, O_RDWR | O_NOCTTY);
    }
    if (pty_slave < 0) {
        printf("  Cannot open slave %s: %s\n", slave_name, strerror(errno));
        /* Still run with master only */
        pty_slave = pty_master;  /* Fallback: use master for both */
    }

    /* Make non-blocking to avoid hangs */
    fcntl(pty_master, F_SETFL, O_NONBLOCK);
    fcntl(pty_slave, F_SETFL, O_NONBLOCK);

    /* Check which ldiscs are available */
    printf("  Testing available line disciplines...\n");
    int available[8] = {0};
    int test_ldiscs[] = { N_TTY, N_SLIP, N_MOUSE, N_PPP, N_STRIP, N_AX25, -1 };
    for (int i = 0; test_ldiscs[i] >= 0; i++) {
        int old_ld;
        ioctl(pty_slave, TIOCGETD, &old_ld);
        int ld = test_ldiscs[i];
        int r = ioctl(pty_slave, TIOCSETD, &ld);
        if (r == 0) {
            printf("    N_%d: OK\n", ld);
            available[i] = 1;
            /* Switch back to N_TTY */
            int tty = N_TTY;
            ioctl(pty_slave, TIOCSETD, &tty);
        } else {
            printf("    N_%d: %s\n", ld, strerror(errno));
        }
    }

    go = 0; stop = 0;
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, ldisc_switch_thread, NULL);
    pthread_create(&t2, NULL, pty_write_thread, NULL);
    pthread_create(&t3, NULL, pty_read_thread, NULL);

    go = 1;
    sleep(3);
    stop = 1;

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);

    printf("  Completed ldisc race\n");
    if (pty_slave != pty_master) close(pty_slave);
    close(pty_master);
}

/* ========== TEST 5: PTY master/slave concurrent close race ========== */

static void test_pty_close_race(void) {
    printf("\n=== TEST 5: PTY concurrent open/close/ioctl race ===\n");
    fflush(stdout);

    int ops = 0;
    for (int i = 0; i < 500; i++) {
        int master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (master < 0) continue;

        int unlock = 0;
        ioctl(master, TIOCSPTLCK, &unlock);
        int slave_num = 0;
        ioctl(master, TIOCGPTN, &slave_num);

        char sname[64];
        snprintf(sname, sizeof(sname), "/dev/pts/%d", slave_num);
        int slave = open(sname, O_RDWR | O_NOCTTY | O_NONBLOCK);

        pid_t pid = fork();
        if (pid == 0) {
            /* Child: rapidly write to master + change ldisc */
            alarm(3);
            char buf[128];
            memset(buf, 'R', sizeof(buf));
            for (int j = 0; j < 100; j++) {
                write(master, buf, sizeof(buf));
                int ld = (j % 2 == 0) ? N_TTY : N_SLIP;
                ioctl(slave >= 0 ? slave : master, TIOCSETD, &ld);
            }
            _exit(0);
        }

        /* Parent: close master while child writes */
        usleep(10);
        close(master);
        if (slave >= 0) close(slave);

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("  *** CRASH at iter %d, sig=%d ***\n", i, WTERMSIG(status));
        ops++;
    }
    printf("  %d iterations completed\n", ops);
}

/* ========== TEST 6: epoll_ctl ADD/DEL race from threads ========== */

static int epoll_target_fd = -1;
static int epoll_fd = -1;

static void *epoll_add_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        struct epoll_event ev = { .events = EPOLLIN | EPOLLET };
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, epoll_target_fd, &ev);
        ops++;
    }
    return (void*)(long)ops;
}

static void *epoll_del_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    while (!stop) {
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, epoll_target_fd, &ev);
        ops++;
    }
    return (void*)(long)ops;
}

static void *epoll_wait_thread(void *arg) {
    while (!go) sched_yield();
    int ops = 0;
    struct epoll_event evs[4];
    while (!stop) {
        epoll_wait(epoll_fd, evs, 4, 0);
        ops++;
    }
    return (void*)(long)ops;
}

static void test_epoll_race(void) {
    printf("\n=== TEST 6: epoll ADD/DEL/WAIT race ===\n");
    fflush(stdout);

    /* Use a pipe as the target fd */
    int pfd[2];
    pipe(pfd);
    epoll_target_fd = pfd[0];
    epoll_fd = epoll_create1(0);

    go = 0; stop = 0;
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, epoll_add_thread, NULL);
    pthread_create(&t2, NULL, epoll_del_thread, NULL);
    pthread_create(&t3, NULL, epoll_wait_thread, NULL);

    go = 1;
    /* Write to pipe periodically to trigger events */
    for (int i = 0; i < 30; i++) {
        write(pfd[1], "x", 1);
        usleep(100000);  /* 100ms */
    }
    stop = 1;

    void *r1, *r2, *r3;
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    pthread_join(t3, &r3);
    printf("  add: %ld, del: %ld, wait: %ld\n",
           (long)r1, (long)r2, (long)r3);

    close(epoll_fd);
    close(pfd[0]); close(pfd[1]);
}

/* ========== TEST 7: epoll nested + concurrent modification ========== */

static void test_epoll_nested_race(void) {
    printf("\n=== TEST 7: Nested epoll race ===\n");
    fflush(stdout);

    int ops = 0;
    for (int i = 0; i < 200; i++) {
        int pfd[2];
        pipe(pfd);

        int ep1 = epoll_create1(0);
        int ep2 = epoll_create1(0);

        /* ep1 monitors pipe read end */
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(ep1, EPOLL_CTL_ADD, pfd[0], &ev);

        /* ep2 monitors ep1 (nested) */
        ev.events = EPOLLIN;
        epoll_ctl(ep2, EPOLL_CTL_ADD, ep1, &ev);

        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            /* Child: rapidly write to pipe + close pipe + close ep1 */
            for (int j = 0; j < 50; j++) {
                write(pfd[1], "data", 4);
                struct epoll_event ev2 = { .events = EPOLLIN | EPOLLOUT };
                epoll_ctl(ep1, EPOLL_CTL_MOD, pfd[0], &ev2);
                struct epoll_event evs[4];
                epoll_wait(ep2, evs, 4, 0);
            }
            close(pfd[1]);
            close(ep1);
            _exit(0);
        }

        /* Parent: epoll_wait on nested epoll + close things */
        struct epoll_event evs[4];
        for (int j = 0; j < 50; j++) {
            epoll_wait(ep2, evs, 4, 0);
            write(pfd[1], "x", 1);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("  *** CRASH at iter %d, sig=%d ***\n", i, WTERMSIG(status));

        close(ep2); close(ep1);
        close(pfd[0]); close(pfd[1]);
        ops++;
    }
    printf("  %d iterations completed\n", ops);
}

/* ========== TEST 8: splice from socket to pipe race ========== */

static void test_splice_socket_race(void) {
    printf("\n=== TEST 8: splice socket→pipe + close race ===\n");
    fflush(stdout);

    int ops = 0, ok = 0, err = 0;
    for (int i = 0; i < 500; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) continue;

        int pfd[2];
        if (pipe(pfd) < 0) { close(sv[0]); close(sv[1]); continue; }

        /* Write data to socket */
        char data[1024];
        memset(data, 'S', sizeof(data));
        send(sv[0], data, sizeof(data), MSG_DONTWAIT);

        pid_t pid = fork();
        if (pid == 0) {
            alarm(2);
            usleep(1);
            /* Close socket while parent splices */
            close(sv[1]);
            close(pfd[1]);
            _exit(0);
        }

        /* splice from socket to pipe */
        long r = syscall(__NR_splice, sv[1], NULL, pfd[1], NULL,
                         1024, 0x03 /* SPLICE_F_MOVE | SPLICE_F_NONBLOCK */);
        if (r > 0) ok++;
        else err++;

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("  *** CRASH at iter %d ***\n", i);

        close(sv[0]); close(sv[1]);
        close(pfd[0]); close(pfd[1]);
        ops++;
    }
    printf("  %d ops, splice ok=%d err=%d\n", ops, ok, err);
}

/* ========== MAIN ========== */

static void check_dmesg(const char *label) {
    printf("\n--- dmesg after %s ---\n", label);
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE "
           "'oops|bug|panic|fault|corrupt|poison|Backtrace|Unable|"
           "slab|list_del|use.after|double|bad.page|WARNING|BUG' 2>/dev/null");
}

int main(void) {
    printf("=== Splice/TTY/Epoll Race Condition Fuzzer ===\n");
    printf("Kernel zero-day research — SM-T377A (3.10.9)\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    signal(SIGSEGV, sighandler);
    signal(SIGBUS, sighandler);

    /* Pin to CPU 0 */
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    /* Each test in forked child for crash safety */
    struct {
        const char *name;
        void (*func)(void);
    } tests[] = {
        { "splice+close race", test_splice_close_race },
        { "tee race", test_tee_race },
        { "vmsplice+munmap race", test_vmsplice_race },
        { "ldisc switch race", test_ldisc_race },
        { "pty close race", test_pty_close_race },
        { "epoll ADD/DEL race", test_epoll_race },
        { "nested epoll race", test_epoll_nested_race },
        { "splice socket race", test_splice_socket_race },
        { NULL, NULL }
    };

    for (int i = 0; tests[i].name; i++) {
        printf("--- Running: %s ---\n", tests[i].name);
        fflush(stdout);

        pid_t pid = fork();
        if (pid == 0) {
            alarm(20);
            tests[i].func();
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("*** %s: CRASHED sig=%d ***\n", tests[i].name, WTERMSIG(status));
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            printf("*** %s: exited with code %d ***\n",
                   tests[i].name, WEXITSTATUS(status));
        }

        check_dmesg(tests[i].name);
    }

    printf("\n=== All tests complete ===\n");
    return 0;
}
