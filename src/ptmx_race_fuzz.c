/*
 * ptmx_race_fuzz.c — PTY master/slave race condition fuzzer
 *
 * Targets the tty subsystem which has been historically buggy in 3.10:
 *   1. TIOCSETD (line discipline change) concurrent with read/write
 *   2. Close master while slave is actively doing I/O
 *   3. TIOCSTI (fake input) racing with discipline change
 *   4. Concurrent open/close/ioctl from multiple threads
 *   5. TIOCSPTLCK unlock + access race
 *   6. HANGUP race (VHANGUP while I/O in progress)
 *
 * Each test in fork-isolated child with alarm(5) for safety.
 * Build: .\qemu\build-arm.bat src\ptmx_race_fuzz.c ptmx_race_fuzz
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

static volatile int g_stop = 0;
static volatile int g_master_fd = -1;
static volatile int g_slave_fd = -1;

/* Line disciplines to try */
#define N_TTY    0
#define N_SLIP   1
#define N_PPP    3

static int open_pty_pair(int *master, int *slave) {
    *master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (*master < 0) return -1;

    /* Unlock slave */
    int unlock = 0;
    if (ioctl(*master, TIOCSPTLCK, &unlock) < 0) {
        close(*master); return -1;
    }

    /* Get slave name */
    int pty_num;
    if (ioctl(*master, TIOCGPTN, &pty_num) < 0) {
        close(*master); return -1;
    }

    char slave_name[32];
    snprintf(slave_name, sizeof(slave_name), "/dev/pts/%d", pty_num);
    *slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (*slave < 0) {
        close(*master); return -1;
    }
    return 0;
}

/* ===== TEST 1: TIOCSETD race with concurrent I/O ===== */

static void *ldisc_writer(void *arg) {
    int fd = *(int *)arg;
    char buf[64];
    memset(buf, 'A', sizeof(buf));
    while (!g_stop) {
        write(fd, buf, sizeof(buf));
        usleep(1);
    }
    return NULL;
}

static void *ldisc_reader(void *arg) {
    int fd = *(int *)arg;
    char buf[64];
    while (!g_stop) {
        read(fd, buf, sizeof(buf));
        usleep(1);
    }
    return NULL;
}

static void *ldisc_changer(void *arg) {
    int fd = *(int *)arg;
    while (!g_stop) {
        int ldisc = N_TTY;
        ioctl(fd, TIOCSETD, &ldisc);
        usleep(1);
        /* Try SLIP — may fail but the attempt races with I/O */
        ldisc = N_SLIP;
        ioctl(fd, TIOCSETD, &ldisc);
        usleep(1);
        ldisc = N_TTY;
        ioctl(fd, TIOCSETD, &ldisc);
        usleep(1);
    }
    return NULL;
}

static void test_ldisc_race(void) {
    printf("=== TEST 1: TIOCSETD race with concurrent I/O ===\n");
    int anomalies = 0;

    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int master, slave;
            if (open_pty_pair(&master, &slave) < 0) _exit(99);

            /* Set non-blocking to avoid writer blocking */
            fcntl(master, F_SETFL, O_NONBLOCK);
            fcntl(slave, F_SETFL, O_NONBLOCK);

            g_stop = 0;
            pthread_t tw, tr, tc;
            pthread_create(&tw, NULL, ldisc_writer, &slave);
            pthread_create(&tr, NULL, ldisc_reader, &master);
            pthread_create(&tc, NULL, ldisc_changer, &slave);
            usleep(500000); /* 500ms of racing */
            g_stop = 1;
            pthread_join(tw, NULL);
            pthread_join(tr, NULL);
            pthread_join(tc, NULL);
            close(slave);
            close(master);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 25 == 0)
            printf("  [%d/100] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 100 trials\n\n", anomalies);
}

/* ===== TEST 2: Close master while slave does I/O ===== */

struct close_io_args {
    int master;
    int slave;
};

static void *close_master_thread(void *arg) {
    struct close_io_args *a = arg;
    usleep(100); /* let I/O start */
    close(a->master);
    return NULL;
}

static void *slave_io_thread(void *arg) {
    struct close_io_args *a = arg;
    char buf[128];
    memset(buf, 'B', sizeof(buf));
    for (int i = 0; i < 1000 && !g_stop; i++) {
        write(a->slave, buf, sizeof(buf));
        struct termios term;
        tcgetattr(a->slave, &term);
        usleep(1);
    }
    return NULL;
}

static void test_close_io_race(void) {
    printf("=== TEST 2: Close master while slave does I/O ===\n");
    int anomalies = 0;

    for (int trial = 0; trial < 200; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int master, slave;
            if (open_pty_pair(&master, &slave) < 0) _exit(99);
            fcntl(slave, F_SETFL, O_NONBLOCK);

            g_stop = 0;
            struct close_io_args args = { master, slave };
            pthread_t t1, t2;
            pthread_create(&t1, NULL, close_master_thread, &args);
            pthread_create(&t2, NULL, slave_io_thread, &args);
            pthread_join(t1, NULL);
            g_stop = 1;
            pthread_join(t2, NULL);
            close(slave);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 50 == 0)
            printf("  [%d/200] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 200 trials\n\n", anomalies);
}

/* ===== TEST 3: TIOCSTI race (fake input injection) ===== */

static void *tiocsti_thread(void *arg) {
    int fd = *(int *)arg;
    while (!g_stop) {
        char c = 'X';
        ioctl(fd, TIOCSTI, &c);
        usleep(1);
    }
    return NULL;
}

static void test_tiocsti_race(void) {
    printf("=== TEST 3: TIOCSTI + discipline change race ===\n");
    int anomalies = 0;

    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int master, slave;
            if (open_pty_pair(&master, &slave) < 0) _exit(99);
            fcntl(master, F_SETFL, O_NONBLOCK);

            g_stop = 0;
            pthread_t t1, t2, t3;
            pthread_create(&t1, NULL, tiocsti_thread, &slave);
            pthread_create(&t2, NULL, ldisc_changer, &slave);
            pthread_create(&t3, NULL, ldisc_reader, &master);
            usleep(500000);
            g_stop = 1;
            pthread_join(t1, NULL);
            pthread_join(t2, NULL);
            pthread_join(t3, NULL);
            close(slave);
            close(master);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 25 == 0)
            printf("  [%d/100] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 100 trials\n\n", anomalies);
}

/* ===== TEST 4: Rapid open/close ptmx (exhaust + reclaim) ===== */

static void test_rapid_open_close(void) {
    printf("=== TEST 4: Rapid ptmx open/close (SLUB pressure) ===\n");
    int anomalies = 0;

    for (int trial = 0; trial < 50; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            for (int i = 0; i < 500; i++) {
                int master, slave;
                if (open_pty_pair(&master, &slave) == 0) {
                    char buf[16] = "test\n";
                    write(slave, buf, 5);
                    close(slave);
                    close(master);
                }
            }
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 25 == 0)
            printf("  [%d/50] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 50 trials\n\n", anomalies);
}

/* ===== TEST 5: VHANGUP + I/O race ===== */

static void *hangup_thread(void *arg) {
    int fd = *(int *)arg;
    while (!g_stop) {
        ioctl(fd, TIOCVHANGUP, 0);
        usleep(50);
    }
    return NULL;
}

static void test_hangup_race(void) {
    printf("=== TEST 5: VHANGUP + I/O race ===\n");
    int anomalies = 0;

    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int master, slave;
            if (open_pty_pair(&master, &slave) < 0) _exit(99);
            fcntl(master, F_SETFL, O_NONBLOCK);
            fcntl(slave, F_SETFL, O_NONBLOCK);

            g_stop = 0;
            pthread_t tw, tr, th;
            pthread_create(&tw, NULL, ldisc_writer, &slave);
            pthread_create(&tr, NULL, ldisc_reader, &master);
            pthread_create(&th, NULL, hangup_thread, &master);
            usleep(500000);
            g_stop = 1;
            pthread_join(tw, NULL);
            pthread_join(tr, NULL);
            pthread_join(th, NULL);
            close(slave);
            close(master);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 25 == 0)
            printf("  [%d/100] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 100 trials\n\n", anomalies);
}

/* ===== TEST 6: Terminal attribute changes during I/O ===== */

static void *termios_changer(void *arg) {
    int fd = *(int *)arg;
    while (!g_stop) {
        struct termios t;
        tcgetattr(fd, &t);
        /* Toggle canonical mode */
        t.c_lflag ^= ICANON;
        tcsetattr(fd, TCSANOW, &t);
        usleep(10);
        /* Toggle echo */
        t.c_lflag ^= ECHO;
        tcsetattr(fd, TCSANOW, &t);
        usleep(10);
        /* Toggle raw mode bits */
        t.c_iflag ^= (IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
        tcsetattr(fd, TCSAFLUSH, &t);
        usleep(10);
    }
    return NULL;
}

static void test_termios_io_race(void) {
    printf("=== TEST 6: Termios changes during I/O ===\n");
    int anomalies = 0;

    for (int trial = 0; trial < 100; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int master, slave;
            if (open_pty_pair(&master, &slave) < 0) _exit(99);
            fcntl(master, F_SETFL, O_NONBLOCK);
            fcntl(slave, F_SETFL, O_NONBLOCK);

            g_stop = 0;
            pthread_t tw, tr, tc;
            pthread_create(&tw, NULL, ldisc_writer, &slave);
            pthread_create(&tr, NULL, ldisc_reader, &master);
            pthread_create(&tc, NULL, termios_changer, &slave);
            usleep(500000);
            g_stop = 1;
            pthread_join(tw, NULL);
            pthread_join(tr, NULL);
            pthread_join(tc, NULL);
            close(slave);
            close(master);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 25 == 0)
            printf("  [%d/100] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 100 trials\n\n", anomalies);
}

/* ===== TEST 7: Multi-thread open+close+ioctl chaos ===== */

static void *ptmx_chaos(void *arg) {
    (void)arg;
    while (!g_stop) {
        int master, slave;
        if (open_pty_pair(&master, &slave) == 0) {
            char buf[32] = "chaos";
            write(slave, buf, 5);
            int ldisc = N_TTY;
            ioctl(slave, TIOCSETD, &ldisc);
            struct termios t;
            tcgetattr(slave, &t);
            close(slave);
            /* Use master after slave close */
            read(master, buf, sizeof(buf));
            close(master);
        }
        usleep(10);
    }
    return NULL;
}

static void test_ptmx_chaos(void) {
    printf("=== TEST 7: Multi-thread ptmx chaos ===\n");
    int anomalies = 0;

    for (int trial = 0; trial < 50; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            g_stop = 0;
            pthread_t threads[4];
            for (int i = 0; i < 4; i++)
                pthread_create(&threads[i], NULL, ptmx_chaos, NULL);
            sleep(2);
            g_stop = 1;
            for (int i = 0; i < 4; i++)
                pthread_join(threads[i], NULL);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("  [%d] %s sig=%d\n", trial,
                   sig == SIGALRM ? "HANG" : "CRASH ***", sig);
            anomalies++;
        }
        if ((trial + 1) % 10 == 0)
            printf("  [%d/50] anomalies=%d\n", trial + 1, anomalies);
    }
    printf("  Result: %d anomalies / 50 trials\n\n", anomalies);
}

int main(int argc, char **argv) {
    printf("=== PTMX/TTY Race Fuzzer ===\n");
    printf("Kernel 3.10.9 | PID=%d UID=%d\n", getpid(), getuid());

    /* Validate ptmx works */
    int m, s;
    if (open_pty_pair(&m, &s) < 0) {
        printf("FATAL: can't open pty pair\n");
        return 1;
    }
    printf("PTY pair: master=%d slave=%d\n\n", m, s);
    close(s); close(m);

    int test = -1;
    if (argc > 1) test = atoi(argv[1]);

    if (test < 0 || test == 1) test_ldisc_race();
    if (test < 0 || test == 2) test_close_io_race();
    if (test < 0 || test == 3) test_tiocsti_race();
    if (test < 0 || test == 4) test_rapid_open_close();
    if (test < 0 || test == 5) test_hangup_race();
    if (test < 0 || test == 6) test_termios_io_race();
    if (test < 0 || test == 7) test_ptmx_chaos();

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE 'tty|ldisc|ptmx|pts|oops|BUG|panic|fault|KASAN' 2>/dev/null");
    printf("\n=== Done ===\n");
    return 0;
}
