/*
 * binder_fuzz.c — Android binder ioctl fuzzer
 *
 * Target: Samsung SM-T377A, kernel 3.10.9
 * Binder ioctls from: drivers/staging/android/binder.h
 *
 * Attack surface:
 *   - BINDER_WRITE_READ: main IPC path — read/write buffers
 *   - BINDER_SET_MAX_THREADS: thread pool control
 *   - BINDER_SET_CONTEXT_MGR: become servicemanager (one per system)
 *   - BINDER_THREAD_EXIT: thread cleanup
 *   - BINDER_VERSION: info leak
 *   - BC_* commands embedded in write buffer
 *
 * Build: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -o binder_fuzz binder_fuzz.c
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

/* ===== Binder definitions ===== */

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version {
    signed long protocol_version;
};

/* Binder transaction data (simplified for fuzzing) */
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

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_IDLE_TIMEOUT _IOW('b', 3, int64_t)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, size_t)
#define BINDER_SET_IDLE_PRIORITY _IOW('b', 6, int32_t)
#define BINDER_SET_CONTEXT_MGR  _IOW('b', 7, int32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)

/* BC (binder command) codes written into the write buffer */
#define BC_TRANSACTION      _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY            _IOW('c', 1, struct binder_transaction_data)
#define BC_ACQUIRE_RESULT   _IOW('c', 2, int32_t)
#define BC_FREE_BUFFER      _IOW('c', 3, void *)
#define BC_INCREFS          _IOW('c', 4, uint32_t)
#define BC_ACQUIRE          _IOW('c', 5, uint32_t)
#define BC_RELEASE          _IOW('c', 6, uint32_t)
#define BC_DECREFS          _IOW('c', 7, uint32_t)
#define BC_INCREFS_DONE     _IOW('c', 8, struct { void *ptr; void *cookie; })
#define BC_ACQUIRE_DONE     _IOW('c', 9, struct { void *ptr; void *cookie; })
#define BC_REGISTER_LOOPER  _IO('c', 11)
#define BC_ENTER_LOOPER     _IO('c', 12)
#define BC_EXIT_LOOPER      _IO('c', 13)
#define BC_REQUEST_DEATH_NOTIFICATION _IOW('c', 14, struct { uint32_t handle; void *cookie; })
#define BC_CLEAR_DEATH_NOTIFICATION _IOW('c', 15, struct { uint32_t handle; void *cookie; })
#define BC_DEAD_BINDER_DONE _IOW('c', 16, void *)

/* ===== PRNG ===== */

static uint64_t rng_state;
static uint64_t rnd64(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return x;
}
static uint32_t rnd32(void) { return (uint32_t)rnd64(); }

/* ===== Globals ===== */

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static FILE *g_log = NULL;
static uint64_t g_ops = 0;

static void log_op(const char *op, int ret, int err, uint64_t a0, uint64_t a1) {
    if (!g_log) return;
    fprintf(g_log, "op=%s ret=%d e=%d a0=0x%llx a1=0x%llx\n",
            op, ret, err,
            (unsigned long long)a0, (unsigned long long)a1);
}

/* Binder mmap buffer — binder requires a mmap'd region for transaction data */
static void *g_binder_mmap = NULL;
#define BINDER_MMAP_SIZE (1024 * 1024)  /* 1MB is typical */

/* ===== Operations ===== */

static void op_version(int fd) {
    struct binder_version ver;
    memset(&ver, 0, sizeof(ver));
    errno = 0;
    int ret = ioctl(fd, BINDER_VERSION, &ver);
    log_op("VERSION", ret, errno, (uint64_t)ver.protocol_version, 0);
    g_ops++;
}

static void op_set_max_threads(int fd) {
    size_t vals[] = {0, 1, 4, 15, 16, 255, 0xFFFFFFFF, 0x7FFFFFFF};
    size_t val = vals[rnd32() % 8];
    errno = 0;
    int ret = ioctl(fd, BINDER_SET_MAX_THREADS, &val);
    log_op("MAX_THREADS", ret, errno, val, 0);
    g_ops++;
}

static void op_set_context_mgr(int fd) {
    int32_t val = 0;
    errno = 0;
    int ret = ioctl(fd, BINDER_SET_CONTEXT_MGR, &val);
    log_op("CONTEXT_MGR", ret, errno, 0, 0);
    g_ops++;
}

static void op_thread_exit(int fd) {
    int32_t val = 0;
    errno = 0;
    int ret = ioctl(fd, BINDER_THREAD_EXIT, &val);
    log_op("THREAD_EXIT", ret, errno, 0, 0);
    g_ops++;
}

/* Write a BC command + read response */
static void op_write_read(int fd) {
    /* Build a write buffer with a single BC command */
    uint8_t wbuf[256];
    int wlen = 0;

    uint32_t cmd_pick = rnd32() % 10;
    uint32_t cmd;

    if (cmd_pick < 3) {
        /* BC_INCREFS/ACQUIRE/RELEASE/DECREFS with handle */
        uint32_t bc_cmds[] = {BC_INCREFS, BC_ACQUIRE, BC_RELEASE, BC_DECREFS};
        cmd = bc_cmds[rnd32() % 4];
        memcpy(wbuf, &cmd, 4); wlen += 4;
        /* Avoid handle 0 (servicemanager) — refcount ops on it kill the system */
        uint32_t handle = 1 + (rnd32() % 9);
        memcpy(wbuf + wlen, &handle, 4); wlen += 4;
    } else if (cmd_pick < 5) {
        /* BC_ENTER_LOOPER or BC_EXIT_LOOPER */
        cmd = (rnd32() % 2) ? BC_ENTER_LOOPER : BC_EXIT_LOOPER;
        memcpy(wbuf, &cmd, 4); wlen += 4;
    } else if (cmd_pick < 7) {
        /* BC_FREE_BUFFER with random/NULL pointer */
        cmd = BC_FREE_BUFFER;
        memcpy(wbuf, &cmd, 4); wlen += 4;
        void *ptr = (rnd32() % 2) ? NULL : (void *)(uintptr_t)(rnd32());
        memcpy(wbuf + wlen, &ptr, sizeof(ptr)); wlen += sizeof(ptr);
    } else if (cmd_pick < 9) {
        /* BC_TRANSACTION — MUST use TF_ONE_WAY to avoid blocking */
        cmd = BC_TRANSACTION;
        memcpy(wbuf, &cmd, 4); wlen += 4;
        struct binder_transaction_data td;
        memset(&td, 0, sizeof(td));
        td.target.handle = 1 + (rnd32() % 4);  /* Avoid handle 0 (servicemanager) */
        td.code = rnd32();
        td.flags = 0x01;  /* TF_ONE_WAY always — sync blocks forever */
        td.data_size = 0;
        td.offsets_size = 0;
        memcpy(wbuf + wlen, &td, sizeof(td)); wlen += sizeof(td);
    } else {
        /* Random garbage command */
        cmd = rnd32();
        memcpy(wbuf, &cmd, 4); wlen += 4;
    }

    /* Read buffer — set to 0 to avoid blocking!
     * Binder blocks on read_size>0 waiting for incoming transactions */
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = wlen;
    bwr.write_consumed = 0;
    bwr.write_buffer = (unsigned long)wbuf;
    bwr.read_size = 0;  /* write-only to avoid blocking */
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;

    errno = 0;
    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    log_op("WRITE_READ", ret, errno, cmd, (uint64_t)bwr.write_consumed);
    g_ops++;
}

/* Write-only (no read) */
static void op_write_only(int fd) {
    uint32_t cmd = BC_REGISTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = 4;
    bwr.write_buffer = (unsigned long)&cmd;
    bwr.read_size = 0;
    bwr.read_buffer = 0;

    errno = 0;
    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    log_op("WRITE_ONLY", ret, errno, cmd, 0);
    g_ops++;
}

/* Empty write-read (triggers poll/read) — non-blocking only */
static void op_empty_wr(int fd) {
    uint8_t rbuf[64];
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = 0;
    bwr.read_size = sizeof(rbuf);
    bwr.read_buffer = (unsigned long)rbuf;

    /* Use a very short timeout by sending SIGALRM */
    alarm(1);
    errno = 0;
    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    alarm(0);
    log_op("EMPTY_WR", ret, errno, (uint64_t)bwr.read_consumed, 0);
    g_ops++;
}

/* Fuzz with completely random ioctl data */
static void op_random_ioctl(int fd) {
    uint8_t buf[128];
    for (int i = 0; i < 128; i++) buf[i] = (uint8_t)rnd32();

    /* Skip BINDER_WRITE_READ with random data — random read_size blocks */
    unsigned long cmds[] = {
        BINDER_SET_MAX_THREADS,
        BINDER_SET_CONTEXT_MGR, BINDER_THREAD_EXIT,
        BINDER_VERSION, BINDER_SET_IDLE_TIMEOUT
    };
    unsigned long cmd = cmds[rnd32() % 5];

    errno = 0;
    int ret = ioctl(fd, cmd, buf);
    log_op("RANDOM", ret, errno, cmd, 0);
    g_ops++;
}

/* Reopen binder (test context cleanup) */
static int op_reopen(int fd) {
    close(fd);
    if (g_binder_mmap) {
        munmap(g_binder_mmap, BINDER_MMAP_SIZE);
        g_binder_mmap = NULL;
    }

    usleep(1000);
    int nfd = open("/dev/binder", O_RDWR);
    if (nfd < 0) {
        log_op("REOPEN_FAIL", -1, errno, 0, 0);
        return -1;
    }

    g_binder_mmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                         MAP_PRIVATE, nfd, 0);
    if (g_binder_mmap == MAP_FAILED) {
        g_binder_mmap = NULL;
        /* Non-fatal — binder works without mmap for some ops */
    }

    log_op("REOPEN", 0, 0, (uint64_t)nfd, 0);
    g_ops++;
    return nfd;
}

/* ===== Main ===== */

int main(int argc, char **argv) {
    uint64_t max_iters = 0, seed = 0;

    if (argc >= 2) max_iters = strtoull(argv[1], NULL, 0);
    if (argc >= 3) seed = strtoull(argv[2], NULL, 0);

    if (seed == 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        seed = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec;
    }
    rng_state = seed;

    const char *log_path = getenv("BINDER_LOG_PATH");
    if (!log_path || !*log_path) log_path = "./binder_fuzz.log";
    g_log = fopen(log_path, "w");
    if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);

    signal(SIGINT, on_sigint);
    signal(SIGALRM, SIG_IGN);  /* for timeout on blocking reads */

    int fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "[-] open(/dev/binder): %s\n", strerror(errno));
        return 1;
    }

    /* Binder expects an mmap'd region for transaction buffers */
    g_binder_mmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                         MAP_PRIVATE, fd, 0);
    if (g_binder_mmap == MAP_FAILED) {
        g_binder_mmap = NULL;
        fprintf(stderr, "[!] binder mmap failed (continuing): %s\n", strerror(errno));
    }

    fprintf(stderr, "[+] /dev/binder fd=%d seed=0x%llx mmap=%p\n",
            fd, (unsigned long long)seed, g_binder_mmap);

    /* Get version first */
    op_version(fd);

    uint64_t iters = 0;
    while (!g_stop) {
        if (max_iters && iters >= max_iters) break;

        int ops = 2 + (rnd32() % 6);
        for (int i = 0; i < ops && !g_stop; i++) {
            uint32_t pick = rnd32() % 100;

            /* NOTE: BINDER_SET_CONTEXT_MGR removed — SELinux blocks it AND
             * the combination with fd close/reopen killed node graph (see findings).
             * op_reopen also removed — same reason. */
            if      (pick < 5)   op_version(fd);
            else if (pick < 15)  op_set_max_threads(fd);
            else if (pick < 20)  op_thread_exit(fd);
            else if (pick < 55)  op_write_read(fd);
            else if (pick < 70)  op_write_only(fd);
            else if (pick < 85)  op_random_ioctl(fd);
            else                 { /* nop breather */ }
        }

        /* Reopen DISABLED — caused binder node death in previous run */
        /* if (rnd32() % 1000 == 0) { ... } */

        if (iters % 1000 == 0) {
            fprintf(stderr, "[%llu] ops=%llu\n",
                    (unsigned long long)iters,
                    (unsigned long long)g_ops);
        }
        iters++;
    }

    fprintf(stderr, "[*] Done iters=%llu ops=%llu\n",
            (unsigned long long)iters,
            (unsigned long long)g_ops);

    if (g_binder_mmap) munmap(g_binder_mmap, BINDER_MMAP_SIZE);
    close(fd);
    if (g_log) { fflush(g_log); fclose(g_log); }
    return 0;
}
