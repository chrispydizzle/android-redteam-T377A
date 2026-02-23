#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * Stub protocol notes (from your module):
 * - Single ioctl number, variable-size payload. First 8 bytes are uk_header:
 *      u32 id; u32 ret;
 * - Driver reads size from _IOC_SIZE(cmd) and copy_from_user(size) into stack buffer.
 * - Must call CHECK_VERSION (id=0) first, then SET_FLAGS (id=530), then others.
 */

#define DEV_PATH "/dev/mali0"
#define CALL_MAX_SIZE 536

// Function IDs (match your stub)
#define UKP_FUNC_ID_CHECK_VERSION 0
#define KBASE_FUNC_MEM_ALLOC      512
#define KBASE_FUNC_MEM_IMPORT     513
#define KBASE_FUNC_MEM_COMMIT     514
#define KBASE_FUNC_MEM_QUERY      515
#define KBASE_FUNC_MEM_FREE       516
#define KBASE_FUNC_MEM_FLAGS_CHANGE 517
#define KBASE_FUNC_MEM_ALIAS      518
#define KBASE_FUNC_JOB_SUBMIT_UK6 519
#define KBASE_FUNC_SYNC           520
#define KBASE_FUNC_POST_TERM      521
#define KBASE_FUNC_HWCNT_SETUP    522
#define KBASE_FUNC_HWCNT_DUMP     523
#define KBASE_FUNC_HWCNT_CLEAR    524
#define KBASE_FUNC_GPU_PROPS_REG_DUMP 526
#define KBASE_FUNC_FIND_CPU_OFFSET 527
#define KBASE_FUNC_GET_VERSION    528
#define KBASE_FUNC_SET_FLAGS      530
#define KBASE_FUNC_INJECT_ERROR   532
#define KBASE_FUNC_MODEL_CONTROL  533
#define KBASE_FUNC_KEEP_GPU_POWERED 534
#define KBASE_FUNC_FENCE_VALIDATE 535
#define KBASE_FUNC_STREAM_CREATE  536
#define KBASE_FUNC_JOB_SUBMIT     540
#define KBASE_FUNC_DISJOINT_QUERY 541
#define KBASE_FUNC_GET_CONTEXT_ID 543

// uk_header (matches your union layout for the first 8 bytes)
struct uk_header {
    uint32_t id;
    uint32_t ret;
};

// CHECK_VERSION payload (matches your stub’s local struct)
struct uk_check_version {
    struct uk_header header;
    uint16_t major;
    uint16_t minor;
    uint8_t  padding[4];
};

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int sig) {
    (void)sig;
    g_stop = 1;
}

/* Simple PRNG: xorshift64 */
static uint64_t rng_state = 0x123456789abcdef0ULL;
static uint64_t rnd64(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}
static uint32_t rnd32(void) { return (uint32_t)rnd64(); }
static uint32_t pick_u32(const uint32_t *arr, size_t n) {
    return arr[rnd64() % n];
}

/*
 * The real driver uses a single ioctl “number” and uses _IOC_SIZE(cmd)
 * to determine the payload length.
 *
 * You can pick any _IOC type/nr; your stub doesn’t inspect cmd besides size.
 * Use _IOC with _IOC_READ|_IOC_WRITE because the stub does copy_to_user too.
 */
static unsigned int make_cmd(uint32_t size) {
    // 'M' is arbitrary; nr=0 is arbitrary.
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, size);
}

static void fill_random(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rnd32();
}

static void hexdump_prefix(const uint8_t *buf, size_t n, size_t max) {
    size_t m = n < max ? n : max;
    for (size_t i = 0; i < m; i++) {
        fprintf(stderr, "%02x", buf[i]);
        if ((i + 1) % 2 == 0) fprintf(stderr, " ");
    }
    if (n > max) fprintf(stderr, "...");
}

static int do_ioctl(int fd, unsigned int cmd, void *buf) {
    int r = ioctl(fd, cmd, buf);
    return r;
}

/* Session prologue: CHECK_VERSION then SET_FLAGS (minimal valid-ish) */
static int do_handshake(int fd) {
    // CHECK_VERSION requires size >= sizeof(struct uk_check_version) in your stub.
    struct uk_check_version ver;
    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10;
    ver.minor = 0;

    unsigned int cmd_ver = make_cmd((uint32_t)sizeof(ver));
    if (do_ioctl(fd, cmd_ver, &ver) < 0) {
        fprintf(stderr, "[!] CHECK_VERSION ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    // SET_FLAGS: your stub doesn’t parse fields; it only checks id and setup_complete.
    // It expects size=16 in your log. We’ll send 16 bytes.
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = KBASE_FUNC_SET_FLAGS;

    unsigned int cmd_flags = make_cmd((uint32_t)sizeof(buf));
    if (do_ioctl(fd, cmd_flags, buf) < 0) {
        fprintf(stderr, "[!] SET_FLAGS ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    uint64_t iters = 0;
    uint64_t max_iters = 0; // 0 = infinite
    uint64_t seed = 0;

    if (argc >= 2) max_iters = strtoull(argv[1], NULL, 0);
    if (argc >= 3) seed = strtoull(argv[2], NULL, 0);

    if (seed == 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        seed = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec;
    }
    rng_state = seed;

    signal(SIGINT, on_sigint);

    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[-] Failed to open %s: errno=%d (%s)\n", DEV_PATH, errno, strerror(errno));
        return 1;
    }
    fprintf(stderr, "[+] Opened %s (fd=%d), seed=0x%llx\n", DEV_PATH, fd, (unsigned long long)seed);

    if (do_handshake(fd) != 0) {
        fprintf(stderr, "[-] Handshake failed\n");
        close(fd);
        return 1;
    }
    fprintf(stderr, "[+] Handshake OK\n");

    // Weighted list of “interesting” ids. Add more as you implement real logic.
    const uint32_t ids[] = {
        KBASE_FUNC_MEM_ALLOC,
        KBASE_FUNC_MEM_FREE,
        KBASE_FUNC_MEM_QUERY,
        KBASE_FUNC_MEM_COMMIT,
        KBASE_FUNC_MEM_FLAGS_CHANGE,
        KBASE_FUNC_GPU_PROPS_REG_DUMP,
        KBASE_FUNC_GET_VERSION,
        KBASE_FUNC_GET_CONTEXT_ID,
        KBASE_FUNC_DISJOINT_QUERY,
        KBASE_FUNC_FIND_CPU_OFFSET,
        // keep some noise:
        KBASE_FUNC_SYNC,
        KBASE_FUNC_POST_TERM
    };

    // Sizes to try a lot (boundary-focused), plus random.
    const uint32_t sizes[] = {
        0, 8, 12, 15, 16, 23, 24, 31, 32, 39, 40,
        47, 48, 49, 55, 56, 57, 63, 64,
        127, 128, 255, 256, 511, 512, 535, 536
    };

    // We keep one “known-good-ish” gpu_va from MEM_ALLOC to enable stateful sequences.
    uint64_t last_gpu_va = 0;

    uint8_t buf[CALL_MAX_SIZE];

    while (!g_stop) {
        if (max_iters && iters >= max_iters) break;

        // Decide size:
        uint32_t size;
        if ((rnd32() % 4) == 0) {
            // 25%: random size in [0..CALL_MAX_SIZE]
            size = (uint32_t)(rnd64() % (CALL_MAX_SIZE + 1));
        } else {
            // 75%: boundary sizes
            size = pick_u32(sizes, sizeof(sizes)/sizeof(sizes[0]));
            if (size > CALL_MAX_SIZE) size = CALL_MAX_SIZE;
        }

        // If size is too small to hold uk_header, occasionally force it bigger so we do real calls.
        if ((rnd32() % 3) != 0 && size < sizeof(struct uk_header)) {
            size = (uint32_t)sizeof(struct uk_header);
        }

        memset(buf, 0, sizeof(buf));
        fill_random(buf, size);

        // Choose id; bias to use stateful ids sometimes.
        uint32_t id = pick_u32(ids, sizeof(ids)/sizeof(ids[0]));
        ((struct uk_header*)buf)->id = id;
        ((struct uk_header*)buf)->ret = 0;

        // A little state: sometimes place last_gpu_va into likely fields.
        // This is intentionally “dumb but useful.”
        if (last_gpu_va && size >= 16) {
            if ((rnd32() % 2) == 0) {
                // Put last_gpu_va right after header (common layout: header + u64 addr)
                memcpy(buf + 8, &last_gpu_va, sizeof(last_gpu_va));
            }
        }

        unsigned int cmd = make_cmd(size);

        errno = 0;
        int r = do_ioctl(fd, cmd, buf);
        int e = errno;

        // If we called MEM_ALLOC with enough space, try to harvest gpu_va from the spot your stub writes.
        if (r == 0 && id == KBASE_FUNC_MEM_ALLOC) {
            // In your stub, gpu_va is after: header + 4*u64 = 8 + 32 = 40, then gpu_va at offset 40.
            // That assumes the same layout and enough size.
            if (size >= 48) {
                uint64_t gpu_va = 0;
                memcpy(&gpu_va, buf + 40, sizeof(gpu_va));
                if (gpu_va) last_gpu_va = gpu_va;
            }
        }

        // Print occasional progress and any non-boring results.
        if (r < 0) {
            // EINVAL is common; still log some of them early.
            if (e != EINVAL || (iters < 1000 && (iters % 50 == 0))) {
                fprintf(stderr, "[%llu] ioctl fail r=%d errno=%d(%s) id=%u size=%u cmd=0x%x buf[0:16]=",
                        (unsigned long long)iters, r, e, strerror(e), id, size, cmd);
                hexdump_prefix(buf, size, 16);
                fprintf(stderr, "\n");
            }
        } else {
            // Log “interesting” successes occasionally
            if ((iters % 1000) == 0) {
                fprintf(stderr, "[%llu] ok id=%u size=%u last_gpu_va=0x%llx\n",
                        (unsigned long long)iters, id, size,
                        (unsigned long long)last_gpu_va);
            }
        }

        iters++;
    }

    fprintf(stderr, "[*] Done. iters=%llu last_gpu_va=0x%llx\n",
            (unsigned long long)iters, (unsigned long long)last_gpu_va);

    close(fd);
    return 0;
}