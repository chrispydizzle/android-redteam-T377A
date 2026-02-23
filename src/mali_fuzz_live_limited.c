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

#define DEV_PATH "/dev/mali0"
#define CALL_MAX_SIZE 536

// Function IDs (Samsung/ARM UK)
#define UKP_FUNC_ID_CHECK_VERSION      0
#define KBASE_FUNC_MEM_ALLOC           512
#define KBASE_FUNC_MEM_QUERY           515
#define KBASE_FUNC_MEM_FREE            516
#define KBASE_FUNC_GPU_PROPS_REG_DUMP  526
#define KBASE_FUNC_GET_VERSION         528
#define KBASE_FUNC_SET_FLAGS           530
#define KBASE_FUNC_DISJOINT_QUERY      541
#define KBASE_FUNC_GET_CONTEXT_ID      543

// Query values (commonly used; adjust if your header defines differently)
#define KBASE_MEM_QUERY_COMMIT_SIZE    1ULL

/* --- Real structs from Samsung GPL source --- */

union uk_header {
    uint32_t id;     /* input: function ID */
    uint32_t ret;    /* output: mali error code (0=ok, 3=function_failed) */
    uint64_t sizer;  /* force 8-byte size/alignment */
};

/* sizeof = 16 */
struct uku_version_check_args {
    union uk_header header;
    uint16_t major;
    uint16_t minor;
    uint8_t padding[4];
};

/* sizeof = 16 */
struct kbase_uk_set_flags {
    union uk_header header;
    uint32_t create_flags;
    uint32_t padding;
};

/* sizeof = 80 */
#define KBASE_GET_VERSION_BUFFER_SIZE 64
struct kbase_uk_get_ddk_version {
    union uk_header header;
    char version_buffer[KBASE_GET_VERSION_BUFFER_SIZE];
    uint32_t version_string_size;
    uint32_t padding;
};

/* sizeof = 56 */
struct kbase_uk_mem_alloc {
    union uk_header header;
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extent;
    uint64_t flags;
    uint64_t gpu_va;
    uint16_t va_alignment;
    uint8_t  padding[6];
};

/* sizeof = 16 */
struct kbase_uk_mem_free {
    union uk_header header;
    uint64_t gpu_addr;
};

/* sizeof = 32 */
struct kbase_uk_mem_query {
    union uk_header header;
    uint64_t gpu_addr;
    uint64_t query;
    uint64_t value;
};

/* sizeof = 16 */
struct kbase_uk_context_id {
    union uk_header header;
    int32_t id;
    int32_t padding;
};

/* sizeof = 16 */
struct kbase_uk_disjoint_query {
    union uk_header header;
    uint32_t counter;
    uint32_t padding;
};

/* sizeof = 536 */
#define KBASE_UK_GPUPROPS_SIZE 536

/* ---- Fuzzer plumbing ---- */

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

/* xorshift64 */
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

static unsigned long make_cmd(uint32_t size) {
    // Match your working enum: IOC_TYPE=0x80, IOC_NR=0, DIR=RW
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, size);
}

static void fill_random(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rnd32();
}

static int uk_ioctl(int fd, void *buf, uint32_t size) {
    errno = 0;
    return ioctl(fd, make_cmd(size), buf);
}

static int do_handshake(int fd) {
    struct uku_version_check_args ver;
    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10;
    ver.minor = 0;
    if (uk_ioctl(fd, &ver, (uint32_t)sizeof(ver)) < 0) return -1;
    if (ver.header.ret != 0) return -1;

    struct kbase_uk_set_flags flags;
    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    flags.create_flags = 0;
    if (uk_ioctl(fd, &flags, (uint32_t)sizeof(flags)) < 0) return -1;
    if (flags.header.ret != 0) return -1;

    return 0;
}

/* ---- Tiny allocation table for stateful fuzzing ---- */

#define MAX_ALLOCS 64
struct alloc_entry {
    uint64_t gpu_va;
    uint64_t va_pages;
    uint64_t flags;
    int in_use;
};
static struct alloc_entry g_allocs[MAX_ALLOCS];

// Allocation limiting (in GPU pages).
static uint64_t g_live_pages = 0;
static uint64_t g_max_live_pages = 4096; // configurable via env

// Simple on-disk flight recorder.
static FILE *g_log = NULL;
static int g_log_fd = -1;
static uint64_t g_log_lines = 0;
static uint64_t g_log_fsync_every = 50; // configurable via env

static void log_line(const char *line) {
    if (!g_log) return;
    fputs(line, g_log);
    fputc('\n', g_log);
    g_log_lines++;
    if (g_log_lines % g_log_fsync_every == 0) {
        fflush(g_log);
        if (g_log_fd >= 0) fsync(g_log_fd);
    }
}

static void log_op(const char *op, uint32_t func_id, uint32_t size,
                   int sys_ret, int sys_errno, uint32_t uk_ret,
                   uint64_t aux0, uint64_t aux1) {
    char line[256];
    // aux0/aux1 are op-specific (e.g., gpu_va, pages)
    snprintf(line, sizeof(line),
             "op=%s id=%u size=%u sys_ret=%d errno=%d uk_ret=%u live_pages=%llu aux0=0x%llx aux1=%llu",
             op, func_id, size, sys_ret, sys_errno, uk_ret,
             (unsigned long long)g_live_pages,
             (unsigned long long)aux0,
             (unsigned long long)aux1);
    log_line(line);
}

static void allocs_add(uint64_t gpu_va, uint64_t va_pages, uint64_t flags) {
    if (!gpu_va) return;
    for (int i = 0; i < MAX_ALLOCS; i++) {
        if (!g_allocs[i].in_use) {
            g_allocs[i].in_use = 1;
            g_allocs[i].gpu_va = gpu_va;
            g_allocs[i].va_pages = va_pages;
            g_allocs[i].flags = flags;
            g_live_pages += va_pages;
            return;
        }
    }
    // overwrite a random slot if full
    int j = (int)(rnd32() % MAX_ALLOCS);
    if (g_allocs[j].in_use) {
        // subtract old pages before overwriting
        if (g_live_pages >= g_allocs[j].va_pages) g_live_pages -= g_allocs[j].va_pages;
        else g_live_pages = 0;
    }
    g_allocs[j].in_use = 1;
    g_allocs[j].gpu_va = gpu_va;
    g_allocs[j].va_pages = va_pages;
    g_allocs[j].flags = flags;
    g_live_pages += va_pages;
}

static uint64_t allocs_pick_any(int *out_index) {
    int live[MAX_ALLOCS];
    int n = 0;
    for (int i = 0; i < MAX_ALLOCS; i++) if (g_allocs[i].in_use) live[n++] = i;
    if (n == 0) return 0;
    int idx = live[rnd32() % (uint32_t)n];
    if (out_index) *out_index = idx;
    return g_allocs[idx].gpu_va;
}

static void allocs_free_index(int idx) {
    if (idx >= 0 && idx < MAX_ALLOCS && g_allocs[idx].in_use) {
        if (g_live_pages >= g_allocs[idx].va_pages) g_live_pages -= g_allocs[idx].va_pages;
        else g_live_pages = 0;
        g_allocs[idx].in_use = 0;
    }
}

/* ---- Structured ops ---- */

static void op_get_version(int fd) {
    struct kbase_uk_get_ddk_version v;
    memset(&v, 0, sizeof(v));
    v.header.id = KBASE_FUNC_GET_VERSION;
    v.version_string_size = KBASE_GET_VERSION_BUFFER_SIZE;
    int r = uk_ioctl(fd, &v, (uint32_t)sizeof(v));
    log_op("GET_VERSION", KBASE_FUNC_GET_VERSION, (uint32_t)sizeof(v), r, errno, v.header.ret, 0, 0);
    if (r == 0 && v.header.ret == 0) {
        // keep it light; just touch buffer
        v.version_buffer[KBASE_GET_VERSION_BUFFER_SIZE - 1] = 0;
    }
}

static void op_disjoint_query(int fd) {
    struct kbase_uk_disjoint_query dq;
    memset(&dq, 0, sizeof(dq));
    dq.header.id = KBASE_FUNC_DISJOINT_QUERY;
    int r = uk_ioctl(fd, &dq, (uint32_t)sizeof(dq));
    log_op("DISJOINT_QUERY", KBASE_FUNC_DISJOINT_QUERY, (uint32_t)sizeof(dq), r, errno, dq.header.ret, dq.counter, 0);
}

static void op_get_context_id(int fd) {
    struct kbase_uk_context_id cid;
    memset(&cid, 0, sizeof(cid));
    cid.header.id = KBASE_FUNC_GET_CONTEXT_ID;
    int r = uk_ioctl(fd, &cid, (uint32_t)sizeof(cid));
    log_op("GET_CONTEXT_ID", KBASE_FUNC_GET_CONTEXT_ID, (uint32_t)sizeof(cid), r, errno, cid.header.ret, (uint64_t)(uint32_t)cid.id, 0);
}

static void op_gpu_props(int fd) {
    uint8_t buf[KBASE_UK_GPUPROPS_SIZE];
    memset(buf, 0, sizeof(buf));
    ((union uk_header*)buf)->id = KBASE_FUNC_GPU_PROPS_REG_DUMP;
    int r = uk_ioctl(fd, buf, (uint32_t)sizeof(buf));
    log_op("GPU_PROPS_REG_DUMP", KBASE_FUNC_GPU_PROPS_REG_DUMP, (uint32_t)sizeof(buf), r, errno, ((union uk_header*)buf)->ret, 0, 0);
}

static void op_mem_alloc(int fd) {
    struct kbase_uk_mem_alloc m;
    memset(&m, 0, sizeof(m));
    m.header.id = KBASE_FUNC_MEM_ALLOC;

    // Seed from your known-good flags; then mutate
    const uint64_t base_flags = 0x20fULL;
    uint64_t flags = base_flags;

    // mutate a few bits
    if ((rnd32() % 3) == 0) flags ^= (1ULL << (rnd32() % 16));
    if ((rnd32() % 5) == 0) flags ^= (1ULL << (rnd32() % 32));

    // pages: bias to small/boundary values
    uint64_t choices[] = {0,1,2,15,16,17,32,64,256,1024};
    uint64_t va_pages = choices[rnd32() % (sizeof(choices)/sizeof(choices[0]))];
    if (va_pages == 0) va_pages = 1;

    uint64_t commit_pages = va_pages;
    if ((rnd32() % 4) == 0) commit_pages = 0;
    if ((rnd32() % 8) == 0) commit_pages = va_pages + 1;

    m.va_pages = va_pages;
    m.commit_pages = commit_pages;
    m.extent = 0;
    m.flags = flags;
    m.va_alignment = 0; // keep simple; add mutations later if needed

    // Allocation limiting: avoid runaway memory pressure.
    if (g_live_pages + m.va_pages > g_max_live_pages) {
        log_op("MEM_ALLOC_SKIPPED_CAP", KBASE_FUNC_MEM_ALLOC, (uint32_t)sizeof(m), 0, 0, 0, 0, m.va_pages);
        return;
    }

    int r = uk_ioctl(fd, &m, (uint32_t)sizeof(m));
    log_op("MEM_ALLOC", KBASE_FUNC_MEM_ALLOC, (uint32_t)sizeof(m), r, errno, m.header.ret, m.gpu_va, m.va_pages);
    if (r == 0 && m.header.ret == 0) allocs_add(m.gpu_va, m.va_pages, m.flags);
}

static void op_mem_query(int fd) {
    int idx = -1;
    uint64_t va = allocs_pick_any(&idx);
    if (!va) return;

    struct kbase_uk_mem_query q;
    memset(&q, 0, sizeof(q));
    q.header.id = KBASE_FUNC_MEM_QUERY;
    q.gpu_addr = va;
    q.query = KBASE_MEM_QUERY_COMMIT_SIZE;

    int r = uk_ioctl(fd, &q, (uint32_t)sizeof(q));
    log_op("MEM_QUERY", KBASE_FUNC_MEM_QUERY, (uint32_t)sizeof(q), r, errno, q.header.ret, q.gpu_addr, q.value);
}

static void op_mem_free(int fd) {
    int idx = -1;
    uint64_t va = allocs_pick_any(&idx);
    if (!va) return;

    struct kbase_uk_mem_free f;
    memset(&f, 0, sizeof(f));
    f.header.id = KBASE_FUNC_MEM_FREE;
    f.gpu_addr = va;

    int r = uk_ioctl(fd, &f, (uint32_t)sizeof(f));
    log_op("MEM_FREE", KBASE_FUNC_MEM_FREE, (uint32_t)sizeof(f), r, errno, f.header.ret, f.gpu_addr, 0);
    if (r == 0 && f.header.ret == 0) allocs_free_index(idx);
}

/* ---- Raw “size fuzz” op (keeps your original spirit) ---- */
static void op_raw_size_fuzz(int fd) {
    uint8_t buf[CALL_MAX_SIZE];
    uint32_t size = (uint32_t)(rnd64() % (CALL_MAX_SIZE + 1));
    if (size < sizeof(union uk_header)) size = (uint32_t)sizeof(union uk_header);

    memset(buf, 0, sizeof(buf));
    fill_random(buf, size);

    // Pick an id from the “safe-ish” set to avoid constant EFAULT from pointer-bearing calls
    uint32_t ids[] = {
        KBASE_FUNC_MEM_ALLOC, KBASE_FUNC_MEM_QUERY, KBASE_FUNC_MEM_FREE,
        KBASE_FUNC_GET_VERSION, KBASE_FUNC_GET_CONTEXT_ID, KBASE_FUNC_DISJOINT_QUERY,
        KBASE_FUNC_GPU_PROPS_REG_DUMP
    };
    ((union uk_header*)buf)->id = ids[rnd32() % (sizeof(ids)/sizeof(ids[0]))];

    int r = uk_ioctl(fd, buf, size);
    log_op("RAW_SIZE_FUZZ", ((union uk_header*)buf)->id, size, r, errno, ((union uk_header*)buf)->ret, 0, 0);
}

int main(int argc, char **argv) {
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

    // Config via env vars (no root needed).
    const char *cap_s = getenv("MALI_MAX_LIVE_PAGES");
    if (cap_s && *cap_s) {
        uint64_t v = strtoull(cap_s, NULL, 0);
        if (v > 0) g_max_live_pages = v;
    }
    const char *fsync_s = getenv("MALI_LOG_FSYNC_EVERY");
    if (fsync_s && *fsync_s) {
        uint64_t v = strtoull(fsync_s, NULL, 0);
        if (v > 0) g_log_fsync_every = v;
    }
    const char *log_path = getenv("MALI_LOG_PATH");
    if (!log_path || !*log_path) log_path = "./mali_fuzz.log";

    g_log = fopen(log_path, "a");
    if (g_log) {
        g_log_fd = fileno(g_log);
        setvbuf(g_log, NULL, _IOLBF, 0); // line buffered
        char header[256];
        snprintf(header, sizeof(header),
                 "--- run start seed=0x%llx max_live_pages=%llu fsync_every=%llu ---",
                 (unsigned long long)seed,
                 (unsigned long long)g_max_live_pages,
                 (unsigned long long)g_log_fsync_every);
        log_line(header);
    }

    signal(SIGINT, on_sigint);

    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[-] open(%s) failed: %s\n", DEV_PATH, strerror(errno));
        return 1;
    }
    fprintf(stderr, "[+] Opened %s fd=%d seed=0x%llx\n", DEV_PATH, fd, (unsigned long long)seed);
    if (g_log) {
        char l[128];
        snprintf(l, sizeof(l), "opened fd=%d", fd);
        log_line(l);
    }

    if (do_handshake(fd) != 0) {
        fprintf(stderr, "[-] handshake failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    fprintf(stderr, "[+] Handshake OK\n");
    log_line("handshake ok");

    uint64_t iters = 0;
    while (!g_stop) {
        if (max_iters && iters >= max_iters) break;

        // 2–10 ops per iteration
        int ops = 2 + (rnd32() % 9);

        for (int i = 0; i < ops; i++) {
            uint32_t pick = rnd32() % 100;

            // If we're near/over cap, bias toward frees.
            if (g_live_pages >= g_max_live_pages && pick < 80) pick = 90;

            if (pick < 5)        op_get_version(fd);       // sanity
            else if (pick < 10)  op_get_context_id(fd);
            else if (pick < 15)  op_disjoint_query(fd);
            else if (pick < 20)  op_gpu_props(fd);
            else if (pick < 55)  op_mem_alloc(fd);
            else if (pick < 80)  op_mem_query(fd);
            else if (pick < 95)  op_mem_free(fd);
            else                 op_raw_size_fuzz(fd);      // keep some chaos

            if (g_stop) break;
        }

        if ((iters % 1000) == 0) {
            int live = 0;
            for (int i = 0; i < MAX_ALLOCS; i++) if (g_allocs[i].in_use) live++;
            fprintf(stderr, "[%llu] iter ok (live_allocs=%d)\n",
                    (unsigned long long)iters, live);
        }

        iters++;
    }

    fprintf(stderr, "[*] Done iters=%llu\n", (unsigned long long)iters);
    if (g_log) {
        char footer[128];
        snprintf(footer, sizeof(footer), "--- run end iters=%llu ---", (unsigned long long)iters);
        log_line(footer);
        fflush(g_log);
        if (g_log_fd >= 0) fsync(g_log_fd);
        fclose(g_log);
    }
    close(fd);
    return 0;
}