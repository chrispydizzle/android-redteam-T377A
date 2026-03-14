/*
 * mali_fuzz_full.c — Full-coverage Mali r7p0 ioctl fuzzer
 *
 * Extends mali_fuzz_live_limited.c with:
 *   - All 20+ dispatchable kbase functions (not just 7)
 *   - MEM_FLAGS_CHANGE / MEM_COMMIT on live allocations
 *   - Samsung vendor ioctls (CREATE/DESTROY_SURFACE, MIN_LOCK, SECURE_WORLD)
 *   - Double-free / use-after-free / stale-VA testing
 *   - Context lifecycle (periodic fd re-open)
 *   - MEM_QUERY with all 3 query types + fuzzed addrs
 *   - Fuzzed va_alignment, extent, and commit_pages > va_pages
 *   - Crash self-monitoring (SIGSEGV/SIGBUS recovery)
 *
 * Struct sizes from Samsung GPL source:
 *   github.com/jcadduono/android_kernel_samsung_universal3475
 *   drivers/gpu/arm/t72x/r7p0/mali_kbase_uku.h
 *
 * Build: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -o mali_fuzz_full mali_fuzz_full.c
 * Push:  adb push mali_fuzz_full /data/local/tmp/
 * Run:   adb shell /data/local/tmp/mali_fuzz_full [max_iters] [seed]
 *
 * Environment variables:
 *   MALI_MAX_LIVE_PAGES  — cap on GPU pages (default: 4096)
 *   MALI_LOG_FSYNC_EVERY — fsync interval (default: 50)
 *   MALI_LOG_PATH        — log file path (default: ./mali_fuzz.log)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

#define DEV_PATH "/dev/mali0"
#define CALL_MAX_SIZE 568  /* KBASE_FUNC_MAX - 1 */

/* ===== Function IDs (Samsung/ARM UK protocol) ===== */
#define UK_FUNC_ID                          512
#define UKP_FUNC_ID_CHECK_VERSION           0
#define KBASE_FUNC_MEM_ALLOC                (UK_FUNC_ID + 0)   /* 512 */
#define KBASE_FUNC_MEM_IMPORT               (UK_FUNC_ID + 1)   /* 513 */
#define KBASE_FUNC_MEM_COMMIT               (UK_FUNC_ID + 2)   /* 514 */
#define KBASE_FUNC_MEM_QUERY                (UK_FUNC_ID + 3)   /* 515 */
#define KBASE_FUNC_MEM_FREE                 (UK_FUNC_ID + 4)   /* 516 */
#define KBASE_FUNC_MEM_FLAGS_CHANGE         (UK_FUNC_ID + 5)   /* 517 */
#define KBASE_FUNC_MEM_ALIAS                (UK_FUNC_ID + 6)   /* 518 */
#define KBASE_FUNC_SYNC                     (UK_FUNC_ID + 8)   /* 520 */
#define KBASE_FUNC_POST_TERM                (UK_FUNC_ID + 9)   /* 521 */
#define KBASE_FUNC_HWCNT_SETUP              (UK_FUNC_ID + 10)  /* 522 */
#define KBASE_FUNC_HWCNT_DUMP               (UK_FUNC_ID + 11)  /* 523 */
#define KBASE_FUNC_HWCNT_CLEAR              (UK_FUNC_ID + 12)  /* 524 */
#define KBASE_FUNC_GPU_PROPS_REG_DUMP       (UK_FUNC_ID + 14)  /* 526 */
#define KBASE_FUNC_FIND_CPU_OFFSET          (UK_FUNC_ID + 15)  /* 527 */
#define KBASE_FUNC_GET_VERSION              (UK_FUNC_ID + 16)  /* 528 */
#define KBASE_FUNC_EXT_BUFFER_LOCK          (UK_FUNC_ID + 17)  /* 529 */
#define KBASE_FUNC_SET_FLAGS                (UK_FUNC_ID + 18)  /* 530 */
#define KBASE_FUNC_SET_TEST_DATA            (UK_FUNC_ID + 19)  /* 531 */
#define KBASE_FUNC_INJECT_ERROR             (UK_FUNC_ID + 20)  /* 532 */
#define KBASE_FUNC_MODEL_CONTROL            (UK_FUNC_ID + 21)  /* 533 */
#define KBASE_FUNC_KEEP_GPU_POWERED         (UK_FUNC_ID + 22)  /* 534 */
#define KBASE_FUNC_FENCE_VALIDATE           (UK_FUNC_ID + 23)  /* 535 */
#define KBASE_FUNC_STREAM_CREATE            (UK_FUNC_ID + 24)  /* 536 */
#define KBASE_FUNC_GET_PROFILING_CONTROLS   (UK_FUNC_ID + 25)  /* 537 */
#define KBASE_FUNC_SET_PROFILING_CONTROLS   (UK_FUNC_ID + 26)  /* 538 */
#define KBASE_FUNC_DEBUGFS_MEM_PROFILE_ADD  (UK_FUNC_ID + 27)  /* 539 */
#define KBASE_FUNC_JOB_SUBMIT               (UK_FUNC_ID + 28)  /* 540 */
#define KBASE_FUNC_DISJOINT_QUERY           (UK_FUNC_ID + 29)  /* 541 */
#define KBASE_FUNC_GET_CONTEXT_ID           (UK_FUNC_ID + 31)  /* 543 */
#define KBASE_FUNC_TLSTREAM_ACQUIRE         (UK_FUNC_ID + 32)  /* 544 */
#define KBASE_FUNC_TLSTREAM_TEST            (UK_FUNC_ID + 33)  /* 545 */
#define KBASE_FUNC_TLSTREAM_STATS           (UK_FUNC_ID + 34)  /* 546 */
#define KBASE_FUNC_TLSTREAM_FLUSH           (UK_FUNC_ID + 35)  /* 547 */
#define KBASE_FUNC_HWCNT_READER_SETUP       (UK_FUNC_ID + 36)  /* 548 */
/* Samsung vendor functions (dispatched via gpu_vendor_dispatch).
 * These are auto-numbered in the enum after HWCNT_READER_SETUP = UK_FUNC_ID+36. */
#define KBASE_FUNC_HWCNT_UTIL_SETUP         549  /* UK_FUNC_ID + 37 */
#define KBASE_FUNC_HWCNT_GPR_DUMP           550
#define KBASE_FUNC_VSYNC_SKIP               551
#define KBASE_FUNC_CREATE_SURFACE           552
#define KBASE_FUNC_DESTROY_SURFACE          553
#define KBASE_FUNC_SET_MIN_LOCK             554
#define KBASE_FUNC_UNSET_MIN_LOCK           555
#define KBASE_FUNC_TMU_SKIP                 556
#define KBASE_FUNC_SECURE_WORLD_RENDERING   (UK_FUNC_ID + 55)  /* 567 */
#define KBASE_FUNC_NON_SECURE_WORLD_RENDERING (UK_FUNC_ID + 56)/* 568 */

/* Memory query types */
#define KBASE_MEM_QUERY_COMMIT_SIZE  1
#define KBASE_MEM_QUERY_VA_SIZE      2
#define KBASE_MEM_QUERY_FLAGS        3

/* Memory flags (from mali_base_kernel.h) */
#define BASE_MEM_PROT_CPU_RD    (1ULL << 0)
#define BASE_MEM_PROT_CPU_WR    (1ULL << 1)
#define BASE_MEM_PROT_GPU_RD    (1ULL << 2)
#define BASE_MEM_PROT_GPU_WR    (1ULL << 3)
#define BASE_MEM_GROW_ON_GPF    (1ULL << 9)
#define BASE_MEM_SAME_VA        (1ULL << 9)
#define BASE_MEM_COHERENT_SYSTEM (1ULL << 10)
#define BASE_MEM_COHERENT_LOCAL  (1ULL << 11)
#define BASE_MEM_CACHED_CPU      (1ULL << 12)
#define BASE_MEM_SECURE          (1ULL << 14)

/* ===== Struct definitions (from Samsung GPL source) ===== */

union uk_header {
    uint32_t id;
    uint32_t ret;
    uint64_t sizer;
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

/* sizeof = 32 */
struct kbase_uk_mem_flags_change {
    union uk_header header;
    uint64_t gpu_va;
    uint64_t flags;
    uint64_t mask;
};

/* sizeof = 32 */
struct kbase_uk_mem_commit {
    union uk_header header;
    uint64_t gpu_addr;
    uint64_t pages;
    uint32_t result_subcode;
    uint32_t padding;
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

/* sizeof = 40 */
struct kbase_uk_hwcnt_setup {
    union uk_header header;
    uint64_t dump_buffer;
    uint32_t jm_bm;
    uint32_t shader_bm;
    uint32_t tiler_bm;
    uint32_t unused_1;
    uint32_t mmu_l2_bm;
    uint32_t padding;
};

/* sizeof = 32 (Samsung SYSTRACE addition) */
struct kbase_uk_job_submit {
    union uk_header header;
    uint64_t addr_sizer;
    uint32_t nr_atoms;
    uint32_t stride;
    uint32_t gles_ctx_handle;
    uint32_t padding;
};

/* sizeof = 40 */
struct kbase_uk_find_cpu_offset {
    union uk_header header;
    uint64_t gpu_addr;
    uint64_t cpu_addr;
    uint64_t size;
    uint64_t offset;
};

/* sizeof = 48 */
struct kbase_uk_stream_create {
    union uk_header header;
    char name[32];
    int32_t fd;
    uint32_t padding;
};

/* sizeof = 16 */
struct kbase_uk_keep_gpu_powered {
    union uk_header header;
    uint32_t enabled;
    uint32_t padding;
};

/* sizeof = 16 */
struct kbase_uk_tlstream_acquire {
    union uk_header header;
    int32_t fd;
    int32_t padding;
};

/* sizeof = 32 */
#define FBDUMP_CONTROL_MAX 5
struct kbase_uk_profiling_controls {
    union uk_header header;
    uint32_t profiling_controls[FBDUMP_CONTROL_MAX];
    uint32_t padding;
};

/* sizeof = 536 — GPU property tree */
#define KBASE_UK_GPUPROPS_SIZE 536

/* sizeof = 24 — Samsung vendor custom command */
struct kbase_uk_custom_command {
    union uk_header header;
    uint32_t enabled;
    uint32_t padding;
    uint64_t flags;
};

/* sizeof = 40 — sync (basep_syncset = {u64 handle, u64 user_addr, u64 size, u8 type, u8 pad[7]}) */
struct kbase_uk_sync_now {
    union uk_header header;
    uint64_t mem_handle;
    uint64_t user_addr;
    uint64_t size;
    uint8_t  type;
    uint8_t  padding[7];
};

/* sizeof = 48 */
struct kbase_uk_mem_import {
    union uk_header header;
    uint64_t phandle_sizer;
    uint32_t type;
    uint32_t padding;
    uint64_t flags;
    uint64_t gpu_va;
    uint64_t va_pages;
};

/* ===== PRNG (xorshift64) ===== */

static uint64_t rng_state = 0x123456789abcdef0ULL;
static uint64_t rnd64(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return x;
}
static uint32_t rnd32(void) { return (uint32_t)rnd64(); }

static void fill_random(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rnd32();
}

/* ===== Signal recovery ===== */

static sigjmp_buf g_jmpbuf;
static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_in_ioctl = 0;
static volatile int g_crash_sig = 0;

static void on_sigint(int sig) { (void)sig; g_stop = 1; }
static void on_crash(int sig) {
    g_crash_sig = sig;
    if (g_in_ioctl) siglongjmp(g_jmpbuf, 1);
    _exit(128 + sig);
}

/* ===== Ioctl helpers ===== */

static unsigned long make_cmd(uint32_t size) {
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, size);
}

static int uk_ioctl(int fd, void *buf, uint32_t size) {
    errno = 0;
    return ioctl(fd, make_cmd(size), buf);
}

/* Protected ioctl — recovers from SIGSEGV/SIGBUS */
static int uk_ioctl_safe(int fd, void *buf, uint32_t size) {
    int ret;
    g_crash_sig = 0;
    g_in_ioctl = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_ioctl = 0;
        errno = EFAULT;
        return -1;
    }
    ret = uk_ioctl(fd, buf, size);
    g_in_ioctl = 0;
    return ret;
}

static int do_handshake(int fd) {
    struct uku_version_check_args ver;
    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10; ver.minor = 0;
    if (uk_ioctl(fd, &ver, sizeof(ver)) < 0) return -1;
    if (ver.header.ret != 0) return -1;

    struct kbase_uk_set_flags flags;
    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    flags.create_flags = 0;
    if (uk_ioctl(fd, &flags, sizeof(flags)) < 0) return -1;
    if (flags.header.ret != 0) return -1;

    return 0;
}

/* ===== Allocation table ===== */

#define MAX_ALLOCS 128
struct alloc_entry {
    uint64_t gpu_va;
    uint64_t va_pages;
    uint64_t flags;
    int in_use;
    int freed;  /* for UAF testing: freed but not removed from table */
};
static struct alloc_entry g_allocs[MAX_ALLOCS];

static uint64_t g_live_pages = 0;
static uint64_t g_max_live_pages = 4096;

/* Stats */
static uint64_t g_stat_ops = 0;
static uint64_t g_stat_crashes = 0;
static uint64_t g_stat_uaf = 0;
static uint64_t g_stat_double_free = 0;

/* ===== Logging ===== */

static FILE *g_log = NULL;
static int g_log_fd = -1;
static uint64_t g_log_lines = 0;
static uint64_t g_log_fsync_every = 50;

static void log_line(const char *line) {
    if (!g_log) return;
    fputs(line, g_log); fputc('\n', g_log);
    g_log_lines++;
    if (g_log_lines % g_log_fsync_every == 0) {
        fflush(g_log);
        if (g_log_fd >= 0) fsync(g_log_fd);
    }
}

static void log_op(const char *op, uint32_t func_id, uint32_t size,
                   int sys_ret, int sys_errno, uint32_t uk_ret,
                   uint64_t aux0, uint64_t aux1) {
    char line[320];
    snprintf(line, sizeof(line),
             "op=%s id=%u sz=%u ret=%d e=%d uk=%u lp=%llu a0=0x%llx a1=%llu",
             op, func_id, size, sys_ret, sys_errno, uk_ret,
             (unsigned long long)g_live_pages,
             (unsigned long long)aux0, (unsigned long long)aux1);
    log_line(line);
}

/* ===== Allocation management ===== */

static void allocs_add(uint64_t gpu_va, uint64_t va_pages, uint64_t flags) {
    if (!gpu_va) return;
    for (int i = 0; i < MAX_ALLOCS; i++) {
        if (!g_allocs[i].in_use) {
            g_allocs[i] = (struct alloc_entry){gpu_va, va_pages, flags, 1, 0};
            g_live_pages += va_pages;
            return;
        }
    }
    int j = (int)(rnd32() % MAX_ALLOCS);
    if (g_allocs[j].in_use && !g_allocs[j].freed) {
        if (g_live_pages >= g_allocs[j].va_pages) g_live_pages -= g_allocs[j].va_pages;
        else g_live_pages = 0;
    }
    g_allocs[j] = (struct alloc_entry){gpu_va, va_pages, flags, 1, 0};
    g_live_pages += va_pages;
}

static uint64_t allocs_pick_live(int *out_idx) {
    int live[MAX_ALLOCS], n = 0;
    for (int i = 0; i < MAX_ALLOCS; i++)
        if (g_allocs[i].in_use && !g_allocs[i].freed) live[n++] = i;
    if (n == 0) return 0;
    int idx = live[rnd32() % (uint32_t)n];
    if (out_idx) *out_idx = idx;
    return g_allocs[idx].gpu_va;
}

static uint64_t allocs_pick_any(int *out_idx) {
    int used[MAX_ALLOCS], n = 0;
    for (int i = 0; i < MAX_ALLOCS; i++)
        if (g_allocs[i].in_use) used[n++] = i;
    if (n == 0) return 0;
    int idx = used[rnd32() % (uint32_t)n];
    if (out_idx) *out_idx = idx;
    return g_allocs[idx].gpu_va;
}

static void allocs_mark_freed(int idx) {
    if (idx >= 0 && idx < MAX_ALLOCS && g_allocs[idx].in_use) {
        if (!g_allocs[idx].freed) {
            if (g_live_pages >= g_allocs[idx].va_pages) g_live_pages -= g_allocs[idx].va_pages;
            else g_live_pages = 0;
        }
        g_allocs[idx].freed = 1;
    }
}

static void allocs_remove(int idx) {
    if (idx >= 0 && idx < MAX_ALLOCS) {
        if (g_allocs[idx].in_use && !g_allocs[idx].freed) {
            if (g_live_pages >= g_allocs[idx].va_pages) g_live_pages -= g_allocs[idx].va_pages;
            else g_live_pages = 0;
        }
        g_allocs[idx].in_use = 0;
        g_allocs[idx].freed = 0;
    }
}

/* ===== Op implementations ===== */

static void op_get_version(int fd) {
    struct kbase_uk_get_ddk_version v;
    memset(&v, 0, sizeof(v));
    v.header.id = KBASE_FUNC_GET_VERSION;
    int r = uk_ioctl(fd, &v, sizeof(v));
    log_op("GET_VERSION", KBASE_FUNC_GET_VERSION, sizeof(v), r, errno, v.header.ret, 0, 0);
    g_stat_ops++;
}

static void op_disjoint_query(int fd) {
    struct kbase_uk_disjoint_query dq;
    memset(&dq, 0, sizeof(dq));
    dq.header.id = KBASE_FUNC_DISJOINT_QUERY;
    int r = uk_ioctl(fd, &dq, sizeof(dq));
    log_op("DISJOINT_QUERY", KBASE_FUNC_DISJOINT_QUERY, sizeof(dq), r, errno, dq.header.ret, dq.counter, 0);
    g_stat_ops++;
}

static void op_get_context_id(int fd) {
    struct kbase_uk_context_id cid;
    memset(&cid, 0, sizeof(cid));
    cid.header.id = KBASE_FUNC_GET_CONTEXT_ID;
    int r = uk_ioctl(fd, &cid, sizeof(cid));
    log_op("GET_CONTEXT_ID", KBASE_FUNC_GET_CONTEXT_ID, sizeof(cid), r, errno, cid.header.ret, (uint64_t)(uint32_t)cid.id, 0);
    g_stat_ops++;
}

static void op_gpu_props(int fd) {
    uint8_t buf[KBASE_UK_GPUPROPS_SIZE];
    memset(buf, 0, sizeof(buf));
    ((union uk_header*)buf)->id = KBASE_FUNC_GPU_PROPS_REG_DUMP;
    int r = uk_ioctl(fd, buf, sizeof(buf));
    log_op("GPU_PROPS", KBASE_FUNC_GPU_PROPS_REG_DUMP, sizeof(buf), r, errno, ((union uk_header*)buf)->ret, 0, 0);
    g_stat_ops++;
}

static void op_mem_alloc(int fd) {
    struct kbase_uk_mem_alloc m;
    memset(&m, 0, sizeof(m));
    m.header.id = KBASE_FUNC_MEM_ALLOC;

    /* Base flags with mutation */
    uint64_t flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                     BASE_MEM_SAME_VA;
    if (rnd32() % 3 == 0) flags ^= (1ULL << (rnd32() % 16));
    if (rnd32() % 5 == 0) flags ^= (1ULL << (rnd32() % 32));
    if (rnd32() % 10 == 0) flags |= BASE_MEM_CACHED_CPU;
    if (rnd32() % 20 == 0) flags |= BASE_MEM_COHERENT_LOCAL;

    uint64_t page_choices[] = {1, 2, 15, 16, 17, 32, 64, 128, 256, 1024};
    m.va_pages = page_choices[rnd32() % 10];
    m.commit_pages = m.va_pages;

    /* Interesting mutations */
    uint32_t mut = rnd32() % 20;
    if (mut == 0) m.commit_pages = 0;
    if (mut == 1) m.commit_pages = m.va_pages + 1;  /* commit > va */
    if (mut == 2) m.extent = rnd32() % 64;
    if (mut == 3) m.va_alignment = (uint16_t)(rnd32() % 16);
    if (mut == 4) m.va_pages = 0;  /* zero-page alloc */
    if (mut == 5) { m.va_pages = 0xFFFFFFFF; m.commit_pages = 1; } /* huge va */
    if (mut == 6) flags = 0;  /* bad flags (known to fail) */
    if (mut == 7) flags = 0xFFFFFFFFFFFFFFFFULL;  /* all flags set */

    m.flags = flags;

    if (g_live_pages + m.va_pages > g_max_live_pages && m.va_pages < 0x10000) {
        log_op("MEM_ALLOC_CAP", KBASE_FUNC_MEM_ALLOC, sizeof(m), 0, 0, 0, 0, m.va_pages);
        return;
    }

    int r = uk_ioctl(fd, &m, sizeof(m));
    log_op("MEM_ALLOC", KBASE_FUNC_MEM_ALLOC, sizeof(m), r, errno, m.header.ret, m.gpu_va, m.va_pages);
    if (r == 0 && m.header.ret == 0 && m.gpu_va != 0)
        allocs_add(m.gpu_va, m.va_pages, m.flags);
    g_stat_ops++;
}

static void op_mem_query(int fd) {
    int idx = -1;
    uint64_t va;

    /* Sometimes query freed/stale addresses */
    if (rnd32() % 5 == 0)
        va = allocs_pick_any(&idx);
    else
        va = allocs_pick_live(&idx);
    if (!va) return;

    struct kbase_uk_mem_query q;
    memset(&q, 0, sizeof(q));
    q.header.id = KBASE_FUNC_MEM_QUERY;
    q.gpu_addr = va;

    /* Vary query type */
    uint32_t qt = rnd32() % 6;
    if (qt < 2) q.query = KBASE_MEM_QUERY_COMMIT_SIZE;
    else if (qt < 4) q.query = KBASE_MEM_QUERY_VA_SIZE;
    else if (qt == 4) q.query = KBASE_MEM_QUERY_FLAGS;
    else q.query = rnd32() % 10;  /* invalid query type */

    /* Sometimes fuzz the address */
    if (rnd32() % 10 == 0) q.gpu_addr ^= (uint64_t)(rnd32() % 0x10000);

    int r = uk_ioctl(fd, &q, sizeof(q));
    const char *tag = (idx >= 0 && g_allocs[idx].freed) ? "MEM_QUERY_UAF" : "MEM_QUERY";
    if (idx >= 0 && g_allocs[idx].freed) g_stat_uaf++;
    log_op(tag, KBASE_FUNC_MEM_QUERY, sizeof(q), r, errno, q.header.ret, q.gpu_addr, q.value);
    g_stat_ops++;
}

static void op_mem_free(int fd) {
    int idx = -1;
    uint64_t va;

    /* Sometimes double-free */
    if (rnd32() % 8 == 0)
        va = allocs_pick_any(&idx);
    else
        va = allocs_pick_live(&idx);
    if (!va) return;

    struct kbase_uk_mem_free f;
    memset(&f, 0, sizeof(f));
    f.header.id = KBASE_FUNC_MEM_FREE;
    f.gpu_addr = va;

    /* Fuzz address sometimes */
    if (rnd32() % 15 == 0) f.gpu_addr ^= (uint64_t)(rnd32() % 0x1000);

    int r = uk_ioctl(fd, &f, sizeof(f));
    const char *tag = (idx >= 0 && g_allocs[idx].freed) ? "MEM_FREE_DOUBLE" : "MEM_FREE";
    if (idx >= 0 && g_allocs[idx].freed) g_stat_double_free++;
    log_op(tag, KBASE_FUNC_MEM_FREE, sizeof(f), r, errno, f.header.ret, f.gpu_addr, 0);

    if (r == 0 && f.header.ret == 0) {
        if (idx >= 0) {
            /* Keep ~20% as "freed but tracked" for UAF testing */
            if (rnd32() % 5 == 0)
                allocs_mark_freed(idx);
            else
                allocs_remove(idx);
        }
    }
    g_stat_ops++;
}

static void op_mem_flags_change(int fd) {
    int idx = -1;
    uint64_t va = allocs_pick_live(&idx);
    if (!va) return;

    struct kbase_uk_mem_flags_change fc;
    memset(&fc, 0, sizeof(fc));
    fc.header.id = KBASE_FUNC_MEM_FLAGS_CHANGE;
    fc.gpu_va = va;

    /* Try toggling individual protection flags */
    uint32_t pick = rnd32() % 5;
    if (pick == 0) { fc.flags = BASE_MEM_PROT_CPU_RD; fc.mask = BASE_MEM_PROT_CPU_RD; }
    else if (pick == 1) { fc.flags = 0; fc.mask = BASE_MEM_PROT_CPU_WR; }
    else if (pick == 2) { fc.flags = BASE_MEM_PROT_GPU_WR; fc.mask = BASE_MEM_PROT_GPU_WR; }
    else if (pick == 3) { fc.mask = 0xFFFFFFFF; fc.flags = rnd32(); }  /* wild */
    else { fc.mask = rnd64(); fc.flags = rnd64(); }

    int r = uk_ioctl(fd, &fc, sizeof(fc));
    log_op("MEM_FLAGS_CHANGE", KBASE_FUNC_MEM_FLAGS_CHANGE, sizeof(fc), r, errno, fc.header.ret, va, fc.flags);
    g_stat_ops++;
}

static void op_mem_commit(int fd) {
    int idx = -1;
    uint64_t va = allocs_pick_live(&idx);
    if (!va) return;

    struct kbase_uk_mem_commit mc;
    memset(&mc, 0, sizeof(mc));
    mc.header.id = KBASE_FUNC_MEM_COMMIT;
    mc.gpu_addr = va;

    uint32_t pick = rnd32() % 4;
    if (pick == 0) mc.pages = 0;
    else if (pick == 1) mc.pages = 1;
    else if (pick == 2) mc.pages = g_allocs[idx].va_pages + 1;  /* over-commit */
    else mc.pages = rnd32() % 1024;

    int r = uk_ioctl(fd, &mc, sizeof(mc));
    log_op("MEM_COMMIT", KBASE_FUNC_MEM_COMMIT, sizeof(mc), r, errno, mc.header.ret, va, mc.pages);
    g_stat_ops++;
}

static void op_find_cpu_offset(int fd) {
    int idx = -1;
    uint64_t va = allocs_pick_live(&idx);
    if (!va) return;

    struct kbase_uk_find_cpu_offset fco;
    memset(&fco, 0, sizeof(fco));
    fco.header.id = KBASE_FUNC_FIND_CPU_OFFSET;
    fco.gpu_addr = va;
    fco.cpu_addr = 0x10000;
    fco.size = 0x1000;

    int r = uk_ioctl(fd, &fco, sizeof(fco));
    log_op("FIND_CPU_OFFSET", KBASE_FUNC_FIND_CPU_OFFSET, sizeof(fco), r, errno, fco.header.ret, va, fco.offset);
    g_stat_ops++;
}

static void op_sync(int fd) {
    struct kbase_uk_sync_now sn;
    memset(&sn, 0, sizeof(sn));
    sn.header.id = KBASE_FUNC_SYNC;
    sn.type = (uint8_t)(rnd32() % 4);

    /* Sometimes use a live allocation's VA */
    int idx = -1;
    uint64_t va = allocs_pick_live(&idx);
    if (va) sn.mem_handle = va;

    int r = uk_ioctl_safe(fd, &sn, sizeof(sn));
    log_op("SYNC", KBASE_FUNC_SYNC, sizeof(sn), r, errno, sn.header.ret, sn.mem_handle, sn.type);
    if (g_crash_sig) { g_stat_crashes++; log_line("!CRASH in SYNC"); }
    g_stat_ops++;
}

static void op_stream_create(int fd) {
    struct kbase_uk_stream_create sc;
    memset(&sc, 0, sizeof(sc));
    sc.header.id = KBASE_FUNC_STREAM_CREATE;
    snprintf(sc.name, sizeof(sc.name), "fuzz_%u", rnd32() % 1000);

    int r = uk_ioctl(fd, &sc, sizeof(sc));
    log_op("STREAM_CREATE", KBASE_FUNC_STREAM_CREATE, sizeof(sc), r, errno, sc.header.ret, (uint64_t)sc.fd, 0);
    /* Close returned fd to avoid leak */
    if (r == 0 && sc.header.ret == 0 && sc.fd >= 0) close(sc.fd);
    g_stat_ops++;
}

static void op_keep_gpu_powered(int fd) {
    struct kbase_uk_keep_gpu_powered kgp;
    memset(&kgp, 0, sizeof(kgp));
    kgp.header.id = KBASE_FUNC_KEEP_GPU_POWERED;
    kgp.enabled = rnd32() % 2;
    int r = uk_ioctl(fd, &kgp, sizeof(kgp));
    log_op("KEEP_GPU_POWERED", KBASE_FUNC_KEEP_GPU_POWERED, sizeof(kgp), r, errno, kgp.header.ret, kgp.enabled, 0);
    g_stat_ops++;
}

static void op_profiling_controls(int fd) {
    struct kbase_uk_profiling_controls pc;
    memset(&pc, 0, sizeof(pc));
    /* Try both GET and SET */
    uint32_t func = (rnd32() % 2) ? KBASE_FUNC_GET_PROFILING_CONTROLS : KBASE_FUNC_SET_PROFILING_CONTROLS;
    pc.header.id = func;
    if (func == KBASE_FUNC_SET_PROFILING_CONTROLS) {
        for (int i = 0; i < FBDUMP_CONTROL_MAX; i++)
            pc.profiling_controls[i] = rnd32();
    }
    int r = uk_ioctl(fd, &pc, sizeof(pc));
    log_op("PROFILING_CTRL", func, sizeof(pc), r, errno, pc.header.ret, 0, 0);
    g_stat_ops++;
}

static void op_tlstream_acquire(int fd) {
    struct kbase_uk_tlstream_acquire ta;
    memset(&ta, 0, sizeof(ta));
    ta.header.id = KBASE_FUNC_TLSTREAM_ACQUIRE;
    int r = uk_ioctl(fd, &ta, sizeof(ta));
    log_op("TLSTREAM_ACQUIRE", KBASE_FUNC_TLSTREAM_ACQUIRE, sizeof(ta), r, errno, ta.header.ret, (uint64_t)ta.fd, 0);
    if (r == 0 && ta.header.ret == 0 && ta.fd >= 0) close(ta.fd);
    g_stat_ops++;
}

static void op_hwcnt_setup(int fd) {
    struct kbase_uk_hwcnt_setup hs;
    memset(&hs, 0, sizeof(hs));
    hs.header.id = KBASE_FUNC_HWCNT_SETUP;
    /* Fuzz bitmasks */
    hs.jm_bm = rnd32();
    hs.shader_bm = rnd32();
    hs.tiler_bm = rnd32();
    hs.mmu_l2_bm = rnd32();
    int r = uk_ioctl(fd, &hs, sizeof(hs));
    log_op("HWCNT_SETUP", KBASE_FUNC_HWCNT_SETUP, sizeof(hs), r, errno, hs.header.ret, 0, 0);
    g_stat_ops++;
}

static void op_job_submit(int fd) {
    struct kbase_uk_job_submit js;
    memset(&js, 0, sizeof(js));
    js.header.id = KBASE_FUNC_JOB_SUBMIT;
    js.nr_atoms = rnd32() % 4;
    js.stride = rnd32() % 256;
    int r = uk_ioctl_safe(fd, &js, sizeof(js));
    log_op("JOB_SUBMIT", KBASE_FUNC_JOB_SUBMIT, sizeof(js), r, errno, js.header.ret, 0, js.nr_atoms);
    if (g_crash_sig) { g_stat_crashes++; log_line("!CRASH in JOB_SUBMIT"); }
    g_stat_ops++;
}

/* Samsung vendor functions */
static void op_vendor_surface(int fd) {
    struct kbase_uk_custom_command cc;
    memset(&cc, 0, sizeof(cc));
    /* Alternate between create and destroy */
    cc.header.id = (rnd32() % 2) ? KBASE_FUNC_CREATE_SURFACE : KBASE_FUNC_DESTROY_SURFACE;
    int r = uk_ioctl(fd, &cc, sizeof(cc));
    const char *tag = (cc.header.id == KBASE_FUNC_CREATE_SURFACE) ? "CREATE_SURFACE" : "DESTROY_SURFACE";
    log_op(tag, cc.header.id, sizeof(cc), r, errno, cc.header.ret, 0, 0);
    g_stat_ops++;
}

static void op_vendor_min_lock(int fd) {
    struct kbase_uk_custom_command cc;
    memset(&cc, 0, sizeof(cc));
    cc.header.id = (rnd32() % 2) ? KBASE_FUNC_SET_MIN_LOCK : KBASE_FUNC_UNSET_MIN_LOCK;
    cc.padding = rnd32() % 800;  /* padding field is used as min freq by SET_MIN_LOCK */
    int r = uk_ioctl(fd, &cc, sizeof(cc));
    const char *tag = (cc.header.id == KBASE_FUNC_SET_MIN_LOCK) ? "SET_MIN_LOCK" : "UNSET_MIN_LOCK";
    log_op(tag, cc.header.id, sizeof(cc), r, errno, cc.header.ret, cc.padding, 0);
    g_stat_ops++;
}

/* Raw chaos: random func_id + random size + random payload */
static void op_raw_fuzz(int fd) {
    uint8_t buf[CALL_MAX_SIZE];
    uint32_t size = (uint32_t)(rnd64() % (CALL_MAX_SIZE + 1));
    if (size < sizeof(union uk_header)) size = sizeof(union uk_header);

    memset(buf, 0, sizeof(buf));
    fill_random(buf, size);

    /* Use ALL known func IDs, not just "safe" ones */
    uint32_t all_ids[] = {
        UKP_FUNC_ID_CHECK_VERSION,
        KBASE_FUNC_MEM_ALLOC, KBASE_FUNC_MEM_IMPORT, KBASE_FUNC_MEM_COMMIT,
        KBASE_FUNC_MEM_QUERY, KBASE_FUNC_MEM_FREE, KBASE_FUNC_MEM_FLAGS_CHANGE,
        KBASE_FUNC_MEM_ALIAS, KBASE_FUNC_SYNC, KBASE_FUNC_POST_TERM,
        KBASE_FUNC_HWCNT_SETUP, KBASE_FUNC_HWCNT_DUMP, KBASE_FUNC_HWCNT_CLEAR,
        KBASE_FUNC_GPU_PROPS_REG_DUMP, KBASE_FUNC_FIND_CPU_OFFSET,
        KBASE_FUNC_GET_VERSION, KBASE_FUNC_SET_FLAGS,
        KBASE_FUNC_KEEP_GPU_POWERED, KBASE_FUNC_FENCE_VALIDATE,
        KBASE_FUNC_STREAM_CREATE, KBASE_FUNC_GET_PROFILING_CONTROLS,
        KBASE_FUNC_SET_PROFILING_CONTROLS, KBASE_FUNC_JOB_SUBMIT,
        KBASE_FUNC_DISJOINT_QUERY, KBASE_FUNC_GET_CONTEXT_ID,
        KBASE_FUNC_TLSTREAM_ACQUIRE, KBASE_FUNC_TLSTREAM_FLUSH,
        KBASE_FUNC_CREATE_SURFACE, KBASE_FUNC_DESTROY_SURFACE,
        KBASE_FUNC_SET_MIN_LOCK, KBASE_FUNC_UNSET_MIN_LOCK,
        KBASE_FUNC_SECURE_WORLD_RENDERING, KBASE_FUNC_NON_SECURE_WORLD_RENDERING,
        999  /* totally unknown ID */
    };
    ((union uk_header*)buf)->id = all_ids[rnd32() % (sizeof(all_ids)/sizeof(all_ids[0]))];

    int r = uk_ioctl_safe(fd, buf, size);
    log_op("RAW_FUZZ", ((union uk_header*)buf)->id, size, r, errno, ((union uk_header*)buf)->ret, 0, 0);
    if (g_crash_sig) { g_stat_crashes++; log_line("!CRASH in RAW_FUZZ"); }
    g_stat_ops++;
}

/* Context lifecycle: close and re-open fd */
static int op_reopen(int fd) {
    close(fd);
    /* Brief sleep to let kernel clean up */
    usleep(1000);
    int nfd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (nfd < 0) {
        log_line("!REOPEN_FAILED");
        return -1;
    }
    if (do_handshake(nfd) != 0) {
        log_line("!REOPEN_HANDSHAKE_FAILED");
        close(nfd);
        return -1;
    }
    /* Clear alloc table — old allocations are gone */
    memset(g_allocs, 0, sizeof(g_allocs));
    g_live_pages = 0;
    char buf[64];
    snprintf(buf, sizeof(buf), "REOPEN fd=%d", nfd);
    log_line(buf);
    g_stat_ops++;
    return nfd;
}

/* ===== Main loop ===== */

int main(int argc, char **argv) {
    uint64_t max_iters = 0;
    uint64_t seed = 0;

    if (argc >= 2) max_iters = strtoull(argv[1], NULL, 0);
    if (argc >= 3) seed = strtoull(argv[2], NULL, 0);

    if (seed == 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        seed = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec;
    }
    rng_state = seed;

    /* Config from env */
    const char *s;
    if ((s = getenv("MALI_MAX_LIVE_PAGES")) && *s) {
        uint64_t v = strtoull(s, NULL, 0);
        if (v > 0) g_max_live_pages = v;
    }
    if ((s = getenv("MALI_LOG_FSYNC_EVERY")) && *s) {
        uint64_t v = strtoull(s, NULL, 0);
        if (v > 0) g_log_fsync_every = v;
    }
    const char *log_path = getenv("MALI_LOG_PATH");
    if (!log_path || !*log_path) log_path = "./mali_fuzz_full.log";

    g_log = fopen(log_path, "a");
    if (g_log) {
        g_log_fd = fileno(g_log);
        setvbuf(g_log, NULL, _IOLBF, 0);
        char header[256];
        snprintf(header, sizeof(header),
                 "--- start seed=0x%llx max_pages=%llu fsync=%llu ---",
                 (unsigned long long)seed,
                 (unsigned long long)g_max_live_pages,
                 (unsigned long long)g_log_fsync_every);
        log_line(header);
    }

    signal(SIGINT, on_sigint);
    signal(SIGSEGV, on_crash);
    signal(SIGBUS, on_crash);

    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[-] open(%s): %s\n", DEV_PATH, strerror(errno));
        return 1;
    }
    fprintf(stderr, "[+] %s fd=%d seed=0x%llx\n", DEV_PATH, fd, (unsigned long long)seed);

    if (do_handshake(fd) != 0) {
        fprintf(stderr, "[-] handshake failed\n");
        close(fd);
        return 1;
    }
    fprintf(stderr, "[+] Handshake OK (max_pages=%llu)\n", (unsigned long long)g_max_live_pages);
    log_line("handshake ok");

    uint64_t iters = 0;
    while (!g_stop) {
        if (max_iters && iters >= max_iters) break;

        int ops = 2 + (rnd32() % 9);
        for (int i = 0; i < ops && !g_stop; i++) {
            uint32_t pick = rnd32() % 200;

            /* Bias toward frees when near cap */
            if (g_live_pages >= g_max_live_pages && pick < 150) pick = 150;

            if      (pick < 3)   op_get_version(fd);
            else if (pick < 6)   op_get_context_id(fd);
            else if (pick < 9)   op_disjoint_query(fd);
            else if (pick < 12)  op_gpu_props(fd);
            else if (pick < 50)  op_mem_alloc(fd);
            else if (pick < 85)  op_mem_query(fd);
            else if (pick < 105) op_mem_free(fd);
            else if (pick < 120) op_mem_flags_change(fd);
            else if (pick < 130) op_mem_commit(fd);
            else if (pick < 135) op_find_cpu_offset(fd);
            else if (pick < 140) op_sync(fd);
            else if (pick < 145) op_stream_create(fd);
            else if (pick < 150) op_keep_gpu_powered(fd);
            else if (pick < 155) op_profiling_controls(fd);
            else if (pick < 160) op_hwcnt_setup(fd);
            else if (pick < 165) op_job_submit(fd);
            else if (pick < 170) op_tlstream_acquire(fd);
            else if (pick < 175) op_vendor_surface(fd);
            else if (pick < 180) op_vendor_min_lock(fd);
            else                 op_raw_fuzz(fd);
        }

        /* Periodic context re-open (~every 500 iters) */
        if (rnd32() % 500 == 0) {
            int nfd = op_reopen(fd);
            if (nfd >= 0) fd = nfd;
            else break;
        }

        if (iters % 1000 == 0) {
            int live = 0, freed = 0;
            for (int i = 0; i < MAX_ALLOCS; i++) {
                if (g_allocs[i].in_use && !g_allocs[i].freed) live++;
                if (g_allocs[i].in_use && g_allocs[i].freed) freed++;
            }
            fprintf(stderr, "[%llu] ops=%llu live=%d freed=%d crashes=%llu uaf=%llu dbl_free=%llu\n",
                    (unsigned long long)iters,
                    (unsigned long long)g_stat_ops, live, freed,
                    (unsigned long long)g_stat_crashes,
                    (unsigned long long)g_stat_uaf,
                    (unsigned long long)g_stat_double_free);
        }

        iters++;
    }

    fprintf(stderr, "[*] Done iters=%llu ops=%llu crashes=%llu\n",
            (unsigned long long)iters,
            (unsigned long long)g_stat_ops,
            (unsigned long long)g_stat_crashes);

    if (g_log) {
        char footer[256];
        snprintf(footer, sizeof(footer),
                 "--- end iters=%llu ops=%llu crashes=%llu uaf=%llu dbl_free=%llu ---",
                 (unsigned long long)iters,
                 (unsigned long long)g_stat_ops,
                 (unsigned long long)g_stat_crashes,
                 (unsigned long long)g_stat_uaf,
                 (unsigned long long)g_stat_double_free);
        log_line(footer);
        fflush(g_log);
        if (g_log_fd >= 0) fsync(g_log_fd);
        fclose(g_log);
    }
    close(fd);
    return 0;
}
