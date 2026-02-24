/*
 * ion_fuzz.c — ION memory allocator ioctl fuzzer
 *
 * Target: Samsung SM-T377A, Exynos 3475, kernel 3.10.9
 * ION ioctls from: drivers/staging/android/uapi/ion.h
 * Exynos extensions from: drivers/staging/android/ion/exynos/
 *
 * Key attack surface observations:
 *   - ion_free() drops client->lock between validate and kref_put (TOCTOU)
 *   - Handle IDs are integers that can be guessed/reused
 *   - ION_IOC_SHARE returns a dma-buf fd usable cross-process
 *   - ION_IOC_IMPORT accepts arbitrary fds
 *   - ION_IOC_CUSTOM dispatches to exynos_ion_ioctl (separate attack surface)
 *
 * Build: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -lpthread -o ion_fuzz ion_fuzz.c
 * Run:   adb shell /data/local/tmp/ion_fuzz [max_iters] [seed]
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

/* ===== ION ioctl definitions (from uapi/ion.h) ===== */

typedef int ion_user_handle_t;

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    ion_user_handle_t handle;
};

struct ion_fd_data {
    ion_user_handle_t handle;
    int fd;
};

struct ion_handle_data {
    ion_user_handle_t handle;
};

struct ion_custom_data {
    unsigned int cmd;
    unsigned long arg;
};

#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP     _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT  _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
#define ION_IOC_SYNC    _IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)
#define ION_IOC_CUSTOM  _IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

/* ION flags */
#define ION_FLAG_CACHED             1
#define ION_FLAG_CACHED_NEEDS_SYNC  2
#define ION_FLAG_NOZEROED           8
#define ION_FLAG_PROTECTED          16
#define ION_FLAG_SYNC_FORCE         32

/* Exynos heap IDs */
#define EXYNOS_ION_HEAP_SYSTEM_ID       0
#define EXYNOS_ION_HEAP_EXYNOS_CONTIG_ID 4
#define EXYNOS_ION_HEAP_EXYNOS_ID       5
#define EXYNOS_ION_HEAP_CHUNK_ID        6

/* Exynos custom ioctl — the cmd passed INSIDE ion_custom_data.cmd */
/* ION_IOC_EXYNOS_SYNC = _IOW('E', 0, struct ion_exynos_sync_data) */
/* On ARM32: (1<<30) | ('E'<<8) | 0 | (16<<16) = 0x40104500 */
#define ION_IOC_EXYNOS_MAGIC 'E'
#define ION_EXYNOS_SYNC_BY_HANDLE 0x01
#define ION_EXYNOS_SYNC_INV       0x10

struct ion_exynos_sync_data {
    int flags;
    union {
        int dmabuf_fd;
        ion_user_handle_t handle;
    };
    void *addr;
    size_t size;
};

#define ION_IOC_EXYNOS_SYNC _IOW(ION_IOC_EXYNOS_MAGIC, 0, struct ion_exynos_sync_data)

/* ===== PRNG ===== */

static uint64_t rng_state = 0x123456789abcdef0ULL;
static uint64_t rnd64(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return x;
}
static uint32_t rnd32(void) { return (uint32_t)rnd64(); }

/* ===== Global state ===== */

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

#define MAX_HANDLES 128
struct handle_entry {
    ion_user_handle_t handle;
    int share_fd;  /* dma-buf fd from ION_IOC_SHARE, -1 if not shared */
    size_t len;
    int in_use;
    int freed;     /* freed but kept for UAF testing */
};
static struct handle_entry g_handles[MAX_HANDLES];

static uint64_t g_stat_ops = 0;
static uint64_t g_stat_allocs = 0;
static uint64_t g_stat_frees = 0;
static uint64_t g_stat_shares = 0;
static uint64_t g_stat_double_free = 0;
static uint64_t g_stat_uaf = 0;
static uint64_t g_stat_crashes = 0;

/* ===== Logging ===== */

static FILE *g_log = NULL;
static int g_log_fd = -1;
static uint64_t g_log_lines = 0;

static void log_line(const char *line) {
    if (!g_log) return;
    fputs(line, g_log); fputc('\n', g_log);
    if (++g_log_lines % 50 == 0) {
        fflush(g_log);
        if (g_log_fd >= 0) fsync(g_log_fd);
    }
}

static void log_op(const char *op, int ret, int err, int handle,
                   uint64_t aux0, uint64_t aux1) {
    char buf[256];
    snprintf(buf, sizeof(buf), "op=%s ret=%d e=%d h=%d a0=0x%llx a1=%llu",
             op, ret, err, handle,
             (unsigned long long)aux0, (unsigned long long)aux1);
    log_line(buf);
}

/* ===== Handle management ===== */

static int handles_add(ion_user_handle_t h, size_t len) {
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (!g_handles[i].in_use) {
            g_handles[i] = (struct handle_entry){h, -1, len, 1, 0};
            return i;
        }
    }
    /* Table full — evict random (close share_fd if open) */
    int j = rnd32() % MAX_HANDLES;
    if (g_handles[j].share_fd >= 0) close(g_handles[j].share_fd);
    g_handles[j] = (struct handle_entry){h, -1, len, 1, 0};
    return j;
}

static int handles_pick_live(void) {
    int live[MAX_HANDLES], n = 0;
    for (int i = 0; i < MAX_HANDLES; i++)
        if (g_handles[i].in_use && !g_handles[i].freed) live[n++] = i;
    return n ? live[rnd32() % n] : -1;
}

static int handles_pick_any(void) {
    int used[MAX_HANDLES], n = 0;
    for (int i = 0; i < MAX_HANDLES; i++)
        if (g_handles[i].in_use) used[n++] = i;
    return n ? used[rnd32() % n] : -1;
}

/* ===== ION operations ===== */

static void op_alloc(int fd) {
    struct ion_allocation_data data;
    memset(&data, 0, sizeof(data));

    /* Size mutations */
    size_t sizes[] = {4096, 8192, 16384, 65536, 1, 0, 4097, 0x100000};
    data.len = sizes[rnd32() % 8];

    /* Alignment mutations */
    size_t aligns[] = {0, 4096, 8, 1, 0x10000, 0xFFFFFFFF};
    data.align = aligns[rnd32() % 6];

    /* Heap selection — SAFE heaps only!
     * CRITICAL: bit 2 (0x0004) causes KERNEL CRASH on SM-T377A
     * Safe: bit 0 (system), bit 1, bit 4 (contig)
     * Crash: bit 2, and any mask including bit 2 (e.g. 0xFFFFFFFF)
     */
    uint32_t hp = rnd32() % 10;
    if (hp < 5) data.heap_id_mask = (1 << 0);        /* system heap */
    else if (hp < 7) data.heap_id_mask = (1 << 1);   /* heap 1 */
    else if (hp < 9) data.heap_id_mask = (1 << 4);   /* exynos contig */
    else data.heap_id_mask = 0;                       /* invalid (EINVAL) */

    /* Flag mutations */
    uint32_t fp = rnd32() % 8;
    if (fp < 3) data.flags = 0;
    else if (fp == 3) data.flags = ION_FLAG_CACHED;
    else if (fp == 4) data.flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;
    else if (fp == 5) data.flags = ION_FLAG_NOZEROED;
    else if (fp == 6) data.flags = ION_FLAG_PROTECTED;
    else data.flags = rnd32() & 0xFF;

    errno = 0;
    int ret = ioctl(fd, ION_IOC_ALLOC, &data);
    log_op("ALLOC", ret, errno, data.handle, data.len, data.heap_id_mask);

    if (ret == 0) {
        handles_add(data.handle, data.len);
        g_stat_allocs++;
    }
    g_stat_ops++;
}

static void op_free(int fd) {
    int idx;
    /* Sometimes try double-free */
    if (rnd32() % 6 == 0)
        idx = handles_pick_any();
    else
        idx = handles_pick_live();
    if (idx < 0) return;

    struct ion_handle_data data;
    data.handle = g_handles[idx].handle;

    /* Sometimes fuzz the handle value */
    if (rnd32() % 10 == 0) data.handle += (int)(rnd32() % 5) - 2;

    const char *tag = g_handles[idx].freed ? "FREE_DOUBLE" : "FREE";
    if (g_handles[idx].freed) g_stat_double_free++;

    errno = 0;
    int ret = ioctl(fd, ION_IOC_FREE, &data);
    log_op(tag, ret, errno, data.handle, 0, 0);

    if (ret == 0 && !g_handles[idx].freed) {
        /* Keep some as "freed" for UAF, remove others */
        if (rnd32() % 4 == 0) {
            g_handles[idx].freed = 1;
        } else {
            if (g_handles[idx].share_fd >= 0) close(g_handles[idx].share_fd);
            g_handles[idx].in_use = 0;
        }
        g_stat_frees++;
    }
    g_stat_ops++;
}

static void op_share(int fd) {
    int idx = handles_pick_live();
    if (idx < 0) return;

    struct ion_fd_data data;
    memset(&data, 0, sizeof(data));
    data.handle = g_handles[idx].handle;

    errno = 0;
    int ret = ioctl(fd, ION_IOC_SHARE, &data);
    log_op("SHARE", ret, errno, data.handle, (uint64_t)data.fd, 0);

    if (ret == 0 && data.fd >= 0) {
        /* Close old share fd if any */
        if (g_handles[idx].share_fd >= 0) close(g_handles[idx].share_fd);
        g_handles[idx].share_fd = data.fd;
        g_stat_shares++;
    }
    g_stat_ops++;
}

static void op_map(int fd) {
    int idx = handles_pick_live();
    if (idx < 0) return;

    struct ion_fd_data data;
    memset(&data, 0, sizeof(data));
    data.handle = g_handles[idx].handle;

    errno = 0;
    int ret = ioctl(fd, ION_IOC_MAP, &data);
    log_op("MAP", ret, errno, data.handle, (uint64_t)data.fd, 0);

    if (ret == 0 && data.fd >= 0) {
        /* Try to mmap it */
        void *ptr = mmap(NULL, g_handles[idx].len ? g_handles[idx].len : 4096,
                         PROT_READ | PROT_WRITE, MAP_SHARED, data.fd, 0);
        if (ptr != MAP_FAILED) {
            /* Touch the memory */
            volatile char *p = (volatile char *)ptr;
            char c = p[0];
            p[0] = c;
            munmap(ptr, g_handles[idx].len ? g_handles[idx].len : 4096);
            log_op("MMAP_OK", 0, 0, data.handle, g_handles[idx].len, 0);
        } else {
            log_op("MMAP_FAIL", -1, errno, data.handle, g_handles[idx].len, 0);
        }
        close(data.fd);
    }
    g_stat_ops++;
}

static void op_import(int fd) {
    /* Import from a shared fd */
    int idx = -1;
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (g_handles[i].in_use && g_handles[i].share_fd >= 0) {
            idx = i;
            break;
        }
    }

    struct ion_fd_data data;
    memset(&data, 0, sizeof(data));

    if (idx >= 0) {
        data.fd = g_handles[idx].share_fd;
    } else {
        /* Fuzz: try importing bogus fds */
        data.fd = (int)(rnd32() % 100);
    }

    errno = 0;
    int ret = ioctl(fd, ION_IOC_IMPORT, &data);
    log_op("IMPORT", ret, errno, data.handle, (uint64_t)data.fd, 0);

    if (ret == 0 && data.handle > 0) {
        handles_add(data.handle, idx >= 0 ? g_handles[idx].len : 4096);
    }
    g_stat_ops++;
}

static void op_sync(int fd) {
    int idx = handles_pick_live();
    struct ion_fd_data data;
    memset(&data, 0, sizeof(data));

    if (idx >= 0 && g_handles[idx].share_fd >= 0) {
        data.fd = g_handles[idx].share_fd;
    } else {
        data.fd = (int)(rnd32() % 50);  /* fuzz fd */
    }

    errno = 0;
    int ret = ioctl(fd, ION_IOC_SYNC, &data);
    log_op("SYNC", ret, errno, 0, (uint64_t)data.fd, 0);
    g_stat_ops++;
}

static void op_custom(int fd) {
    /* ION_IOC_CUSTOM dispatches to exynos_ion_ioctl
     * which only accepts ION_IOC_EXYNOS_SYNC */
    int idx = -1;
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (g_handles[i].in_use && g_handles[i].share_fd >= 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) { g_stat_ops++; return; }

    struct ion_exynos_sync_data esd;
    memset(&esd, 0, sizeof(esd));
    esd.dmabuf_fd = g_handles[idx].share_fd;
    esd.addr = NULL;
    esd.size = g_handles[idx].len ? g_handles[idx].len : 4096;

    /* Mutate flags */
    uint32_t fp = rnd32() % 4;
    if (fp == 0) esd.flags = 0;
    else if (fp == 1) esd.flags = ION_EXYNOS_SYNC_INV;
    else if (fp == 2) esd.flags = ION_EXYNOS_SYNC_BY_HANDLE;
    else esd.flags = (int)(rnd32() & 0xFF);

    struct ion_custom_data data;
    data.cmd = ION_IOC_EXYNOS_SYNC;
    data.arg = (unsigned long)&esd;

    errno = 0;
    int ret = ioctl(fd, ION_IOC_CUSTOM, &data);
    log_op("CUSTOM", ret, errno, 0, (uint64_t)esd.flags, (uint64_t)esd.dmabuf_fd);
    g_stat_ops++;
}

static void op_uaf_query(int fd) {
    /* Try operations on freed handles */
    int idx = handles_pick_any();
    if (idx < 0 || !g_handles[idx].freed) return;

    struct ion_fd_data data;
    memset(&data, 0, sizeof(data));
    data.handle = g_handles[idx].handle;

    errno = 0;
    int ret = ioctl(fd, ION_IOC_SHARE, &data);
    log_op("SHARE_UAF", ret, errno, data.handle, 0, 0);
    if (ret == 0 && data.fd >= 0) {
        close(data.fd);
        log_line("!UAF_SHARE_SUCCEEDED");
    }
    g_stat_uaf++;
    g_stat_ops++;
}

/* Stale handle: free then immediately try to use (race window) */
static void op_free_use_race(int fd) {
    int idx = handles_pick_live();
    if (idx < 0) return;

    ion_user_handle_t h = g_handles[idx].handle;

    /* Free it */
    struct ion_handle_data fdata = { .handle = h };
    errno = 0;
    int fret = ioctl(fd, ION_IOC_FREE, &fdata);

    /* Immediately try to share (race window: handle may be destroyed) */
    struct ion_fd_data sdata = { .handle = h, .fd = -1 };
    errno = 0;
    int sret = ioctl(fd, ION_IOC_SHARE, &sdata);

    char buf[128];
    snprintf(buf, sizeof(buf), "FREE_USE_RACE free_ret=%d share_ret=%d share_fd=%d h=%d",
             fret, sret, sdata.fd, h);
    log_line(buf);

    if (sret == 0 && sdata.fd >= 0) {
        close(sdata.fd);
        log_line("!RACE_SHARE_AFTER_FREE_SUCCEEDED");
    }

    if (fret == 0) {
        g_handles[idx].in_use = 0;
        if (g_handles[idx].share_fd >= 0) close(g_handles[idx].share_fd);
        g_stat_frees++;
    }
    g_stat_ops += 2;
}

/* Alloc handle IDs: try to guess next handle ID */
static void op_handle_guess(int fd) {
    struct ion_handle_data data;

    /* Try handle IDs 1-20 (ION uses sequential idr) */
    int h = 1 + (rnd32() % 20);
    data.handle = h;

    errno = 0;
    int ret = ioctl(fd, ION_IOC_FREE, &data);
    log_op("HANDLE_GUESS", ret, errno, h, 0, 0);
    g_stat_ops++;
}

/* Re-open: test context cleanup */
static int op_reopen(int fd) {
    close(fd);
    usleep(1000);

    int nfd = open("/dev/ion", O_RDWR);
    if (nfd < 0) {
        log_line("!REOPEN_FAILED");
        return -1;
    }

    /* Clear handle table — old handles belong to destroyed client */
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (g_handles[i].share_fd >= 0) close(g_handles[i].share_fd);
    }
    memset(g_handles, 0, sizeof(g_handles));
    for (int i = 0; i < MAX_HANDLES; i++) g_handles[i].share_fd = -1;

    char buf[64];
    snprintf(buf, sizeof(buf), "REOPEN fd=%d", nfd);
    log_line(buf);
    g_stat_ops++;
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

    const char *log_path = getenv("ION_LOG_PATH");
    if (!log_path || !*log_path) log_path = "./ion_fuzz.log";

    g_log = fopen(log_path, "a");
    if (g_log) {
        g_log_fd = fileno(g_log);
        setvbuf(g_log, NULL, _IOLBF, 0);
        char hdr[128];
        snprintf(hdr, sizeof(hdr), "--- start seed=0x%llx ---", (unsigned long long)seed);
        log_line(hdr);
    }

    for (int i = 0; i < MAX_HANDLES; i++) g_handles[i].share_fd = -1;

    signal(SIGINT, on_sigint);

    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[-] open(/dev/ion): %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[+] /dev/ion fd=%d seed=0x%llx\n", fd, (unsigned long long)seed);

    uint64_t iters = 0;
    while (!g_stop) {
        if (max_iters && iters >= max_iters) break;

        int ops = 2 + (rnd32() % 9);
        for (int i = 0; i < ops && !g_stop; i++) {
            uint32_t pick = rnd32() % 200;

            /* Count live handles for bias */
            int live = 0;
            for (int j = 0; j < MAX_HANDLES; j++)
                if (g_handles[j].in_use && !g_handles[j].freed) live++;

            /* If too many handles, bias toward frees */
            if (live > 100 && pick < 120) pick = 120;

            if      (pick < 40)  op_alloc(fd);
            else if (pick < 70)  op_free(fd);
            else if (pick < 90)  op_share(fd);
            else if (pick < 110) op_map(fd);
            else if (pick < 120) op_import(fd);
            else if (pick < 135) op_sync(fd);
            else if (pick < 145) op_custom(fd);
            else if (pick < 160) op_uaf_query(fd);
            else if (pick < 175) op_free_use_race(fd);
            else if (pick < 190) op_handle_guess(fd);
            else                 { /* nop — breather */ }
        }

        /* Periodic reopen (~every 500 iters) */
        if (rnd32() % 500 == 0) {
            int nfd = op_reopen(fd);
            if (nfd >= 0) fd = nfd;
            else break;
        }

        if (iters % 1000 == 0) {
            int live = 0, freed = 0, shared = 0;
            for (int i = 0; i < MAX_HANDLES; i++) {
                if (g_handles[i].in_use && !g_handles[i].freed) live++;
                if (g_handles[i].in_use && g_handles[i].freed) freed++;
                if (g_handles[i].share_fd >= 0) shared++;
            }
            fprintf(stderr, "[%llu] ops=%llu allocs=%llu frees=%llu shares=%llu "
                    "live=%d freed=%d shared=%d dbl=%llu uaf=%llu\n",
                    (unsigned long long)iters,
                    (unsigned long long)g_stat_ops,
                    (unsigned long long)g_stat_allocs,
                    (unsigned long long)g_stat_frees,
                    (unsigned long long)g_stat_shares,
                    live, freed, shared,
                    (unsigned long long)g_stat_double_free,
                    (unsigned long long)g_stat_uaf);
        }

        iters++;
    }

    fprintf(stderr, "[*] Done iters=%llu ops=%llu allocs=%llu frees=%llu "
            "dbl=%llu uaf=%llu crashes=%llu\n",
            (unsigned long long)iters,
            (unsigned long long)g_stat_ops,
            (unsigned long long)g_stat_allocs,
            (unsigned long long)g_stat_frees,
            (unsigned long long)g_stat_double_free,
            (unsigned long long)g_stat_uaf,
            (unsigned long long)g_stat_crashes);

    if (g_log) {
        char ftr[256];
        snprintf(ftr, sizeof(ftr),
                 "--- end iters=%llu ops=%llu allocs=%llu frees=%llu dbl=%llu uaf=%llu ---",
                 (unsigned long long)iters,
                 (unsigned long long)g_stat_ops,
                 (unsigned long long)g_stat_allocs,
                 (unsigned long long)g_stat_frees,
                 (unsigned long long)g_stat_double_free,
                 (unsigned long long)g_stat_uaf);
        log_line(ftr);
        fflush(g_log); fsync(g_log_fd); fclose(g_log);
    }

    /* Cleanup */
    for (int i = 0; i < MAX_HANDLES; i++)
        if (g_handles[i].share_fd >= 0) close(g_handles[i].share_fd);
    close(fd);
    return 0;
}
