/*
 * ashmem_fuzz.c — Android ashmem ioctl fuzzer
 *
 * Target: Samsung SM-T377A, kernel 3.10.9
 * ashmem ioctls from: drivers/staging/android/ashmem.h
 *
 * Attack surface:
 *   - SET_NAME: 256-byte name buffer (stack overflow potential)
 *   - SET_SIZE: controls mmap-able range
 *   - SET_PROT_MASK: permission downgrade
 *   - PIN/UNPIN: page-range locking with offset/len (integer overflow)
 *   - PURGE_ALL_CACHES: global side-effect
 *   - mmap after various state transitions
 *
 * Build: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -o ashmem_fuzz ashmem_fuzz.c
 */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

/* ===== ashmem definitions ===== */

#define ASHMEM_NAME_LEN 256
#define ASHMEM_NAME_DEF "dev/ashmem"

#define ASHMEM_NOT_PURGED 0
#define ASHMEM_WAS_PURGED 1
#define ASHMEM_IS_UNPINNED 0
#define ASHMEM_IS_PINNED 1

struct ashmem_pin {
    uint32_t offset;
    uint32_t len;
};

#define __ASHMEMIOC 0x77

#define ASHMEM_SET_NAME       _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME       _IOR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE       _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE       _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK  _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK  _IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN            _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN          _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)

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

/* Signal recovery for SIGBUS/SIGSEGV from mmap access */
static sigjmp_buf g_jmpbuf;
static volatile sig_atomic_t g_in_mmap_access = 0;
static uint64_t g_stat_sigrecovery = 0;

static void on_crash_signal(int sig) {
    (void)sig;
    if (g_in_mmap_access) {
        g_stat_sigrecovery++;
        siglongjmp(g_jmpbuf, 1);
    }
    /* Not in mmap access — re-raise */
    signal(sig, SIG_DFL);
    raise(sig);
}

#define MAX_REGIONS 32
struct ashmem_region {
    int fd;
    size_t size;
    int mapped;
    void *map_ptr;
    int in_use;
};
static struct ashmem_region g_regions[MAX_REGIONS];

static uint64_t g_ops = 0;
static uint64_t g_creates = 0, g_closes = 0;
static uint64_t g_sets = 0, g_gets = 0;
static uint64_t g_pins = 0, g_unpins = 0;
static uint64_t g_mmaps = 0, g_purges = 0;

/* ===== Logging ===== */

static FILE *g_log = NULL;

static void log_op(const char *op, int ret, int err, int fd,
                   uint64_t a0, uint64_t a1) {
    if (!g_log) return;
    fprintf(g_log, "op=%s ret=%d e=%d fd=%d a0=0x%llx a1=0x%llx\n",
            op, ret, err, fd,
            (unsigned long long)a0, (unsigned long long)a1);
}

/* ===== Region management ===== */

static int region_add(int fd, size_t size) {
    for (int i = 0; i < MAX_REGIONS; i++) {
        if (!g_regions[i].in_use) {
            g_regions[i] = (struct ashmem_region){fd, size, 0, NULL, 1};
            return i;
        }
    }
    /* Full — close fd */
    close(fd);
    return -1;
}

static int region_pick(void) {
    int live[MAX_REGIONS], n = 0;
    for (int i = 0; i < MAX_REGIONS; i++)
        if (g_regions[i].in_use) live[n++] = i;
    return n ? live[rnd32() % n] : -1;
}

static void region_close(int idx) {
    if (g_regions[idx].mapped && g_regions[idx].map_ptr) {
        munmap(g_regions[idx].map_ptr,
               g_regions[idx].size ? g_regions[idx].size : 4096);
    }
    close(g_regions[idx].fd);
    g_regions[idx].in_use = 0;
}

/* ===== Operations ===== */

static void op_create(void) {
    int fd = open("/dev/ashmem", O_RDWR);
    if (fd < 0) {
        log_op("CREATE", -1, errno, -1, 0, 0);
        return;
    }
    region_add(fd, 0);
    g_creates++;
    g_ops++;
    log_op("CREATE", 0, 0, fd, 0, 0);
}

static void op_set_name(void) {
    int idx = region_pick();
    if (idx < 0) return;

    char name[ASHMEM_NAME_LEN];
    uint32_t mode = rnd32() % 6;
    if (mode == 0) {
        /* Normal name */
        snprintf(name, sizeof(name), "fuzz_%u", rnd32() % 10000);
    } else if (mode == 1) {
        /* Max length name */
        memset(name, 'A', ASHMEM_NAME_LEN - 1);
        name[ASHMEM_NAME_LEN - 1] = '\0';
    } else if (mode == 2) {
        /* Empty name */
        name[0] = '\0';
    } else if (mode == 3) {
        /* Name with special chars */
        snprintf(name, sizeof(name), "../../../etc/passwd");
    } else if (mode == 4) {
        /* Name with null bytes in middle */
        memset(name, 'B', ASHMEM_NAME_LEN);
        name[10] = '\0';
        name[ASHMEM_NAME_LEN - 1] = '\0';
    } else {
        /* Random bytes */
        for (int i = 0; i < ASHMEM_NAME_LEN - 1; i++)
            name[i] = (char)(rnd32() & 0xFF);
        name[ASHMEM_NAME_LEN - 1] = '\0';
    }

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_SET_NAME, name);
    log_op("SET_NAME", ret, errno, g_regions[idx].fd, mode, 0);
    g_sets++;
    g_ops++;
}

static void op_get_name(void) {
    int idx = region_pick();
    if (idx < 0) return;

    char name[ASHMEM_NAME_LEN];
    memset(name, 0, sizeof(name));
    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_GET_NAME, name);
    log_op("GET_NAME", ret, errno, g_regions[idx].fd, 0, 0);
    g_gets++;
    g_ops++;
}

static void op_set_size(void) {
    int idx = region_pick();
    if (idx < 0) return;

    size_t sizes[] = {0, 1, 4096, 65536, 1048576, 0x7FFFFFFF, 0xFFFFFFFF, 4097};
    size_t sz = sizes[rnd32() % 8];

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_SET_SIZE, sz);
    if (ret == 0) g_regions[idx].size = sz;
    log_op("SET_SIZE", ret, errno, g_regions[idx].fd, sz, 0);
    g_sets++;
    g_ops++;
}

static void op_get_size(void) {
    int idx = region_pick();
    if (idx < 0) return;

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_GET_SIZE, 0);
    log_op("GET_SIZE", ret, errno, g_regions[idx].fd, (uint64_t)(unsigned)ret, 0);
    g_gets++;
    g_ops++;
}

static void op_set_prot(void) {
    int idx = region_pick();
    if (idx < 0) return;

    unsigned long prots[] = {
        PROT_READ | PROT_WRITE,
        PROT_READ,
        PROT_WRITE,
        PROT_NONE,
        PROT_READ | PROT_EXEC,
        0xFFFFFFFF,
        0
    };
    unsigned long prot = prots[rnd32() % 7];

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_SET_PROT_MASK, prot);
    log_op("SET_PROT", ret, errno, g_regions[idx].fd, prot, 0);
    g_sets++;
    g_ops++;
}

static void op_get_prot(void) {
    int idx = region_pick();
    if (idx < 0) return;

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_GET_PROT_MASK, 0);
    log_op("GET_PROT", ret, errno, g_regions[idx].fd, (uint64_t)(unsigned)ret, 0);
    g_gets++;
    g_ops++;
}

static void op_pin(void) {
    int idx = region_pick();
    if (idx < 0) return;

    struct ashmem_pin pin;
    uint32_t mode = rnd32() % 5;
    if (mode == 0) {
        pin.offset = 0; pin.len = 0;  /* entire region */
    } else if (mode == 1) {
        pin.offset = 0; pin.len = 4096;
    } else if (mode == 2) {
        /* Misaligned */
        pin.offset = 1; pin.len = 4095;
    } else if (mode == 3) {
        /* Overflow: offset + len wraps */
        pin.offset = 0xFFFF0000; pin.len = 0x20000;
    } else {
        pin.offset = (rnd32() & 0xFFFFF000);
        pin.len = (rnd32() & 0xFFFFF000);
    }

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_PIN, &pin);
    log_op("PIN", ret, errno, g_regions[idx].fd, pin.offset, pin.len);
    g_pins++;
    g_ops++;
}

static void op_unpin(void) {
    int idx = region_pick();
    if (idx < 0) return;

    struct ashmem_pin pin;
    uint32_t mode = rnd32() % 3;
    if (mode == 0) {
        pin.offset = 0; pin.len = 0;
    } else if (mode == 1) {
        pin.offset = 0; pin.len = 4096;
    } else {
        pin.offset = (rnd32() & 0xFFFFF000);
        pin.len = (rnd32() & 0xFFFFF000);
    }

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_UNPIN, &pin);
    log_op("UNPIN", ret, errno, g_regions[idx].fd, pin.offset, pin.len);
    g_unpins++;
    g_ops++;
}

static void op_get_pin_status(void) {
    int idx = region_pick();
    if (idx < 0) return;

    errno = 0;
    int ret = ioctl(g_regions[idx].fd, ASHMEM_GET_PIN_STATUS, 0);
    log_op("PIN_STATUS", ret, errno, g_regions[idx].fd, 0, 0);
    g_gets++;
    g_ops++;
}

static void op_mmap_access(void) {
    int idx = region_pick();
    if (idx < 0) return;

    size_t sz = g_regions[idx].size;
    if (sz == 0 || sz > 0x10000000) return;
    /* Clamp to reasonable size for mmap */
    if (sz > 4 * 1024 * 1024) sz = 4 * 1024 * 1024;

    /* Unmap previous if mapped */
    if (g_regions[idx].mapped && g_regions[idx].map_ptr) {
        munmap(g_regions[idx].map_ptr, sz);
        g_regions[idx].mapped = 0;
        g_regions[idx].map_ptr = NULL;
    }

    errno = 0;
    void *ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED,
                     g_regions[idx].fd, 0);
    if (ptr == MAP_FAILED) {
        log_op("MMAP", -1, errno, g_regions[idx].fd, sz, 0);
        g_ops++;
        return;
    }

    g_regions[idx].mapped = 1;
    g_regions[idx].map_ptr = ptr;

    /* Touch memory with signal recovery */
    g_in_mmap_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        volatile char *p = (volatile char *)ptr;
        /* Read first and last byte */
        char c = p[0];
        (void)c;
        if (sz > 1) {
            c = p[sz - 1];
            (void)c;
        }
        /* Write test pattern */
        p[0] = 0x41;
        if (sz > 1) p[sz - 1] = 0x42;
        log_op("MMAP_RW", 0, 0, g_regions[idx].fd, sz, 0);
    } else {
        log_op("MMAP_SIG", -1, 0, g_regions[idx].fd, sz, 0);
    }
    g_in_mmap_access = 0;
    g_mmaps++;
    g_ops++;
}

static void op_purge(void) {
    errno = 0;
    int ret = ioctl(g_regions[0].fd >= 0 ? g_regions[0].fd : -1,
                    ASHMEM_PURGE_ALL_CACHES, 0);
    log_op("PURGE", ret, errno, 0, 0, 0);
    g_purges++;
    g_ops++;
}

/* Unpin then immediately access — test purge race */
static void op_unpin_access(void) {
    int idx = region_pick();
    if (idx < 0 || !g_regions[idx].mapped || !g_regions[idx].map_ptr) return;

    struct ashmem_pin pin = { .offset = 0, .len = 0 };
    ioctl(g_regions[idx].fd, ASHMEM_UNPIN, &pin);

    /* Try purge */
    for (int i = 0; i < MAX_REGIONS; i++) {
        if (g_regions[i].in_use) {
            ioctl(g_regions[i].fd, ASHMEM_PURGE_ALL_CACHES, 0);
            break;
        }
    }

    /* Access unpinned (possibly purged) memory */
    g_in_mmap_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        volatile char *p = (volatile char *)g_regions[idx].map_ptr;
        char c = p[0];
        (void)c;
        log_op("UNPIN_ACCESS", 0, 0, g_regions[idx].fd, 0, 0);
    } else {
        log_op("UNPIN_ACCESS_SIG", -1, 0, g_regions[idx].fd, 0, 0);
    }
    g_in_mmap_access = 0;

    /* Re-pin */
    pin.offset = 0; pin.len = 0;
    ioctl(g_regions[idx].fd, ASHMEM_PIN, &pin);
    g_ops += 3;
}

static void op_close_reopen(void) {
    int idx = region_pick();
    if (idx < 0) return;
    region_close(idx);
    g_closes++;

    int fd = open("/dev/ashmem", O_RDWR);
    if (fd >= 0) region_add(fd, 0);
    g_ops++;
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

    const char *log_path = getenv("ASHMEM_LOG_PATH");
    if (!log_path || !*log_path) log_path = "./ashmem_fuzz.log";
    g_log = fopen(log_path, "w");
    if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);

    signal(SIGINT, on_sigint);
    signal(SIGBUS, on_crash_signal);
    signal(SIGSEGV, on_crash_signal);

    memset(g_regions, 0, sizeof(g_regions));

    /* Seed with a few regions */
    for (int i = 0; i < 4; i++) {
        int fd = open("/dev/ashmem", O_RDWR);
        if (fd >= 0) {
            region_add(fd, 0);
            g_creates++;
        }
    }

    fprintf(stderr, "[+] ashmem_fuzz seed=0x%llx\n", (unsigned long long)seed);

    uint64_t iters = 0;
    while (!g_stop) {
        if (max_iters && iters >= max_iters) break;

        int ops = 2 + (rnd32() % 8);
        for (int i = 0; i < ops && !g_stop; i++) {
            uint32_t pick = rnd32() % 200;

            /* Ensure we have at least one region */
            int live = 0;
            for (int j = 0; j < MAX_REGIONS; j++)
                if (g_regions[j].in_use) live++;
            if (live == 0) { op_create(); continue; }

            if      (pick < 15)  op_create();
            else if (pick < 35)  op_set_name();
            else if (pick < 45)  op_get_name();
            else if (pick < 70)  op_set_size();
            else if (pick < 80)  op_get_size();
            else if (pick < 95)  op_set_prot();
            else if (pick < 105) op_get_prot();
            else if (pick < 125) op_pin();
            else if (pick < 140) op_unpin();
            else if (pick < 150) op_get_pin_status();
            else if (pick < 170) op_mmap_access();
            else if (pick < 180) op_unpin_access();
            else if (pick < 190) op_purge();
            else                 op_close_reopen();
        }

        if (iters % 1000 == 0) {
            int live = 0, mapped = 0;
            for (int j = 0; j < MAX_REGIONS; j++) {
                if (g_regions[j].in_use) live++;
                if (g_regions[j].mapped) mapped++;
            }
            fprintf(stderr, "[%llu] ops=%llu creates=%llu sets=%llu pins=%llu "
                    "mmaps=%llu purges=%llu live=%d mapped=%d sigrecov=%llu\n",
                    (unsigned long long)iters,
                    (unsigned long long)g_ops,
                    (unsigned long long)g_creates,
                    (unsigned long long)g_sets,
                    (unsigned long long)g_pins,
                    (unsigned long long)g_mmaps,
                    (unsigned long long)g_purges,
                    live, mapped,
                    (unsigned long long)g_stat_sigrecovery);
        }

        iters++;
    }

    fprintf(stderr, "[*] Done iters=%llu ops=%llu creates=%llu closes=%llu "
            "sets=%llu gets=%llu pins=%llu unpins=%llu mmaps=%llu "
            "purges=%llu sigrecov=%llu\n",
            (unsigned long long)iters,
            (unsigned long long)g_ops,
            (unsigned long long)g_creates,
            (unsigned long long)g_closes,
            (unsigned long long)g_sets,
            (unsigned long long)g_gets,
            (unsigned long long)g_pins,
            (unsigned long long)g_unpins,
            (unsigned long long)g_mmaps,
            (unsigned long long)g_purges,
            (unsigned long long)g_stat_sigrecovery);

    /* Cleanup */
    for (int i = 0; i < MAX_REGIONS; i++)
        if (g_regions[i].in_use) region_close(i);
    if (g_log) { fflush(g_log); fclose(g_log); }

    return 0;
}
