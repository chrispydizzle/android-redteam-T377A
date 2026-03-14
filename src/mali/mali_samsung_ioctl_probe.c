/*
 * mali_samsung_ioctl_probe.c
 *
 * Targeted probe for Samsung-specific Mali T72x IOCTLs that have NOT been
 * systematically tested with valid inputs:
 *
 *   1. HWCNT_SETUP/DUMP/CLEAR with a valid GPU VA (prior fuzzing only tested
 *      dump_buffer=0 which always returns EFAULT).  We allocate a 4-page buffer,
 *      CPU-map it, configure HWCNT, trigger a dump, then read back the written
 *      counter data to confirm the GPU actually touched user memory.
 *
 *   2. CREATE_SURFACE / DESTROY_SURFACE – prior fuzzer picked create/destroy
 *      randomly and neither was systematically paired.  We test:
 *        a. create only × 4
 *        b. create then destroy (paired)
 *        c. double destroy (second destroy after first succeeds)
 *        d. destroy with no prior create
 *        e. destroy with nonzero payload fields (try to mis-identify "surface")
 *
 *   3. SECURE_WORLD_RENDERING / NON_SECURE_WORLD_RENDERING – never directly
 *      called with any payload.  We probe both IDs with zero and nonzero
 *      payloads and record what header.ret and errno say.
 *
 * Build:  qemu\build-arm.bat src\mali\mali_samsung_ioctl_probe.c mali_samsung_ioctl_probe
 * Run:    adb shell /data/local/tmp/mali_samsung_ioctl_probe
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Mali IOCTL encoding                                                   */
/* ------------------------------------------------------------------ */
#define MALI_IOCTL(size)    _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, (size))

/* UK function IDs */
#define UKP_FUNC_ID_CHECK_VERSION 0
#define UK_FUNC_ID 512
#define KBASE_FUNC_MEM_ALLOC        (UK_FUNC_ID +  0)   /* 512 */
#define KBASE_FUNC_MEM_FREE         (UK_FUNC_ID +  4)   /* 516 */
#define KBASE_FUNC_SET_FLAGS        (UK_FUNC_ID + 18)   /* 530 */
#define KBASE_FUNC_HWCNT_SETUP      (UK_FUNC_ID + 10)   /* 522 */
#define KBASE_FUNC_HWCNT_DUMP       (UK_FUNC_ID + 11)   /* 523 */
#define KBASE_FUNC_HWCNT_CLEAR      (UK_FUNC_ID + 12)   /* 524 */
#define KBASE_FUNC_CREATE_SURFACE   (UK_FUNC_ID + 40)   /* 552 */
#define KBASE_FUNC_DESTROY_SURFACE  (UK_FUNC_ID + 41)   /* 553 */
#define KBASE_FUNC_SECURE_WORLD_RENDERING     (UK_FUNC_ID + 55)  /* 567 */
#define KBASE_FUNC_NON_SECURE_WORLD_RENDERING (UK_FUNC_ID + 56)  /* 568 */

/* MEM_ALLOC flags */
#define BASE_MEM_PROT_CPU_RD (1U << 0)
#define BASE_MEM_PROT_CPU_WR (1U << 1)
#define BASE_MEM_PROT_GPU_RD (1U << 2)
#define BASE_MEM_PROT_GPU_WR (1U << 3)
#define BASE_MEM_COHERENT_LOCAL (1U << 11)

/* ------------------------------------------------------------------ */
/* Structs                                                               */
/* ------------------------------------------------------------------ */
typedef union {
    uint32_t id;
    uint32_t ret;
    uint64_t align;
} uk_header;

struct uku_version_check_args {
    uk_header header;
    uint16_t  major;
    uint16_t  minor;
    uint8_t   padding[4];
};

struct kbase_uk_set_flags {
    uk_header header;
    uint32_t  create_flags;
    uint32_t  padding;
};

struct kbase_uk_mem_alloc {
    uk_header header;
    uint64_t  va_pages;
    uint64_t  commit_pages;
    uint64_t  extent;
    uint32_t  flags;
    uint32_t  pad0;
    uint64_t  gpu_va;
    uint16_t  va_alignment;
    uint8_t   pad1[6];
};

struct kbase_uk_mem_free {
    uk_header header;
    uint64_t  gpu_addr;
};

struct kbase_uk_hwcnt_setup {
    uk_header header;       /* 8  bytes */
    uint64_t  dump_buffer;  /* 8  bytes – GPU VA of counter dump region */
    uint32_t  jm_bm;        /* 4  bytes – Job Manager block bitmask      */
    uint32_t  shader_bm;    /* 4  bytes – Shader core bitmask             */
    uint32_t  tiler_bm;     /* 4  bytes – Tiler bitmask                   */
    uint32_t  unused_1;     /* 4  bytes                                   */
    uint32_t  mmu_l2_bm;    /* 4  bytes – MMU/L2 bitmask                  */
    uint32_t  padding;      /* 4  bytes                                   */
};                          /* 40 bytes total                             */

struct kbase_uk_hwcnt_dump {
    uk_header header;       /* 8 bytes – only header needed               */
};

/* Samsung vendor command (CREATE_SURFACE, DESTROY_SURFACE, SECURE_WORLD …) */
struct kbase_uk_custom_command {
    uk_header header;   /* 8  bytes */
    uint32_t  enabled;  /* 4  bytes */
    uint32_t  padding;  /* 4  bytes */
    uint64_t  flags;    /* 8  bytes */
};                      /* 24 bytes total */

/* ------------------------------------------------------------------ */
/* Helpers                                                               */
/* ------------------------------------------------------------------ */
static int mali_ioctl(int fd, void *buf, size_t sz)
{
    errno = 0;
    return ioctl(fd, MALI_IOCTL(sz), buf);
}

static int mali_init(int fd)
{
    struct uku_version_check_args ver;
    struct kbase_uk_set_flags     flags;

    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10; ver.minor = 2;
    if (mali_ioctl(fd, &ver, sizeof(ver)) < 0) {
        fprintf(stderr, "CHECK_VERSION ioctl failed: %s\n", strerror(errno));
        return -1;
    }
    printf("[init] CHECK_VERSION ret=%u version=%u.%u\n",
           ver.header.ret, ver.major, ver.minor);

    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    if (mali_ioctl(fd, &flags, sizeof(flags)) < 0) {
        fprintf(stderr, "SET_FLAGS ioctl failed: %s\n", strerror(errno));
        return -1;
    }
    printf("[init] SET_FLAGS ret=%u\n", flags.header.ret);
    return (flags.header.ret == 0) ? 0 : -1;
}

static uint64_t mali_alloc(int fd, uint64_t pages, uint32_t mem_flags)
{
    struct kbase_uk_mem_alloc a;
    memset(&a, 0, sizeof(a));
    a.header.id    = KBASE_FUNC_MEM_ALLOC;
    a.va_pages     = pages;
    a.commit_pages = pages;
    a.extent       = pages;
    a.flags        = mem_flags;

    if (mali_ioctl(fd, &a, sizeof(a)) < 0) {
        fprintf(stderr, "[alloc] ioctl failed: %s\n", strerror(errno));
        return 0;
    }
    printf("[alloc] ret=%u gpu_va=0x%llx pages=%llu\n",
           a.header.ret, (unsigned long long)a.gpu_va, (unsigned long long)pages);
    return (a.header.ret == 0) ? a.gpu_va : 0;
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, size_t sz, int prot)
{
    unsigned long pgoff = (unsigned long)(gpu_va >> 12);
    void *p = (void *)syscall(__NR_mmap2, (unsigned long)NULL, sz,
                              prot, MAP_SHARED, fd, pgoff);
    if (p == MAP_FAILED) {
        fprintf(stderr, "[cmap] mmap2 failed gpu_va=0x%llx: %s\n",
                (unsigned long long)gpu_va, strerror(errno));
        return MAP_FAILED;
    }
    printf("[cmap] gpu_va=0x%llx → cpu=%p\n", (unsigned long long)gpu_va, p);
    return p;
}

static void mali_free(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_free f;
    memset(&f, 0, sizeof(f));
    f.header.id = KBASE_FUNC_MEM_FREE;
    f.gpu_addr  = gpu_va;
    mali_ioctl(fd, &f, sizeof(f));
}

/* ------------------------------------------------------------------ */
/* Section 1: HWCNT with valid GPU VA                                    */
/* ------------------------------------------------------------------ */
static void test_hwcnt(int fd)
{
    puts("\n=== HWCNT: setup + dump + read-back ===");

    /* allocate 4 CPU+GPU-accessible pages for the counter dump region */
    uint32_t mflags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                      BASE_MEM_COHERENT_LOCAL;
    uint64_t dump_gpu_va = mali_alloc(fd, 4, mflags);
    if (!dump_gpu_va) {
        puts("[hwcnt] MEM_ALLOC failed, skipping HWCNT test");
        return;
    }

    size_t dump_sz = 4 * 4096;
    void *dump_cpu = mali_cpu_map(fd, dump_gpu_va, dump_sz,
                                  PROT_READ | PROT_WRITE);
    if (dump_cpu == MAP_FAILED) {
        puts("[hwcnt] CPU map failed, skipping read-back");
        dump_cpu = NULL;
    }

    /* zero the dump region before setup so we can detect writes */
    if (dump_cpu) memset(dump_cpu, 0, dump_sz);

    /* --- HWCNT_SETUP: enable all blocks, dump_buffer = our GPU VA --- */
    struct kbase_uk_hwcnt_setup hs;
    memset(&hs, 0, sizeof(hs));
    hs.header.id   = KBASE_FUNC_HWCNT_SETUP;
    hs.dump_buffer = dump_gpu_va;
    hs.jm_bm       = 0xFFFFFFFF;
    hs.shader_bm   = 0xFFFFFFFF;
    hs.tiler_bm    = 0xFFFFFFFF;
    hs.mmu_l2_bm   = 0xFFFFFFFF;

    int r = mali_ioctl(fd, &hs, sizeof(hs));
    printf("[hwcnt] HWCNT_SETUP: ioctl_ret=%d errno=%d uk_ret=%u\n",
           r, errno, hs.header.ret);

    if (hs.header.ret != 0) {
        printf("[hwcnt] HWCNT_SETUP rejected (uk_ret=%u) – trying with all-zero bitmasks\n",
               hs.header.ret);
        memset(&hs, 0, sizeof(hs));
        hs.header.id   = KBASE_FUNC_HWCNT_SETUP;
        hs.dump_buffer = dump_gpu_va;
        r = mali_ioctl(fd, &hs, sizeof(hs));
        printf("[hwcnt] HWCNT_SETUP(zeroBM): ioctl_ret=%d errno=%d uk_ret=%u\n",
               r, errno, hs.header.ret);
    }

    /* --- HWCNT_DUMP: trigger counter collection into dump_buffer --- */
    struct kbase_uk_hwcnt_dump hd;
    memset(&hd, 0, sizeof(hd));
    hd.header.id = KBASE_FUNC_HWCNT_DUMP;
    r = mali_ioctl(fd, &hd, sizeof(hd));
    printf("[hwcnt] HWCNT_DUMP: ioctl_ret=%d errno=%d uk_ret=%u\n",
           r, errno, hd.header.ret);

    /* --- read back the dump region --- */
    if (dump_cpu) {
        uint32_t *u32 = (uint32_t *)dump_cpu;
        int nonzero = 0;
        for (size_t i = 0; i < dump_sz / 4; i++)
            if (u32[i]) nonzero++;
        printf("[hwcnt] dump_buffer read-back: %d/%zu non-zero u32 words\n",
               nonzero, dump_sz / 4);
        if (nonzero > 0) {
            puts("[hwcnt] *** GPU wrote counter data to user page! First 8 words:");
            for (int i = 0; i < 8; i++)
                printf("  [%d] = 0x%08x\n", i, u32[i]);
        } else {
            puts("[hwcnt] dump_buffer is still all zeros (DUMP had no effect or SETUP failed)");
        }
    }

    /* --- HWCNT_CLEAR --- */
    struct kbase_uk_hwcnt_dump hc;
    memset(&hc, 0, sizeof(hc));
    hc.header.id = KBASE_FUNC_HWCNT_CLEAR;
    r = mali_ioctl(fd, &hc, sizeof(hc));
    printf("[hwcnt] HWCNT_CLEAR: ioctl_ret=%d errno=%d uk_ret=%u\n",
           r, errno, hc.header.ret);

    /* --- HWCNT_SETUP(dump_buffer=0): release / disable counters --- */
    memset(&hs, 0, sizeof(hs));
    hs.header.id   = KBASE_FUNC_HWCNT_SETUP;
    hs.dump_buffer = 0;
    r = mali_ioctl(fd, &hs, sizeof(hs));
    printf("[hwcnt] HWCNT_SETUP(disable): ioctl_ret=%d errno=%d uk_ret=%u\n",
           r, errno, hs.header.ret);

    if (dump_cpu) munmap(dump_cpu, dump_sz);
    mali_free(fd, dump_gpu_va);
}

/* ------------------------------------------------------------------ */
/* Section 2: CREATE_SURFACE / DESTROY_SURFACE                          */
/* ------------------------------------------------------------------ */
static void cc_call(int fd, const char *tag, uint32_t func_id,
                    uint32_t enabled, uint64_t flags_val)
{
    struct kbase_uk_custom_command cc;
    memset(&cc, 0, sizeof(cc));
    cc.header.id = func_id;
    cc.enabled   = enabled;
    cc.flags     = flags_val;

    int r = mali_ioctl(fd, &cc, sizeof(cc));
    printf("[surface] %s: ioctl_ret=%d errno=%d uk_ret=%u\n",
           tag, r, errno, cc.header.ret);
}

static void test_surface(int fd)
{
    puts("\n=== CREATE_SURFACE / DESTROY_SURFACE ===");

    /* a) four plain CREATE_SURFACE calls */
    for (int i = 0; i < 4; i++) {
        char tag[32]; snprintf(tag, sizeof(tag), "CREATE#%d", i);
        cc_call(fd, tag, KBASE_FUNC_CREATE_SURFACE, 0, 0);
    }

    /* b) one CREATE then one DESTROY (paired) */
    cc_call(fd, "CREATE_paired", KBASE_FUNC_CREATE_SURFACE, 0, 0);
    cc_call(fd, "DESTROY_paired", KBASE_FUNC_DESTROY_SURFACE, 0, 0);

    /* c) double destroy: second destroy right after the first */
    cc_call(fd, "DESTROY_double_1st", KBASE_FUNC_DESTROY_SURFACE, 0, 0);
    cc_call(fd, "DESTROY_double_2nd", KBASE_FUNC_DESTROY_SURFACE, 0, 0);

    /* d) destroy-with-no-prior-create (fresh state) */
    cc_call(fd, "DESTROY_noCreate", KBASE_FUNC_DESTROY_SURFACE, 0, 0);

    /* e) destroy with nonzero enabled/flags */
    cc_call(fd, "DESTROY_enabled1", KBASE_FUNC_DESTROY_SURFACE, 1, 0);
    cc_call(fd, "DESTROY_flags_ff", KBASE_FUNC_DESTROY_SURFACE, 0, 0xFFFFFFFFULL);
    cc_call(fd, "DESTROY_large_flags", KBASE_FUNC_DESTROY_SURFACE, 1, 0xDEADBEEFCAFEBABEULL);
}

/* ------------------------------------------------------------------ */
/* Section 3: SECURE_WORLD_RENDERING / NON_SECURE_WORLD_RENDERING       */
/* ------------------------------------------------------------------ */
static void test_secure_world(int fd)
{
    puts("\n=== SECURE_WORLD_RENDERING / NON_SECURE_WORLD_RENDERING ===");

    /* zero payload */
    cc_call(fd, "SECURE_WORLD_zero",     KBASE_FUNC_SECURE_WORLD_RENDERING,     0, 0);
    cc_call(fd, "NON_SECURE_WORLD_zero", KBASE_FUNC_NON_SECURE_WORLD_RENDERING, 0, 0);

    /* enabled=1 */
    cc_call(fd, "SECURE_WORLD_en1",      KBASE_FUNC_SECURE_WORLD_RENDERING,     1, 0);
    cc_call(fd, "NON_SECURE_WORLD_en1",  KBASE_FUNC_NON_SECURE_WORLD_RENDERING, 1, 0);

    /* toggle pair */
    cc_call(fd, "SECURE_toggle1",        KBASE_FUNC_SECURE_WORLD_RENDERING,     1, 0);
    cc_call(fd, "NON_SECURE_toggle1",    KBASE_FUNC_NON_SECURE_WORLD_RENDERING, 1, 0);
    cc_call(fd, "SECURE_toggle2",        KBASE_FUNC_SECURE_WORLD_RENDERING,     0, 0);
    cc_call(fd, "NON_SECURE_toggle2",    KBASE_FUNC_NON_SECURE_WORLD_RENDERING, 0, 0);

    /* nonzero flags */
    cc_call(fd, "SECURE_flags_0xff",     KBASE_FUNC_SECURE_WORLD_RENDERING,     0, 0xFF);
    cc_call(fd, "SECURE_flags_max",      KBASE_FUNC_SECURE_WORLD_RENDERING,     1, 0xFFFFFFFFFFFFFFFFULL);
}

/* ------------------------------------------------------------------ */
/* main                                                                  */
/* ------------------------------------------------------------------ */
int main(void)
{
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open /dev/mali0 failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[main] /dev/mali0 opened fd=%d\n", fd);

    if (mali_init(fd) < 0) {
        puts("[main] mali_init failed");
        close(fd);
        return 1;
    }

    test_hwcnt(fd);
    test_surface(fd);
    test_secure_world(fd);

    puts("\n[main] probe complete");
    close(fd);
    return 0;
}
