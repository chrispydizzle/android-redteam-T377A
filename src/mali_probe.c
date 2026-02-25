/*
 * mali_probe.c — Mali r7p0 diagnostics and stack size probe
 *
 * 1. Hexdumps MEM_ALLOC response to determine correct struct layout
 * 2. Probes maximum ioctl size (potential stack buffer overflow)
 * 3. Tests various flag combinations for MEM_ALLOC
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define DEV_PATH "/dev/mali0"

struct uk_header {
    uint32_t id;
    uint32_t ret;
};

#define UKP_FUNC_ID_CHECK_VERSION 0
#define KBASE_FUNC_SET_FLAGS      530
#define KBASE_FUNC_MEM_ALLOC      512
#define KBASE_FUNC_MEM_FREE       516
#define KBASE_FUNC_MEM_FLAGS_CHANGE 517
#define KBASE_FUNC_MEM_QUERY      515
#define KBASE_FUNC_GET_VERSION    528
#define KBASE_FUNC_GPU_PROPS_REG_DUMP 526
#define KBASE_FUNC_GET_CONTEXT_ID 543

#define BASE_MEM_PROT_CPU_RD    (1U << 0)
#define BASE_MEM_PROT_CPU_WR    (1U << 1)
#define BASE_MEM_PROT_GPU_RD    (1U << 2)
#define BASE_MEM_PROT_GPU_WR    (1U << 3)
#define BASE_MEM_PROT_GPU_EX    (1U << 4)
#define BASE_MEM_GROW_ON_GPF    (1U << 9)
#define BASE_MEM_COHERENT_LOCAL (1U << 11)
#define BASE_MEM_CACHED_CPU     (1U << 12)
#define BASE_MEM_SAME_VA        (1U << 17)
#define BASE_MEM_NEED_MMAP      (1U << 18)

static unsigned int make_cmd(uint32_t size) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, size);
}

static int mali_ioctl(int fd, void *buf, uint32_t size) {
    return ioctl(fd, make_cmd(size), buf);
}

static void hexdump(const void *data, size_t len) {
    const uint8_t *p = data;
    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, "  %04zx: ", i);
        for (size_t j = 0; j < 16 && i+j < len; j++)
            fprintf(stderr, "%02x ", p[i+j]);
        fprintf(stderr, "\n");
    }
}

static int do_handshake(int fd) {
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = UKP_FUNC_ID_CHECK_VERSION;
    buf[8] = 10; buf[9] = 0; /* major=10, minor=0 */
    if (mali_ioctl(fd, buf, sizeof(buf)) < 0)
        return -1;
    fprintf(stderr, "[+] CHECK_VERSION response:\n");
    hexdump(buf, sizeof(buf));

    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = KBASE_FUNC_SET_FLAGS;
    if (mali_ioctl(fd, buf, sizeof(buf)) < 0)
        return -1;
    fprintf(stderr, "[+] SET_FLAGS response:\n");
    hexdump(buf, sizeof(buf));

    return 0;
}

/* ============================================================ */
/* PROBE 1: Hexdump MEM_ALLOC responses with various flags      */
/* ============================================================ */
static void probe_mem_alloc(int fd) {
    fprintf(stderr, "\n=== PROBE 1: MEM_ALLOC hexdump ===\n");

    /* Try with a large buffer to capture full response */
    uint32_t flag_combos[] = {
        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD,
        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD,
        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR,
        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD | BASE_MEM_SAME_VA,
        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD | BASE_MEM_NEED_MMAP,
        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD | BASE_MEM_CACHED_CPU,
        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR,
    };

    for (int i = 0; i < (int)(sizeof(flag_combos)/sizeof(flag_combos[0])); i++) {
        uint8_t buf[128];
        memset(buf, 0xCC, sizeof(buf)); /* fill with sentinel */
        struct uk_header *hdr = (struct uk_header*)buf;
        hdr->id = KBASE_FUNC_MEM_ALLOC;
        hdr->ret = 0xCCCCCCCC;

        /* Standard layout: after uk_header (8 bytes):
         * u64 va_pages (8), u64 commit_pages (8), u64 extent (8),
         * u32 flags (4), u32 padding (4), u64 gpu_va (8),
         * u16 va_alignment (2), u16 padding[3] (6)
         * Total: 8 + 8 + 8 + 8 + 4 + 4 + 8 + 2 + 6 = 56 bytes
         */

        /* Set va_pages at offset 8 */
        *(uint64_t*)(buf + 8) = 1;  /* va_pages */
        *(uint64_t*)(buf + 16) = 1; /* commit_pages */
        *(uint64_t*)(buf + 24) = 0; /* extent */
        *(uint32_t*)(buf + 32) = flag_combos[i]; /* flags */
        *(uint32_t*)(buf + 36) = 0; /* padding */
        /* gpu_va at offset 40 should be filled by kernel */
        *(uint64_t*)(buf + 40) = 0xCCCCCCCCCCCCCCCCULL; /* sentinel */
        *(uint16_t*)(buf + 48) = 0; /* va_alignment */

        /* Try different sizes */
        int sizes[] = { 56, 64, 72, 80, 96, 128 };
        for (int s = 0; s < (int)(sizeof(sizes)/sizeof(sizes[0])); s++) {
            uint8_t tbuf[128];
            memcpy(tbuf, buf, sizeof(tbuf));

            int r = mali_ioctl(fd, tbuf, sizes[s]);
            struct uk_header *rhdr = (struct uk_header*)tbuf;
            if (r < 0) {
                fprintf(stderr, "[*] flags=0x%x size=%d: errno=%d (%s)\n",
                        flag_combos[i], sizes[s], errno, strerror(errno));
                continue;
            }
            fprintf(stderr, "[*] flags=0x%x size=%d: ret=%u\n",
                    flag_combos[i], sizes[s], rhdr->ret);

            if (rhdr->ret == 0) {
                /* Check for gpu_va at various offsets */
                fprintf(stderr, "    Response hexdump:\n");
                hexdump(tbuf, sizes[s]);

                /* Check potential gpu_va locations */
                for (int off = 8; off <= 64; off += 4) {
                    uint32_t v32 = *(uint32_t*)(tbuf + off);
                    if (v32 != 0 && v32 != 0xCCCCCCCC && v32 != 1 &&
                        v32 != flag_combos[i]) {
                        fprintf(stderr, "    [?] Non-zero at offset %d: 0x%08x\n",
                                off, v32);
                    }
                }
                for (int off = 8; off <= 56; off += 8) {
                    uint64_t v64 = *(uint64_t*)(tbuf + off);
                    if (v64 != 0 && v64 != 0xCCCCCCCCCCCCCCCCULL && v64 != 1) {
                        fprintf(stderr, "    [?] u64 at offset %d: 0x%llx\n",
                                off, (unsigned long long)v64);
                    }
                }

                /* Try to free whatever was allocated */
                uint8_t fbuf[24];
                memset(fbuf, 0, sizeof(fbuf));
                ((struct uk_header*)fbuf)->id = KBASE_FUNC_MEM_FREE;
                /* Try gpu_va from offset 40 */
                *(uint64_t*)(fbuf + 8) = *(uint64_t*)(tbuf + 40);
                mali_ioctl(fd, fbuf, sizeof(fbuf));
                break; /* only need first successful size */
            }
        }
    }
}

/* ============================================================ */
/* PROBE 2: Version and context info                             */
/* ============================================================ */
static void probe_version(int fd) {
    fprintf(stderr, "\n=== PROBE 2: GET_VERSION & CONTEXT_ID ===\n");

    uint8_t buf[64];
    memset(buf, 0xCC, sizeof(buf));
    ((struct uk_header*)buf)->id = KBASE_FUNC_GET_VERSION;
    int r = mali_ioctl(fd, buf, 32);
    fprintf(stderr, "[*] GET_VERSION: ioctl=%d, ret=%u\n", r,
            ((struct uk_header*)buf)->ret);
    if (r >= 0) hexdump(buf, 32);

    memset(buf, 0xCC, sizeof(buf));
    ((struct uk_header*)buf)->id = KBASE_FUNC_GET_CONTEXT_ID;
    r = mali_ioctl(fd, buf, 16);
    fprintf(stderr, "[*] GET_CONTEXT_ID: ioctl=%d, ret=%u\n", r,
            ((struct uk_header*)buf)->ret);
    if (r >= 0) hexdump(buf, 16);
}

/* ============================================================ */
/* PROBE 3: ioctl SIZE limit — find max accepted size            */
/* ============================================================ */
static void probe_max_size(int fd) {
    fprintf(stderr, "\n=== PROBE 3: MAX IOCTL SIZE ===\n");
    fprintf(stderr, "[*] Testing increasing ioctl sizes...\n");
    fprintf(stderr, "[!] WARNING: large sizes may overflow stack buffer!\n");
    fprintf(stderr, "[*] Using safe function ID (GET_VERSION) for size probing\n");

    /* Use a heap-allocated buffer to avoid our own stack issues */
    uint8_t *buf = calloc(1, 16384);
    if (!buf) return;

    /* Start from known-safe sizes, increase gradually */
    int test_sizes[] = {
        16, 32, 64, 128, 256, 384, 512,
        520, 528, 532, 536, 540, 544, 548, 552, 556, 560,
        576, 600, 640, 700, 768, 800, 900,
        1024, 1536, 2048, 4096, 8192,
        /* These might crash: */
        /* 12288, 16383 */
    };

    int max_ok = 0;
    int first_fail = 0;

    for (int i = 0; i < (int)(sizeof(test_sizes)/sizeof(test_sizes[0])); i++) {
        int sz = test_sizes[i];
        memset(buf, 0, sz);
        ((struct uk_header*)buf)->id = KBASE_FUNC_GET_VERSION;

        int r = mali_ioctl(fd, buf, sz);
        fprintf(stderr, "[*] size=%d: ioctl=%d, errno=%d, ret=%u\n",
                sz, r, (r < 0) ? errno : 0, ((struct uk_header*)buf)->ret);

        if (r >= 0) {
            max_ok = sz;
        } else if (first_fail == 0) {
            first_fail = sz;
        }
    }

    fprintf(stderr, "\n[*] Max OK size: %d bytes\n", max_ok);
    if (first_fail)
        fprintf(stderr, "[*] First failure at: %d bytes\n", first_fail);
    else
        fprintf(stderr, "[!] ALL sizes accepted! Stack buffer may be >= 8192\n");

    free(buf);
}

/* ============================================================ */
/* PROBE 4: GPU_PROPS_REG_DUMP (large response)                  */
/* ============================================================ */
static void probe_gpu_props(int fd) {
    fprintf(stderr, "\n=== PROBE 4: GPU_PROPS_REG_DUMP ===\n");

    uint8_t buf[536];
    memset(buf, 0xCC, sizeof(buf));
    ((struct uk_header*)buf)->id = KBASE_FUNC_GPU_PROPS_REG_DUMP;

    int r = mali_ioctl(fd, buf, sizeof(buf));
    fprintf(stderr, "[*] GPU_PROPS: ioctl=%d, ret=%u\n", r,
            ((struct uk_header*)buf)->ret);
    if (r >= 0 && ((struct uk_header*)buf)->ret == 0) {
        fprintf(stderr, "    First 128 bytes:\n");
        hexdump(buf, 128);
    }
}

/* ============================================================ */
/* PROBE 5: mmap the Mali fd with various offsets                */
/* ============================================================ */
static void probe_mmap(int fd) {
    fprintf(stderr, "\n=== PROBE 5: MMAP PROBING ===\n");

    /* Try mmap with offset=0 (should give us the context's BASE page) */
    void *p;
    uint64_t offsets[] = { 0, 4096, 0x1000, 0x10000, 0x100000 };
    for (int i = 0; i < (int)(sizeof(offsets)/sizeof(offsets[0])); i++) {
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
                 fd, offsets[i]);
        if (p != MAP_FAILED) {
            fprintf(stderr, "[!] mmap(offset=0x%llx) SUCCEEDED @ %p\n",
                    (unsigned long long)offsets[i], p);
            fprintf(stderr, "    First 16 bytes: ");
            for (int j = 0; j < 16; j++)
                fprintf(stderr, "%02x ", ((uint8_t*)p)[j]);
            fprintf(stderr, "\n");
            munmap(p, 4096);
        } else {
            fprintf(stderr, "[*] mmap(offset=0x%llx) failed: %s\n",
                    (unsigned long long)offsets[i], strerror(errno));
        }
    }
}

int main(void) {
    fprintf(stderr, "=== Mali r7p0 Probe ===\n\n");

    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[-] open: %s\n", strerror(errno));
        return 1;
    }

    if (do_handshake(fd) != 0) {
        close(fd);
        return 1;
    }

    probe_version(fd);
    probe_gpu_props(fd);
    probe_mem_alloc(fd);
    probe_mmap(fd);
    probe_max_size(fd);

    fprintf(stderr, "\n=== Probe complete ===\n");
    close(fd);
    return 0;
}
