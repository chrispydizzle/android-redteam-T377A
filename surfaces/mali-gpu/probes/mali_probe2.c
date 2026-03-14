/*
 * mali_probe2.c — Determine correct Mali UK struct layout
 *
 * Probes MEM_ALLOC at every size from 8 to 128 to find the
 * correct struct size. Also scans function IDs to find active ones.
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

static unsigned int make_cmd(uint32_t size) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, size);
}

static void hexdump(const void *data, size_t len) {
    const uint8_t *p = data;
    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, "    %04zx: ", i);
        for (size_t j = 0; j < 16 && i+j < len; j++)
            fprintf(stderr, "%02x ", p[i+j]);
        fprintf(stderr, "\n");
    }
}

static int do_handshake(int fd) {
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = 0; /* CHECK_VERSION */
    buf[8] = 10; buf[9] = 0;
    if (ioctl(fd, make_cmd(16), buf) < 0) return -1;

    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = 530; /* SET_FLAGS */
    if (ioctl(fd, make_cmd(16), buf) < 0) return -1;

    fprintf(stderr, "[+] Handshake OK\n");
    return 0;
}

/* ============================================================ */
/* SCAN 1: Find correct MEM_ALLOC size                          */
/* ============================================================ */
static void scan_alloc_sizes(int fd) {
    fprintf(stderr, "\n=== SCAN: MEM_ALLOC at every size 8..128 ===\n");

    for (int sz = 8; sz <= 128; sz += 4) {
        uint8_t buf[256];
        memset(buf, 0, 256);
        ((struct uk_header*)buf)->id = 512; /* MEM_ALLOC */

        /* Place va_pages=1, commit_pages=1 at various offsets
         * to handle potential different layouts */
        if (sz >= 16) *(uint64_t*)(buf + 8) = 1;   /* va_pages */
        if (sz >= 24) *(uint64_t*)(buf + 16) = 1;   /* commit_pages */
        if (sz >= 32) *(uint64_t*)(buf + 24) = 0;   /* extent */
        if (sz >= 36) *(uint32_t*)(buf + 32) = 0x07; /* flags: CPU_RD|CPU_WR|GPU_RD */

        int r = ioctl(fd, make_cmd(sz), buf);
        uint32_t ret = ((struct uk_header*)buf)->ret;

        /* Check for any non-zero value that isn't our input */
        int has_output = 0;
        for (int i = 32; i < sz && i < 128; i += 4) {
            uint32_t v = *(uint32_t*)(buf + i);
            if (v != 0 && v != 0x07 && v != 1) {
                has_output = 1;
                break;
            }
        }

        if (r >= 0 && (ret != 0 || has_output)) {
            fprintf(stderr, "[!] size=%d: ioctl=%d ret=%u\n", sz, r, ret);
            hexdump(buf, sz < 80 ? sz : 80);
        } else if (r < 0 && errno != 14 && errno != 22) {
            fprintf(stderr, "[?] size=%d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }
}

/* ============================================================ */
/* SCAN 2: Try all function IDs 0-600 at size=16                */
/* ============================================================ */
static void scan_function_ids(int fd) {
    fprintf(stderr, "\n=== SCAN: Function IDs 0-600 at size=16 ===\n");

    for (int id = 0; id <= 600; id++) {
        uint8_t buf[16];
        memset(buf, 0, sizeof(buf));
        ((struct uk_header*)buf)->id = id;

        int r = ioctl(fd, make_cmd(16), buf);
        uint32_t ret = ((struct uk_header*)buf)->ret;

        if (r >= 0 && ret == 0) {
            /* Check if any output data */
            int has_data = 0;
            for (int i = 8; i < 16; i++) {
                if (buf[i] != 0) { has_data = 1; break; }
            }
            if (has_data || id < 2 || id == 530)
                fprintf(stderr, "[+] id=%d: OK ret=0 data=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                        id, buf[8], buf[9], buf[10], buf[11],
                        buf[12], buf[13], buf[14], buf[15]);
        } else if (r >= 0 && ret != 0 && ret != 4294967295u) {
            fprintf(stderr, "[?] id=%d: ret=%u\n", id, ret);
        }
    }
}

/* ============================================================ */
/* SCAN 3: Try MEM_ALLOC with size=16 (just header + maybe u64) */
/* ============================================================ */
static void scan_alloc_minimal(int fd) {
    fprintf(stderr, "\n=== SCAN: MEM_ALLOC minimal sizes ===\n");

    /* Some Mali UK versions use a different struct layout.
     * In very old versions, the "API version" of the UK interface
     * determines struct sizes. Let's try all reasonable sizes. */

    /* Also try different function IDs near 512 in case the mapping is off */
    for (int id = 510; id <= 545; id++) {
        for (int sz = 16; sz <= 80; sz += 8) {
            uint8_t buf[128];
            memset(buf, 0, 128);
            ((struct uk_header*)buf)->id = id;

            /* For MEM_ALLOC-like functions, put reasonable values */
            *(uint64_t*)(buf + 8) = 1;  /* first u64 after header */
            *(uint64_t*)(buf + 16) = 1; /* second u64 */
            *(uint32_t*)(buf + 32) = 0x07; /* flags */

            int r = ioctl(fd, make_cmd(sz), buf);
            uint32_t ret = ((struct uk_header*)buf)->ret;

            if (r >= 0 && ret == 0) {
                /* Check for gpu_va output (any non-trivial value) */
                for (int off = 8; off < sz; off += 4) {
                    uint32_t v = *(uint32_t*)(buf + off);
                    if (v != 0 && v != 1 && v != 0x07) {
                        fprintf(stderr, "[!] id=%d sz=%d: found value 0x%08x at offset %d\n",
                                id, sz, v, off);
                    }
                }
            }

            /* Only print interesting results */
            if (r >= 0 && ret == 0 && *(uint64_t*)(buf + 8) != 1) {
                fprintf(stderr, "[!] id=%d sz=%d ret=0 — response differs from input:\n", id, sz);
                hexdump(buf, sz);
            }
        }
    }
}

/* ============================================================ */
/* SCAN 4: What happens with the REAL ioctl encoding?           */
/* ============================================================ */
static void scan_ioctl_encoding(int fd) {
    fprintf(stderr, "\n=== SCAN: Alternative ioctl encodings ===\n");

    /* Maybe the Mali driver uses type=0x80 instead of 'M' */
    uint8_t types[] = { 'M', 0x80, 'G', 'K', 'B', 0 };
    uint8_t nrs[] = { 0, 1, 2, 3 };

    for (int t = 0; types[t]; t++) {
        for (int n = 0; n < 4; n++) {
            uint8_t buf[16];
            memset(buf, 0, sizeof(buf));
            ((struct uk_header*)buf)->id = 0; /* CHECK_VERSION */
            buf[8] = 10; buf[9] = 0;

            unsigned int cmd = _IOC(_IOC_READ | _IOC_WRITE, types[t], nrs[n], 16);
            int r = ioctl(fd, cmd, buf);
            if (r >= 0 && ((struct uk_header*)buf)->ret == 0) {
                fprintf(stderr, "[+] type=0x%02x nr=%d size=16: WORKS! version=%d.%d\n",
                        types[t], nrs[n], buf[8], buf[9]);
            }
        }
    }
}

/* ============================================================ */
/* SCAN 5: Try uk_header with different field sizes              */
/* ============================================================ */
static void scan_header_layout(int fd) {
    fprintf(stderr, "\n=== SCAN: UK header layout variants ===\n");

    /* Maybe uk_header is { u16 id; u16 ret; } instead of { u32 id; u32 ret; } */
    /* Or maybe it's { u32 id; u16 ret; u16 padding; } */

    /* Test 1: id as u16 at offset 0 */
    {
        uint8_t buf[16];
        memset(buf, 0, sizeof(buf));
        *(uint16_t*)(buf + 0) = 512; /* MEM_ALLOC as u16 */
        int r = ioctl(fd, make_cmd(16), buf);
        fprintf(stderr, "[*] id=512 as u16[0]: ioctl=%d ret_u32=%u\n",
                r, *(uint32_t*)(buf + 4));
    }

    /* Test 2: Look at what CHECK_VERSION returned more carefully */
    {
        uint8_t buf[32];
        memset(buf, 0xAA, sizeof(buf));
        *(uint32_t*)(buf + 0) = 0; /* id=CHECK_VERSION */
        *(uint32_t*)(buf + 4) = 0xAAAAAAAA; /* ret sentinel */
        *(uint16_t*)(buf + 8) = 10; /* major */
        *(uint16_t*)(buf + 10) = 0; /* minor */

        int r = ioctl(fd, make_cmd(16), buf);
        fprintf(stderr, "[*] CHECK_VERSION size=16 full dump:\n");
        hexdump(buf, 16);

        /* Try at size 32 */
        memset(buf, 0xBB, sizeof(buf));
        *(uint32_t*)(buf + 0) = 0;
        *(uint16_t*)(buf + 8) = 10;
        r = ioctl(fd, make_cmd(32), buf);
        fprintf(stderr, "[*] CHECK_VERSION size=32 full dump:\n");
        hexdump(buf, 32);
    }
}

int main(void) {
    fprintf(stderr, "=== Mali r7p0 Probe v2 ===\n\n");

    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[-] open: %s\n", strerror(errno));
        return 1;
    }

    if (do_handshake(fd) != 0) {
        fprintf(stderr, "[-] Handshake failed\n");
        close(fd);
        return 1;
    }

    scan_ioctl_encoding(fd);
    scan_header_layout(fd);
    scan_function_ids(fd);
    scan_alloc_minimal(fd);
    scan_alloc_sizes(fd);

    fprintf(stderr, "\n=== Probe v2 complete ===\n");
    close(fd);
    return 0;
}
