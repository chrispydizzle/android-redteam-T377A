/*
 * mali_import_v2.c — Correct Mali MEM_IMPORT with proper ION struct alignment
 *
 * ROOT CAUSE OF CRASHES: Previous code used 64-bit fields (uint64_t len/align)
 * with ION_IOC_ALLOC, but on ARM32 size_t is 4 bytes. The ioctl copies only
 * 20 bytes, so our 28-byte struct was misaligned — we read back the ION
 * handle as if it were a dma_buf fd, then passed that handle number to
 * Mali MEM_IMPORT → kernel tried to dereference an invalid file* → PANIC.
 *
 * This file uses the CORRECT ARM32 struct layout and tests:
 * 1. ION alloc (old API, correct struct) + ION_IOC_SHARE → dma_buf fd
 * 2. Mali MEM_IMPORT with valid dma_buf fd
 * 3. Repeat to find if import actually works or always fails
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o mali_import_v2 mali_import_v2.c
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* ION old API — CORRECT for ARM32 */
typedef int ion_user_handle_t;
struct ion_allocation_data {
    uint32_t len;            /* size_t = 4 bytes on ARM32 */
    uint32_t align;          /* size_t = 4 bytes on ARM32 */
    uint32_t heap_id_mask;
    uint32_t flags;
    ion_user_handle_t handle; /* output */
};
/* Total: 20 bytes = matches ioctl 0xc0144900 */

struct ion_fd_data {
    ion_user_handle_t handle;
    int fd;
};

#define ION_IOC_ALLOC  _IOWR('I', 0, struct ion_allocation_data)
#define ION_IOC_FREE   _IOWR('I', 1, struct ion_fd_data)
#define ION_IOC_SHARE  _IOWR('I', 4, struct ion_fd_data)

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

/* MEM_IMPORT struct layout (from mali_import_probe.c analysis) */
/* Standard 48-byte layout:
 * [0-7]   uk_header (id/ret)
 * [8-15]  phandle (pointer to fd/handle)
 * [16-19] type
 * [20-23] padding
 * [24-31] va (output)
 * [32-39] va_pages (output?)
 * [40-43] flags
 * [44-47] padding
 */

static int get_dma_buf_fd(void) {
    int ion_fd = open("/dev/ion", O_RDONLY);
    if (ion_fd < 0) { perror("ion open"); return -1; }

    struct ion_allocation_data alloc = {
        .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0
    };
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        perror("ion alloc");
        close(ion_fd);
        return -1;
    }
    fprintf(stderr, "  ION handle=%d\n", alloc.handle);

    struct ion_fd_data share = { .handle = alloc.handle };
    if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) {
        perror("ion share");
        close(ion_fd);
        return -1;
    }
    fprintf(stderr, "  dma_buf fd=%d\n", share.fd);

    close(ion_fd);  /* Keep dma_buf fd alive */
    return share.fd;
}

static int mali_open_ctx(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static void try_import(int mali_fd, int dma_buf_fd, int type, uint32_t flags,
                       const char *label) {
    fprintf(stderr, "\n  [%s] type=%d flags=0x%08x dma_fd=%d\n", label, type, flags, dma_buf_fd);

    uint8_t buf[48];
    memset(buf, 0, 48);
    ((struct uk_header*)buf)->id = 513;  /* MEM_IMPORT */
    *(uint64_t*)(buf + 8) = (uintptr_t)&dma_buf_fd;  /* POINTER to fd */
    *(uint32_t*)(buf + 16) = type;
    *(uint32_t*)(buf + 40) = flags;

    int r = ioctl(mali_fd, make_cmd(48), buf);
    int e = errno;
    uint32_t result = ((struct uk_header*)buf)->id;

    fprintf(stderr, "  ioctl=%d errno=%d result=%u\n", r, e, result);

    /* Dump response for successful imports */
    if (r == 0 && result == 0) {
        uint64_t va = *(uint64_t*)(buf + 24);
        uint64_t pages = *(uint64_t*)(buf + 32);
        fprintf(stderr, "  *** SUCCESS! va=0x%llx pages=%llu ***\n",
                (unsigned long long)va, (unsigned long long)pages);

        /* Free the imported region */
        memset(buf, 0, 16);
        ((struct uk_header*)buf)->id = 516;
        *(uint64_t*)(buf + 8) = va;
        ioctl(mali_fd, make_cmd(16), buf);
        fprintf(stderr, "  Freed import region\n");
    }
}

int main(void) {
    fprintf(stderr, "=== Mali MEM_IMPORT v2 (correct ARM32 structs) ===\n");
    fprintf(stderr, "PID=%d UID=%d\n\n", getpid(), getuid());

    /* Get valid dma_buf fd */
    int dma_fd = get_dma_buf_fd();
    if (dma_fd < 0) return 1;

    /* Open Mali */
    int mali_fd = mali_open_ctx();
    if (mali_fd < 0) { perror("mali open"); return 1; }
    fprintf(stderr, "  Mali fd=%d\n", mali_fd);

    /* Try various import configurations */
    /* Mali r7p0 import types: 0=invalid, 1=UMP, 2=UMM(dma-buf) */
    uint32_t flags[] = {
        0x0F,           /* basic CPU_RD|WR|GPU_RD|WR */
        0x4000000F,     /* IMPORT_SHARED | RW */
        0x40000003,     /* IMPORT_SHARED | CPU_RD|WR */
        0,              /* no flags */
    };

    for (int type = 0; type <= 3; type++) {
        for (int fi = 0; fi < 4; fi++) {
            char label[64];
            snprintf(label, sizeof(label), "T%d_F%d", type, fi);
            try_import(mali_fd, dma_fd, type, flags[fi], label);
        }
    }

    /* Also try passing the fd directly (not pointer) with type=2 */
    fprintf(stderr, "\n--- Direct fd (not pointer) tests ---\n");
    {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uint64_t)dma_fd;  /* RAW fd, not pointer */
        *(uint32_t*)(buf + 16) = 2;
        *(uint32_t*)(buf + 40) = 0x4000000F;

        fprintf(stderr, "  direct fd=%d (NOT pointer)...\n", dma_fd);
        /* This is what caused the crash before — but with correct 'M' magic */
        int r = ioctl(mali_fd, make_cmd(48), buf);
        fprintf(stderr, "  ioctl=%d errno=%d result=%u\n", r, errno, ((struct uk_header*)buf)->id);
    }

    /* Try 32-byte struct size (from mali_fuzz_multithreaded) */
    fprintf(stderr, "\n--- Alternate struct layouts ---\n");
    {
        /* mali_fuzz_multithreaded layout:
         * header(8) + phandle(8) + type(8) + flags(8) + gpu_va(8) + va_pages(8) + usage(8)
         * But that's sizeof=56 */
        uint8_t buf[56];
        memset(buf, 0, 56);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&dma_fd;  /* pointer */
        *(uint64_t*)(buf + 16) = 2;                    /* type (64-bit) */
        *(uint64_t*)(buf + 24) = 0x4000000F;           /* flags */

        fprintf(stderr, "  56-byte layout, type@16(64), flags@24...\n");
        int r = ioctl(mali_fd, make_cmd(56), buf);
        fprintf(stderr, "  ioctl=%d errno=%d result=%u\n", r, errno, ((struct uk_header*)buf)->id);
    }

    close(dma_fd);
    close(mali_fd);

    fprintf(stderr, "\n--- dmesg ---\n");
    system("dmesg 2>/dev/null | grep -iE 'mali|kbase' | tail -5 2>/dev/null");
    fprintf(stderr, "\n=== Done ===\n");
    return 0;
}
