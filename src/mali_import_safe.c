/*
 * mali_import_safe.c — Step-by-step Mali MEM_IMPORT with old ION API
 *
 * Uses ION_IOC_ALLOC + ION_IOC_SHARE (the classic API) instead of
 * the new combined API. Each step prints before/after and is isolated.
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o mali_import_safe mali_import_safe.c
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

/* ION old API */
typedef int ion_user_handle_t;
struct ion_allocation_data {
    size_t len; size_t align;
    unsigned int heap_id_mask; unsigned int flags;
    ion_user_handle_t handle;
};
struct ion_fd_data {
    ion_user_handle_t handle; int fd;
};
#define ION_IOC_ALLOC  _IOWR('I', 0, struct ion_allocation_data)
#define ION_IOC_FREE   _IOWR('I', 1, struct ion_fd_data)
#define ION_IOC_SHARE  _IOWR('I', 4, struct ion_fd_data)

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

int main(int argc, char **argv) {
    int test = 0;
    if (argc >= 2) test = atoi(argv[1]);

    fprintf(stderr, "=== Mali Import Safe Test (old ION API) ===\n");
    fprintf(stderr, "PID=%d test=%d\n", getpid(), test);
    fflush(stderr);

    if (test == 0) {
        /* Just print help and do basic sanity */
        fprintf(stderr, "Tests:\n");
        fprintf(stderr, "  1 = ION alloc + share only (no Mali)\n");
        fprintf(stderr, "  2 = Mali open + handshake only (no import)\n");
        fprintf(stderr, "  3 = Mali MEM_ALLOC only (no import)\n");
        fprintf(stderr, "  4 = Mali MEM_IMPORT type=2 (UMM), old ION API\n");
        fprintf(stderr, "  5 = Mali MEM_IMPORT type=1 (UMP), old ION API\n");
        fprintf(stderr, "  6 = Mali MEM_IMPORT type=0, old ION API\n");
        fprintf(stderr, "  7 = Mali MEM_IMPORT, new ION API (dma_buf fd direct)\n");
        return 0;
    }

    /* Test 1: ION only */
    if (test == 1) {
        fprintf(stderr, "\n--- ION alloc + share ---\n");
        int ion_fd = open("/dev/ion", O_RDONLY);
        if (ion_fd < 0) { perror("ion open"); return 1; }
        fprintf(stderr, "  ion_fd=%d\n", ion_fd);

        struct ion_allocation_data alloc = {
            .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0
        };
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) { perror("ion alloc"); return 1; }
        fprintf(stderr, "  handle=%d\n", alloc.handle);

        struct ion_fd_data share = { .handle = alloc.handle };
        if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) { perror("ion share"); return 1; }
        fprintf(stderr, "  dma_buf_fd=%d\n", share.fd);

        /* Verify mmap */
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, share.fd, 0);
        fprintf(stderr, "  mmap: %p (%s)\n", p, (p != MAP_FAILED) ? "OK" : strerror(errno));
        if (p != MAP_FAILED) munmap(p, 4096);

        close(share.fd);
        close(ion_fd);
        fprintf(stderr, "  ION test OK\n");
        return 0;
    }

    /* Test 2: Mali handshake only */
    if (test == 2) {
        fprintf(stderr, "\n--- Mali open + handshake ---\n");
        int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
        fprintf(stderr, "  mali_fd=%d\n", fd);
        if (fd < 0) return 1;

        uint8_t hb[16];
        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 0; hb[8] = 10;
        int r = ioctl(fd, make_cmd(16), hb);
        fprintf(stderr, "  version: ioctl=%d result=%u\n", r, ((struct uk_header*)hb)->id);

        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 530;
        r = ioctl(fd, make_cmd(16), hb);
        fprintf(stderr, "  set_flags: ioctl=%d result=%u\n", r, ((struct uk_header*)hb)->id);

        close(fd);
        fprintf(stderr, "  Mali handshake OK\n");
        return 0;
    }

    /* Test 3: Mali MEM_ALLOC */
    if (test == 3) {
        fprintf(stderr, "\n--- Mali MEM_ALLOC ---\n");
        int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
        if (fd < 0) return 1;
        uint8_t hb[16];
        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 0; hb[8] = 10;
        ioctl(fd, make_cmd(16), hb);
        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 530;
        ioctl(fd, make_cmd(16), hb);

        uint8_t buf[56];
        memset(buf, 0, 56);
        ((struct uk_header*)buf)->id = 512;
        *(uint64_t*)(buf + 8) = 1;
        *(uint64_t*)(buf + 16) = 1;
        *(uint32_t*)(buf + 32) = 0x0F;
        int r = ioctl(fd, make_cmd(56), buf);
        uint64_t va = *(uint64_t*)(buf + 40);
        fprintf(stderr, "  alloc: ioctl=%d result=%u va=0x%llx\n",
                r, ((struct uk_header*)buf)->id, (unsigned long long)va);

        /* Free */
        memset(buf, 0, 16);
        ((struct uk_header*)buf)->id = 516;
        *(uint64_t*)(buf + 8) = va;
        ioctl(fd, make_cmd(16), buf);

        close(fd);
        fprintf(stderr, "  Mali alloc OK\n");
        return 0;
    }

    /* Tests 4-7: MEM_IMPORT variants */
    if (test >= 4 && test <= 7) {
        /* Step 1: ION alloc */
        int ion_fd = open("/dev/ion", O_RDONLY);
        if (ion_fd < 0) { perror("ion open"); return 1; }

        int dma_buf_fd = -1;

        if (test <= 6) {
            /* Old ION API */
            struct ion_allocation_data alloc = {
                .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0
            };
            if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) { perror("ion alloc"); return 1; }
            struct ion_fd_data share = { .handle = alloc.handle };
            if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) { perror("ion share"); return 1; }
            dma_buf_fd = share.fd;
            fprintf(stderr, "  Old ION: handle=%d dma_buf_fd=%d\n", alloc.handle, dma_buf_fd);
        } else {
            /* New ION API */
            struct {
                uint64_t len; uint64_t align;
                uint32_t heap_id_mask; uint32_t flags; int32_t fd;
            } d = { .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0, .fd = -1 };
            if (ioctl(ion_fd, 0xc0144900, &d) < 0) { perror("ion alloc new"); return 1; }
            dma_buf_fd = d.fd;
            fprintf(stderr, "  New ION: dma_buf_fd=%d\n", dma_buf_fd);
        }

        /* Step 2: Mali open + handshake */
        int mali_fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
        if (mali_fd < 0) { perror("mali open"); return 1; }
        uint8_t hb[16];
        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 0; hb[8] = 10;
        ioctl(mali_fd, make_cmd(16), hb);
        memset(hb, 0, 16);
        ((struct uk_header*)hb)->id = 530;
        ioctl(mali_fd, make_cmd(16), hb);
        fprintf(stderr, "  Mali ready: fd=%d\n", mali_fd);

        /* Step 3: MEM_IMPORT */
        int type = 2;  /* default UMM */
        if (test == 5) type = 1;
        if (test == 6) type = 0;

        fprintf(stderr, "  About to call MEM_IMPORT type=%d phandle=&%d...\n", type, dma_buf_fd);
        fflush(stderr);
        usleep(100000);  /* 100ms flush time */

        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&dma_buf_fd;  /* POINTER to fd */
        *(uint32_t*)(buf + 16) = type;
        *(uint32_t*)(buf + 40) = 0x4000000F;

        int r = ioctl(mali_fd, make_cmd(48), buf);
        int e = errno;
        uint32_t result = ((struct uk_header*)buf)->id;
        uint64_t va = *(uint64_t*)(buf + 24);
        fprintf(stderr, "  RESULT: ioctl=%d errno=%d result=%u va=0x%llx\n",
                r, e, result, (unsigned long long)va);

        if (dma_buf_fd >= 0) close(dma_buf_fd);
        close(ion_fd);
        close(mali_fd);
        fprintf(stderr, "  Import test done\n");
        return 0;
    }

    return 0;
}
