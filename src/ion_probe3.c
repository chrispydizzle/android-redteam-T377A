/*
 * ion_probe3.c — ION probe v3 (skip known-crash heap bits 2,3)
 *
 * CONFIRMED CRASH: heap_id_mask with bit 2 set → kernel crash on SM-T377A
 * Safe heaps: bit 0 (system), bit 1, bit 4 (contig)
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

struct ion_custom_data {
    unsigned int cmd;
    unsigned long arg;
};

struct ion_exynos_sync_data {
    int fd;
    unsigned int flags;
};

#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP     _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT  _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
#define ION_IOC_SYNC    _IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)
#define ION_IOC_CUSTOM  _IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

#define OK(msg) fprintf(stderr, "  [OK]   %s\n", msg)
#define FAIL(msg, e) fprintf(stderr, "  [FAIL] %s: %s (errno=%d)\n", msg, strerror(e), e)

int main(void) {
    fprintf(stderr, "=== ION Probe v3 (safe heaps only) ===\n\n");

    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) { FAIL("open", errno); return 1; }
    OK("open /dev/ion");

    /* Test only safe heap bits: 0, 1, 4.  SKIP: 2,3 (crash), 5+ (ENODEV) */
    fprintf(stderr, "\n--- Safe heap bits: 0, 1, 4 ---\n");
    unsigned int safe_bits[] = {0, 1, 4};
    for (int i = 0; i < 3; i++) {
        struct ion_allocation_data a = {0};
        a.len = 4096; a.align = 4096;
        a.heap_id_mask = (1u << safe_bits[i]);
        a.flags = 0;
        errno = 0;
        int ret = ioctl(fd, ION_IOC_ALLOC, &a);
        fprintf(stderr, "  bit %d (mask=0x%x): %s handle=%d\n",
                safe_bits[i], a.heap_id_mask,
                ret == 0 ? "OK" : "FAIL", ret == 0 ? a.handle : -1);
        if (ret == 0) {
            struct ion_handle_data f = { .handle = a.handle };
            ioctl(fd, ION_IOC_FREE, &f);
        }
    }

    /* Test size boundaries on system heap */
    fprintf(stderr, "\n--- Size boundaries (system heap bit 0) ---\n");
    size_t sizes[] = {1, 4096, 65536, 262144, 1048576, 4194304, 0};
    for (int i = 0; i < 7; i++) {
        struct ion_allocation_data a = {0};
        a.len = sizes[i]; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
        errno = 0;
        int ret = ioctl(fd, ION_IOC_ALLOC, &a);
        fprintf(stderr, "  size=%-10zu: %s (errno=%d)\n",
                sizes[i], ret == 0 ? "OK" : "FAIL", errno);
        if (ret == 0) {
            struct ion_handle_data f = { .handle = a.handle };
            ioctl(fd, ION_IOC_FREE, &f);
        }
    }

    /* Flag testing */
    fprintf(stderr, "\n--- Flag testing (system heap) ---\n");
    unsigned int flags[] = {0, 1, 2, 3, 8, 16, 32, 0xFF};
    const char *fn[] = {"0","CACHED(1)","SYNC(2)","C+S(3)","NOZEROED(8)","PROTECTED(16)","FORCE(32)","0xFF"};
    for (int i = 0; i < 8; i++) {
        struct ion_allocation_data a = {0};
        a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = flags[i];
        errno = 0;
        int ret = ioctl(fd, ION_IOC_ALLOC, &a);
        fprintf(stderr, "  flags=%-15s: %s (errno=%d)\n",
                fn[i], ret == 0 ? "OK" : "FAIL", errno);
        if (ret == 0) {
            struct ion_handle_data f = { .handle = a.handle };
            ioctl(fd, ION_IOC_FREE, &f);
        }
    }

    /* Full lifecycle */
    fprintf(stderr, "\n--- Full lifecycle: alloc→share→map→mmap→sync→import→free ---\n");
    {
        struct ion_allocation_data a = {0};
        a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
        if (ioctl(fd, ION_IOC_ALLOC, &a) != 0) { FAIL("alloc", errno); goto done; }
        fprintf(stderr, "  alloc: handle=%d\n", a.handle);

        struct ion_fd_data s = { .handle = a.handle, .fd = -1 };
        if (ioctl(fd, ION_IOC_SHARE, &s) != 0) { FAIL("share", errno); goto done; }
        fprintf(stderr, "  share: fd=%d\n", s.fd);

        struct ion_fd_data m = { .handle = a.handle, .fd = -1 };
        if (ioctl(fd, ION_IOC_MAP, &m) == 0) {
            void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, m.fd, 0);
            if (ptr != MAP_FAILED) {
                volatile char *p = (volatile char *)ptr;
                p[0] = 0x41; p[4095] = 0x42;
                fprintf(stderr, "  mmap: write OK (%02x %02x)\n", p[0], p[4095]);
                munmap(ptr, 4096);
            } else FAIL("mmap", errno);
            close(m.fd);
        } else FAIL("map", errno);

        struct ion_fd_data sy = { .fd = s.fd };
        errno = 0;
        int sr = ioctl(fd, ION_IOC_SYNC, &sy);
        fprintf(stderr, "  sync: ret=%d errno=%d\n", sr, errno);

        struct ion_fd_data imp = { .fd = s.fd, .handle = 0 };
        if (ioctl(fd, ION_IOC_IMPORT, &imp) == 0) {
            fprintf(stderr, "  import: handle=%d\n", imp.handle);
            struct ion_handle_data f2 = { .handle = imp.handle };
            ioctl(fd, ION_IOC_FREE, &f2);
        } else FAIL("import", errno);

        /* custom: exynos sync */
        struct ion_exynos_sync_data esd = { .fd = s.fd, .flags = 0 };
        struct ion_custom_data cd = { .cmd = 0, .arg = (unsigned long)&esd };
        errno = 0;
        int cr = ioctl(fd, ION_IOC_CUSTOM, &cd);
        fprintf(stderr, "  custom(exynos_sync): ret=%d errno=%d\n", cr, errno);

        close(s.fd);

        struct ion_handle_data f = { .handle = a.handle };
        errno = 0;
        int fr = ioctl(fd, ION_IOC_FREE, &f);
        fprintf(stderr, "  free: ret=%d errno=%d\n", fr, errno);
    }

    /* Double free test */
    fprintf(stderr, "\n--- Double free ---\n");
    {
        struct ion_allocation_data a = {0};
        a.len = 4096; a.align = 4096; a.heap_id_mask = 0x01; a.flags = 0;
        if (ioctl(fd, ION_IOC_ALLOC, &a) == 0) {
            struct ion_handle_data f = { .handle = a.handle };
            errno = 0;
            int r1 = ioctl(fd, ION_IOC_FREE, &f);
            fprintf(stderr, "  1st: ret=%d errno=%d\n", r1, errno);
            errno = 0;
            int r2 = ioctl(fd, ION_IOC_FREE, &f);
            fprintf(stderr, "  2nd: ret=%d errno=%d (%s)\n", r2, errno, strerror(errno));
        }
    }

    /* Bogus handles */
    fprintf(stderr, "\n--- Bogus handles ---\n");
    {
        int bogus[] = {0, -1, 999, 0x7FFFFFFF};
        for (int i = 0; i < 4; i++) {
            struct ion_handle_data f = { .handle = bogus[i] };
            errno = 0;
            int ret = ioctl(fd, ION_IOC_FREE, &f);
            fprintf(stderr, "  FREE(%d): ret=%d errno=%d\n", bogus[i], ret, errno);
        }
    }

    /* Check dmesg */
    fprintf(stderr, "\n--- dmesg (ion) ---\n");
    fflush(stderr);
    system("dmesg | grep -i 'ion\\|BUG\\|WARNING\\|panic' | tail -20");

done:
    close(fd);
    fprintf(stderr, "\n=== Probe v3 Complete ===\n");
    return 0;
}
