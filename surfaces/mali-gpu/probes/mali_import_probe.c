/*
 * mali_import_probe.c — exhaustive MEM_IMPORT probing
 * Try all type values, flag combos, struct sizes, and field layouts
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

/* ION */
typedef int ion_user_handle_t;
struct ion_allocation_data { size_t len; size_t align; unsigned int heap_id_mask; unsigned int flags; ion_user_handle_t handle; };
struct ion_fd_data { ion_user_handle_t handle; int fd; };
#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/* Mali UK */
struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

static int mali_open_ctx(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0;
    hb[8] = 10;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static void hexdump_resp(uint8_t *buf, int sz) {
    for (int i = 0; i < sz; i += 4)
        printf("  [%2d] 0x%08x\n", i, *(uint32_t*)(buf + i));
}

int main(void) {
    printf("=== Mali MEM_IMPORT Exhaustive Probe ===\n\n");

    /* 1. Get ION dma-buf fd */
    int ion_fd = open("/dev/ion", O_RDONLY);
    if (ion_fd < 0) { perror("ion open"); return 1; }

    struct ion_allocation_data alloc = { .len = 4096, .align = 4096,
        .heap_id_mask = 1, .flags = 0 };
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) { perror("ion alloc"); return 1; }

    struct ion_fd_data share = { .handle = alloc.handle };
    if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) { perror("ion share"); return 1; }
    printf("[+] ION: handle=%d dma_buf_fd=%d\n\n", alloc.handle, share.fd);

    /* Verify dma_buf fd is valid */
    void *ion_map = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, share.fd, 0);
    printf("[+] ION mmap: %p (%s)\n\n", ion_map,
           ion_map != MAP_FAILED ? "OK" : strerror(errno));

    /* 2. Open Mali */
    int mali_fd = mali_open_ctx();
    if (mali_fd < 0) { perror("mali open"); return 1; }
    printf("[+] Mali context: fd=%d\n\n", mali_fd);

    /* 3. First verify MEM_ALLOC still works (as a sanity check) */
    {
        uint8_t buf[56];
        memset(buf, 0, 56);
        ((struct uk_header*)buf)->id = 512;
        *(uint64_t*)(buf + 8) = 1;  /* 1 page */
        *(uint64_t*)(buf + 16) = 1; /* commit 1 */
        *(uint32_t*)(buf + 32) = 0x0F; /* CPU_RD|CPU_WR|GPU_RD|GPU_WR */
        int r = ioctl(mali_fd, make_cmd(56), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        uint64_t va = *(uint64_t*)(buf + 40);
        printf("[*] MEM_ALLOC sanity: ioctl=%d result=%u gpu_va=0x%llx\n\n",
               r, result, (unsigned long long)va);
    }

    /* 4. Search firmware symbols for UMM/import hints */
    printf("--- Trying MEM_IMPORT (id=513) ---\n\n");

    /* Handle data on stack */
    int handle_data_fd = share.fd;
    int handle_data_handle = alloc.handle;

    /* Test A: Standard layout, all types */
    uint32_t types[] = { 0, 1, 2, 3, 4, 5 };
    char *type_names[] = { "INVALID", "UMP", "UMM/dma-buf", "USER_BUF", "4", "5" };

    for (int ti = 0; ti < 6; ti++) {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&handle_data_fd;
        *(uint32_t*)(buf + 16) = types[ti];
        *(uint32_t*)(buf + 40) = 0x4000000F; /* IMPORT_SHARED | CPU_RD|WR | GPU_RD|WR */

        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        uint64_t va = *(uint64_t*)(buf + 24);
        printf("  type=%u(%s): ioctl=%d result=%u va=0x%llx\n",
               types[ti], type_names[ti], r, result, (unsigned long long)va);
    }

    printf("\n");

    /* Test B: Various flag combos with type=2 (UMM) */
    printf("--- Flag variants with type=2 ---\n");
    uint32_t flag_combos[] = {
        0x0F,                          /* basic RW */
        0x4000000F,                    /* + IMPORT_SHARED */
        0x40000003,                    /* IMPORT_SHARED + CPU only */
        0x4000000C,                    /* IMPORT_SHARED + GPU only */
        0x40000001,                    /* IMPORT_SHARED + CPU_RD */
        0x40000100,                    /* IMPORT_SHARED + COHERENT_SYSTEM */
        0x40000200,                    /* IMPORT_SHARED + COHERENT_LOCAL */
        0x40002000,                    /* IMPORT_SHARED + CACHED_CPU */
        0x4000210F,                    /* IMPORT_SHARED + CACHED + COHERENT_LOCAL + RW */
        0x00000000,                    /* no flags at all */
        0x4000000F | (1<<10),          /* + SAME_VA */
        0x4000000F | (1<<11),          /* + NEED_MMAP */
    };
    for (int fi = 0; fi < 12; fi++) {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&handle_data_fd;
        *(uint32_t*)(buf + 16) = 2;
        *(uint32_t*)(buf + 40) = flag_combos[fi];

        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        uint64_t va = *(uint64_t*)(buf + 24);
        printf("  flags=0x%08x: ioctl=%d result=%u va=0x%llx\n",
               flag_combos[fi], r, result, (unsigned long long)va);
    }

    printf("\n");

    /* Test C: Different struct sizes */
    printf("--- Struct size variants ---\n");
    int sizes[] = { 32, 40, 48, 56, 64, 72, 80 };
    for (int si = 0; si < 7; si++) {
        uint8_t buf[80];
        memset(buf, 0, 80);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&handle_data_fd;
        *(uint32_t*)(buf + 16) = 2;
        /* Put flags in multiple places to see which one takes */
        if (sizes[si] >= 24) *(uint32_t*)(buf + 20) = 0x4000000F;
        if (sizes[si] >= 44) *(uint32_t*)(buf + 40) = 0x4000000F;

        int r = ioctl(mali_fd, make_cmd(sizes[si]), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  sz=%d: ioctl=%d(e=%d) result=%u\n",
               sizes[si], r, r < 0 ? errno : 0, result);
        if (r >= 0 && result == 0) {
            printf("  ** SUCCESS! Dumping response:\n");
            hexdump_resp(buf, sizes[si]);
        }
    }

    printf("\n");

    /* Test D: Alternate field layouts */
    printf("--- Alternate layouts ---\n");

    /* Layout 1: flags at offset 16, type at offset 20 */
    {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&handle_data_fd;
        *(uint32_t*)(buf + 16) = 0x4000000F; /* flags here */
        *(uint32_t*)(buf + 20) = 2;          /* type here */
        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  layout1(flags@16,type@20): ioctl=%d result=%u\n", r, result);
    }

    /* Layout 2: type at offset 8, phandle at offset 12 (32-bit) */
    {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint32_t*)(buf + 8) = 2;           /* type */
        *(uint32_t*)(buf + 12) = (uintptr_t)&handle_data_fd; /* phandle 32-bit */
        *(uint32_t*)(buf + 16) = 0x4000000F; /* flags */
        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  layout2(type@8,phandle@12,flags@16): ioctl=%d result=%u\n", r, result);
    }

    /* Layout 3: phandle is just the fd value directly (not pointer) */
    {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = share.fd;    /* fd directly, not pointer */
        *(uint32_t*)(buf + 16) = 2;
        *(uint32_t*)(buf + 40) = 0x4000000F;
        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  layout3(fd_direct@8): ioctl=%d result=%u\n", r, result);
    }

    /* Layout 4: ION handle directly (not fd) with type=1 (UMP uses handles) */
    {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&handle_data_handle;
        *(uint32_t*)(buf + 16) = 1;
        *(uint32_t*)(buf + 40) = 0x4000000F;
        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  layout4(ion_handle,type=UMP): ioctl=%d result=%u\n", r, result);
    }

    printf("\n");

    /* Test E: Check what function IDs 513/518/519 return vs known-bad */
    printf("--- Function ID availability ---\n");
    int test_ids[] = { 513, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527 };
    for (int i = 0; i < 11; i++) {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = test_ids[i];
        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  id=%d: ioctl=%d(e=%d) result=%u\n",
               test_ids[i], r, r < 0 ? errno : 0, result);
    }

    printf("\n");

    /* Test F: Check with /dev/mali0 fd directly as phandle (self-import) */
    printf("--- Self-import test ---\n");
    {
        int self_fd = mali_fd;
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&self_fd;
        *(uint32_t*)(buf + 16) = 2;
        *(uint32_t*)(buf + 40) = 0x4000000F;
        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  self(mali_fd): ioctl=%d result=%u\n", r, result);
    }

    /* Test G: Try a pipe fd as dma-buf (to see different error) */
    {
        int pipefd[2];
        pipe(pipefd);
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        *(uint64_t*)(buf + 8) = (uintptr_t)&pipefd[0];
        *(uint32_t*)(buf + 16) = 2;
        *(uint32_t*)(buf + 40) = 0x4000000F;
        int r = ioctl(mali_fd, make_cmd(48), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  pipe_fd: ioctl=%d result=%u\n", r, result);
        close(pipefd[0]); close(pipefd[1]);
    }

    printf("\n=== Done ===\n");
    close(mali_fd);
    close(ion_fd);
    if (ion_map != MAP_FAILED) munmap(ion_map, 4096);
    close(share.fd);
    return 0;
}
