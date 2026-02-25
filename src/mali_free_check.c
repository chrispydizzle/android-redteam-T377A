/*
 * mali_free_check.c — Verify cross-context free ACTUALLY works
 * Check header.id result code, not just ioctl return
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

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
    int r = ioctl(fd, make_cmd(56), buf);
    uint32_t result = ((struct uk_header*)buf)->id;
    uint64_t va = *(uint64_t*)(buf + 40);
    printf("  ALLOC: ioctl=%d result=%u va=0x%llx\n", r, result, (unsigned long long)va);
    if (r < 0 || result != 0) return 0;
    return va;
}

/* Free with FULL result checking */
static int mali_free_verbose(int fd, uint64_t va, const char *label) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    int r = ioctl(fd, make_cmd(16), buf);
    uint32_t result = ((struct uk_header*)buf)->id;
    printf("  FREE(%s): ioctl=%d result=%u (va=0x%llx)\n",
           label, r, result, (unsigned long long)va);
    return (r == 0 && result == 0) ? 0 : -1;
}

int main(void) {
    printf("=== Mali MEM_FREE Result Code Verification ===\n\n");

    int ctx1 = mali_open_ctx();
    int ctx2 = mali_open_ctx();
    printf("ctx1=%d ctx2=%d\n\n", ctx1, ctx2);

    /* TEST 1: Normal free — should return result=0 */
    printf("--- TEST 1: Normal free (ctx1 alloc, ctx1 free) ---\n");
    uint64_t va1 = mali_alloc(ctx1, 1, 0x0F);
    if (va1) mali_free_verbose(ctx1, va1, "normal");

    /* TEST 2: Cross-context free — check result */
    printf("\n--- TEST 2: Cross-context free (ctx1 alloc, ctx2 free) ---\n");
    uint64_t va2 = mali_alloc(ctx1, 1, 0x0F);
    if (va2) mali_free_verbose(ctx2, va2, "cross-ctx");

    /* TEST 3: Double free — first normal, then cross-context */
    printf("\n--- TEST 3: Double-free (ctx1 alloc, ctx1 free, ctx2 free) ---\n");
    uint64_t va3 = mali_alloc(ctx1, 1, 0x0F);
    if (va3) {
        mali_free_verbose(ctx1, va3, "normal");
        mali_free_verbose(ctx2, va3, "cross-ctx-after-free");
    }

    /* TEST 4: Free non-existent VA */
    printf("\n--- TEST 4: Free non-existent VA ---\n");
    mali_free_verbose(ctx1, 0x999000, "nonexistent");

    /* TEST 5: Free VA from ctx2 that only exists in ctx1 (5 regions) */
    printf("\n--- TEST 5: Bulk cross-context free (5 regions) ---\n");
    uint64_t vas[5];
    for (int i = 0; i < 5; i++)
        vas[i] = mali_alloc(ctx1, 1, 0x0F);
    printf("\n");
    for (int i = 0; i < 5; i++)
        if (vas[i]) mali_free_verbose(ctx2, vas[i], "xctx");

    /* TEST 6: After cross-context free, try to use from ctx1 */
    printf("\n--- TEST 6: Use after cross-context free ---\n");
    uint64_t va6 = mali_alloc(ctx1, 1, 0x0F);
    printf("\n  Cross-context free:\n");
    mali_free_verbose(ctx2, va6, "xctx");
    printf("\n  FLAGS_CHANGE on freed region:\n");
    {
        uint8_t buf[32];
        memset(buf, 0, 32);
        ((struct uk_header*)buf)->id = 517; /* FLAGS_CHANGE */
        *(uint64_t*)(buf + 8) = va6;
        *(uint32_t*)(buf + 16) = 0x1F; /* new flags */
        *(uint32_t*)(buf + 20) = 0x1F; /* mask */
        int r = ioctl(ctx1, make_cmd(32), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        printf("  FLAGS_CHANGE: ioctl=%d result=%u\n", r, result);
    }
    printf("\n  MEM_QUERY on freed region:\n");
    {
        uint8_t buf[64];
        memset(buf, 0, 64);
        ((struct uk_header*)buf)->id = 515; /* MEM_QUERY */
        *(uint64_t*)(buf + 8) = va6;
        *(uint32_t*)(buf + 16) = 1; /* KBASE_MEM_QUERY_COMMIT_SIZE */
        int r = ioctl(ctx1, make_cmd(64), buf);
        uint32_t result = ((struct uk_header*)buf)->id;
        uint64_t value = *(uint64_t*)(buf + 24);
        printf("  MEM_QUERY: ioctl=%d result=%u value=%llu\n",
               r, result, (unsigned long long)value);
    }
    printf("\n  Alloc new from ctx1 (should reuse VA):\n");
    uint64_t va6b = mali_alloc(ctx1, 1, 0x0F);
    printf("  va6=0x%llx va6b=0x%llx same=%s\n",
           (unsigned long long)va6, (unsigned long long)va6b,
           va6 == va6b ? "YES" : "NO");

    /* TEST 7: Alloc from ctx1 — does it get same VA? */
    printf("\n--- TEST 7: Alloc after normal free vs after cross-context free ---\n");
    uint64_t va7a = mali_alloc(ctx1, 1, 0x0F);
    mali_free_verbose(ctx1, va7a, "normal");
    uint64_t va7b = mali_alloc(ctx1, 1, 0x0F);
    printf("  After normal free: va7a=0x%llx va7b=0x%llx same=%s\n\n",
           (unsigned long long)va7a, (unsigned long long)va7b,
           va7a == va7b ? "YES" : "NO");
    mali_free_verbose(ctx1, va7b, "normal");

    uint64_t va7c = mali_alloc(ctx1, 1, 0x0F);
    mali_free_verbose(ctx2, va7c, "xctx");
    uint64_t va7d = mali_alloc(ctx1, 1, 0x0F);
    printf("  After xctx free: va7c=0x%llx va7d=0x%llx same=%s\n",
           (unsigned long long)va7c, (unsigned long long)va7d,
           va7c == va7d ? "YES" : "NO");

    close(ctx1);
    close(ctx2);

    printf("\n=== Done ===\n");
    return 0;
}
