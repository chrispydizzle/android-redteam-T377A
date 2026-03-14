#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
#define KBASE_FUNC_MEM_FREE    (UK_FUNC_ID + 4)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_MEM_PROT_CPU_RD (1U << 0)
#define BASE_MEM_PROT_CPU_WR (1U << 1)
#define BASE_MEM_PROT_GPU_RD (1U << 2)
#define BASE_MEM_PROT_GPU_WR (1U << 3)
#define BASE_MEM_COHERENT_LOCAL (1U << 11)

#define BASE_JD_REQ_CS (1U << 1)
#define BASE_JD_REQ_CF (1U << 3)
#define BASE_JD_REQ_V  (1U << 4)

#define MALI_JOB_TYPE_WRITE_VALUE 2
#define MALI_WRITE_VALUE_TYPE_CYCLE_COUNTER 1
#define MALI_WRITE_VALUE_TYPE_SYSTEM_TIMESTAMP 2
#define MALI_WRITE_VALUE_TYPE_ZERO 3
#define MALI_WRITE_VALUE_TYPE_IMMEDIATE_8 4
#define MALI_WRITE_VALUE_TYPE_IMMEDIATE_16 5
#define MALI_WRITE_VALUE_TYPE_IMMEDIATE_32 6
#define MALI_WRITE_VALUE_TYPE_IMMEDIATE_64 7
#define BASE_JD_EVENT_DONE 0x01
#define BASE_JD_EVENT_TERMINATED 0x04
#define BASE_JD_EVENT_JOB_CONFIG_FAULT 0x40
#define BASE_JD_EVENT_JOB_READ_FAULT 0x42
#define BASE_JD_EVENT_JOB_WRITE_FAULT 0x43
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x58
#define BASE_JD_EVENT_JOB_CANCELLED 0x4002

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

struct kbase_uk_mem_free {
    uk_header header;
    uint64_t gpu_addr;
};

struct base_jd_udata {
    uint64_t blob[2];
};

struct base_dependency {
    uint8_t atom_id;
    uint8_t dependency_type;
};

struct base_jd_atom_v2_live {
    uint64_t jc;
    struct base_jd_udata udata;
    uint64_t extres_list;
    uint16_t nr_extres;
    uint8_t jit_id[2];
    struct base_dependency pre_dep[2];
    uint8_t atom_number;
    uint8_t prio;
    uint8_t device_nr;
    uint8_t jobslot;
    uint32_t core_req;
    uint8_t renderpass_id;
    uint8_t padding[7];
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

struct mali_job_header {
    uint32_t exception_status;
    uint32_t first_incomplete_task;
    uint64_t fault_pointer;
    uint8_t is_64b;
    uint8_t type;
    uint8_t barrier;
    uint8_t invalidate_cache;
    uint8_t suppress_prefetch;
    uint8_t enable_texture_mapper;
    uint8_t relax_dependency_1;
    uint8_t relax_dependency_2;
    uint32_t index;
    uint32_t dependency_1;
    uint32_t dependency_2;
    uint64_t next;
};

struct mali_write_value_job_payload {
    uint64_t address;
    uint32_t type;
    uint32_t reserved;
    uint64_t immediate_value;
};

_Static_assert(sizeof(struct base_jd_atom_v2_live) == 56, "live atom size mismatch");
_Static_assert(sizeof(struct base_jd_atom_v2_old56) == 56, "old56 atom size mismatch");
_Static_assert(sizeof(struct kbase_uk_job_submit_trace) == 32, "submit trace size mismatch");
_Static_assert(sizeof(struct base_jd_event_v2) == 24, "event size mismatch");
_Static_assert(sizeof(struct mali_write_value_job_payload) == 24, "payload size mismatch");

static const char *event_name(uint32_t code);

static int mali_ioctl(int fd, void *buf, size_t size)
{
    errno = 0;
    return ioctl(fd, MALI_IOCTL(size), buf);
}

static uint64_t pack_bits64(uint64_t v, uint32_t start, uint32_t end)
{
    return v << start;
}

static void pack_job_header(uint32_t *cl, const struct mali_job_header *h)
{
    cl[0] = h->exception_status;
    cl[1] = h->first_incomplete_task;
    cl[2] = (uint32_t)h->fault_pointer;
    cl[3] = (uint32_t)(h->fault_pointer >> 32);
    cl[4] = (uint32_t)(
        pack_bits64(h->is_64b, 0, 0) |
        pack_bits64(h->type, 1, 7) |
        pack_bits64(h->barrier, 8, 8) |
        pack_bits64(h->invalidate_cache, 9, 9) |
        pack_bits64(h->suppress_prefetch, 11, 11) |
        pack_bits64(h->enable_texture_mapper, 12, 12) |
        pack_bits64(h->relax_dependency_1, 14, 14) |
        pack_bits64(h->relax_dependency_2, 15, 15) |
        pack_bits64(h->index, 16, 31));
    cl[5] = (uint32_t)(
        pack_bits64(h->dependency_1, 0, 15) |
        pack_bits64(h->dependency_2, 16, 31));
    cl[6] = (uint32_t)h->next;
    cl[7] = (uint32_t)(h->next >> 32);
}

static void pack_write_value_payload(uint32_t *cl, const struct mali_write_value_job_payload *p)
{
    cl[0] = (uint32_t)p->address;
    cl[1] = (uint32_t)(p->address >> 32);
    cl[2] = p->type;
    cl[3] = 0;
    cl[4] = (uint32_t)p->immediate_value;
    cl[5] = (uint32_t)(p->immediate_value >> 32);
}

static int mali_init(int fd)
{
    struct uku_version_check_args ver;
    struct kbase_uk_set_flags flags;

    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10;
    ver.minor = 2;
    if (mali_ioctl(fd, &ver, sizeof(ver)) < 0) {
        printf("CHECK_VERSION ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("CHECK_VERSION ret=%u version=%u.%u\n", ver.header.ret, ver.major, ver.minor);
    if (ver.header.ret != 0)
        return -1;

    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    if (mali_ioctl(fd, &flags, sizeof(flags)) < 0) {
        printf("SET_FLAGS ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("SET_FLAGS ret=%u\n", flags.header.ret);
    return flags.header.ret == 0 ? 0 : -1;
}

static int mali_setup_mtp(int fd)
{
    void *mtp;

    mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                          PROT_NONE, MAP_SHARED, fd, (unsigned long)2);
    if (mtp == MAP_FAILED) {
        mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                              PROT_NONE, MAP_SHARED, fd, (unsigned long)3);
    }
    if (mtp == MAP_FAILED) {
        printf("MTP mmap failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    printf("MTP mapped at %p\n", mtp);
    return 0;
}

static uint64_t mali_alloc(int fd, uint64_t pages, uint32_t flags)
{
    struct kbase_uk_mem_alloc alloc;

    memset(&alloc, 0, sizeof(alloc));
    alloc.header.id = KBASE_FUNC_MEM_ALLOC;
    alloc.va_pages = pages;
    alloc.commit_pages = pages;
    alloc.extent = pages;
    alloc.flags = flags;

    if (mali_ioctl(fd, &alloc, sizeof(alloc)) < 0) {
        printf("MEM_ALLOC ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return 0;
    }

    printf("MEM_ALLOC ret=%u gpu_va=0x%llx pages=%llu flags=0x%x\n",
           alloc.header.ret,
           (unsigned long long)alloc.gpu_va,
           (unsigned long long)pages,
           flags);

    return alloc.header.ret == 0 ? alloc.gpu_va : 0;
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, size_t size, int prot)
{
    unsigned long pgoff = (unsigned long)(gpu_va >> 12);
    void *p = (void *)syscall(__NR_mmap2, (unsigned long)NULL, size, prot,
                              MAP_SHARED, fd, pgoff);
    if (p == MAP_FAILED) {
        printf("mmap2 failed for gpu_va=0x%llx errno=%d (%s)\n",
               (unsigned long long)gpu_va, errno, strerror(errno));
        return MAP_FAILED;
    }

    printf("CPU mapped gpu_va=0x%llx at %p\n", (unsigned long long)gpu_va, p);
    return p;
}

static void mali_free(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_free mf;

    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = gpu_va;
    if (mali_ioctl(fd, &mf, sizeof(mf)) < 0) {
        printf("MEM_FREE ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    printf("MEM_FREE ret=%u gpu_va=0x%llx\n", mf.header.ret, (unsigned long long)gpu_va);
}

static int read_event(int fd, struct base_jd_event_v2 *ev)
{
    struct pollfd pfd;
    ssize_t n;
    int rc;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR | POLLHUP;

    rc = poll(&pfd, 1, 1000);
    if (rc <= 0) {
        printf("poll rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
        return -1;
    }

    printf("poll revents=0x%x\n", pfd.revents);
    memset(ev, 0, sizeof(*ev));
    n = read(fd, ev, sizeof(*ev));
    if (n != (ssize_t)sizeof(*ev)) {
        printf("read returned %lld errno=%d (%s)\n", (long long)n, errno, strerror(errno));
        return -1;
    }

    printf("event_code=0x%08x (%s) atom=%u udata=[0x%016llx,0x%016llx]\n",
           ev->event_code,
           event_name(ev->event_code),
           ev->atom_number,
           (unsigned long long)ev->udata.blob[0],
           (unsigned long long)ev->udata.blob[1]);
    return 0;
}

static const char *event_name(uint32_t code)
{
    switch (code) {
    case BASE_JD_EVENT_DONE:
        return "DONE";
    case BASE_JD_EVENT_TERMINATED:
        return "TERMINATED";
    case BASE_JD_EVENT_JOB_CONFIG_FAULT:
        return "JOB_CONFIG_FAULT";
    case BASE_JD_EVENT_JOB_READ_FAULT:
        return "JOB_READ_FAULT";
    case BASE_JD_EVENT_JOB_WRITE_FAULT:
        return "JOB_WRITE_FAULT";
    case BASE_JD_EVENT_DATA_INVALID_FAULT:
        return "DATA_INVALID_FAULT";
    case BASE_JD_EVENT_JOB_CANCELLED:
        return "JOB_CANCELLED";
    default:
        return "UNKNOWN";
    }
}

static int submit_write_value_job(int fd, uint64_t jc_addr, uint8_t atom_number, uint32_t core_req, int use_old56)
{
    struct kbase_uk_job_submit_trace submit;
    void *buf;
    int rc;

    buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        printf("mmap atom buffer failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    memset(buf, 0, 4096);
    if (use_old56) {
        struct base_jd_atom_v2_old56 *atom = (struct base_jd_atom_v2_old56 *)buf;
        atom->jc = jc_addr;
        atom->udata.blob[0] = 0xABCDEF0102030405ULL;
        atom->udata.blob[1] = 0x1122334455667788ULL;
        atom->atom_number = atom_number;
        atom->core_req = (uint16_t)core_req;
    } else {
        struct base_jd_atom_v2_live *atom = (struct base_jd_atom_v2_live *)buf;
        atom->jc = jc_addr;
        atom->udata.blob[0] = 0xABCDEF0102030405ULL;
        atom->udata.blob[1] = 0x1122334455667788ULL;
        atom->atom_number = atom_number;
        atom->core_req = core_req;
    }

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)buf;
    submit.nr_atoms = 1;
    submit.stride = 56;

    rc = mali_ioctl(fd, &submit, sizeof(submit));
    printf("JOB_SUBMIT[%s] rc=%d errno=%d (%s) ret=%u stride=%u core_req=0x%x jc=0x%llx\n",
           use_old56 ? "old56" : "new56",
           rc, errno, strerror(errno), submit.header.ret, submit.stride, core_req,
           (unsigned long long)jc_addr);

    munmap(buf, 4096);
    return (rc == 0 && submit.header.ret == 0) ? 0 : -1;
}

static void try_one(int fd, uint32_t *jc_cpu, uint64_t jc_gpu_va,
                    uint64_t *dest_cpu, uint64_t dest_gpu_va,
                    uint8_t atom_nr, uint32_t core_req, const char *cr_name,
                    uint8_t hdr_type, uint8_t is_64b, const char *hdr_name,
                    uint32_t ptype, uint64_t imm, const char *pt_name,
                    uint64_t prefill)
{
    struct mali_job_header header;
    struct mali_write_value_job_payload payload;
    struct base_jd_event_v2 ev;

    memset(&header, 0, sizeof(header));
    header.is_64b = is_64b;
    header.type = hdr_type;
    header.index = 1;

    memset(&payload, 0, sizeof(payload));
    payload.address = dest_gpu_va;
    payload.type = ptype;
    payload.immediate_value = imm;

    memset(jc_cpu, 0, 56);
    pack_job_header(jc_cpu, &header);
    pack_write_value_payload(jc_cpu + 8, &payload);

    /* prefill dest and flush */
    memset(dest_cpu, 0xAA, 4096);
    msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    uint64_t before = dest_cpu[0];

    /* dump raw descriptor */
    printf("[%s,%s,%s] desc:", hdr_name, pt_name, cr_name);
    for (int w = 0; w < 14; w++)
        printf(" %08x", jc_cpu[w]);
    printf("\n  prefill=0x%016llx ", (unsigned long long)before);
    fflush(stdout);

    if (submit_write_value_job(fd, jc_gpu_va, atom_nr, core_req, 1) < 0)
        return;

    if (read_event(fd, &ev) < 0)
        return;

    /* multiple read-back strategies */
    uint64_t direct = dest_cpu[0];
    msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    uint64_t after_sync = dest_cpu[0];

    printf("direct=0x%016llx synced=0x%016llx",
           (unsigned long long)direct,
           (unsigned long long)after_sync);

    if (direct != prefill || after_sync != prefill) {
        printf(" *** CHANGED ***");
    }
    printf("\n");
}

static void run_probe(void)
{
    struct base_jd_event_v2 ev;
    uint64_t jc_gpu_va = 0, dest_gpu_va = 0, dest2_gpu_va = 0;
    uint64_t *dest_cpu = MAP_FAILED, *dest2_cpu = MAP_FAILED;
    uint32_t *jc_cpu = MAP_FAILED;
    uint8_t an = 1;
    int fd;

    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { printf("open failed\n"); return; }

    printf("Opened /dev/mali0 fd=%d\n", fd);
    if (mali_init(fd) < 0 || mali_setup_mtp(fd) < 0)
        goto out;

    /* alloc JC page — always with coherency */
    jc_gpu_va = mali_alloc(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                BASE_MEM_COHERENT_LOCAL);
    /* dest1: with COHERENT_LOCAL */
    dest_gpu_va = mali_alloc(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                  BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                  BASE_MEM_COHERENT_LOCAL);
    /* dest2: WITHOUT coherency (plain RW) */
    dest2_gpu_va = mali_alloc(fd, 1, BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                   BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR);
    if (!jc_gpu_va || !dest_gpu_va || !dest2_gpu_va)
        goto out;

    jc_cpu = (uint32_t *)mali_cpu_map(fd, jc_gpu_va, 4096, PROT_READ | PROT_WRITE);
    dest_cpu = (uint64_t *)mali_cpu_map(fd, dest_gpu_va, 4096, PROT_READ | PROT_WRITE);
    dest2_cpu = (uint64_t *)mali_cpu_map(fd, dest2_gpu_va, 4096, PROT_READ | PROT_WRITE);
    if (jc_cpu == MAP_FAILED || dest_cpu == MAP_FAILED || dest2_cpu == MAP_FAILED)
        goto out;

    printf("\n=== PHASE 1: WRITE_VALUE is_64b=1, CS-only, coherent dest ===\n");
    printf("--- type=ZERO (should clear 0xAA fill) ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_ZERO, 0, "ZERO",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=CYCLE_COUNTER ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_CYCLE_COUNTER, 0, "CYCLE",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=SYSTEM_TIMESTAMP ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_SYSTEM_TIMESTAMP, 0, "TSTAMP",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=IMMEDIATE_32 ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_IMMEDIATE_32, 0xCAFEBABEULL, "IMM32",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=IMMEDIATE_64 ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_IMMEDIATE_64, 0xDEADBEEFCAFEBABEULL, "IMM64",
            0xAAAAAAAAAAAAAAAAULL);

    printf("\n=== PHASE 2: WRITE_VALUE is_64b=0 (32-bit descriptor), CS-only ===\n");
    printf("--- type=ZERO ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 0, "WV/32b",
            MALI_WRITE_VALUE_TYPE_ZERO, 0, "ZERO",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=CYCLE_COUNTER ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 0, "WV/32b",
            MALI_WRITE_VALUE_TYPE_CYCLE_COUNTER, 0, "CYCLE",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=IMMEDIATE_64 ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest_cpu, dest_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 0, "WV/32b",
            MALI_WRITE_VALUE_TYPE_IMMEDIATE_64, 0xDEADBEEFCAFEBABEULL, "IMM64",
            0xAAAAAAAAAAAAAAAAULL);

    printf("\n=== PHASE 3: non-coherent dest buffer, is_64b=1, CS-only ===\n");
    printf("--- type=ZERO ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest2_cpu, dest2_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_ZERO, 0, "ZERO",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=CYCLE_COUNTER ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest2_cpu, dest2_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_CYCLE_COUNTER, 0, "CYCLE",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=IMMEDIATE_64 ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest2_cpu, dest2_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 1, "WV/64b",
            MALI_WRITE_VALUE_TYPE_IMMEDIATE_64, 0xDEADBEEFCAFEBABEULL, "IMM64",
            0xAAAAAAAAAAAAAAAAULL);

    printf("\n=== PHASE 4: non-coherent dest, is_64b=0 (32-bit), CS-only ===\n");
    printf("--- type=ZERO ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest2_cpu, dest2_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 0, "WV/32b",
            MALI_WRITE_VALUE_TYPE_ZERO, 0, "ZERO",
            0xAAAAAAAAAAAAAAAAULL);

    printf("--- type=IMMEDIATE_64 ---\n");
    try_one(fd, jc_cpu, jc_gpu_va, dest2_cpu, dest2_gpu_va,
            an++, BASE_JD_REQ_CS, "CS",
            2, 0, "WV/32b",
            MALI_WRITE_VALUE_TYPE_IMMEDIATE_64, 0xDEADBEEFCAFEBABEULL, "IMM64",
            0xAAAAAAAAAAAAAAAAULL);

    printf("\n=== PHASE 5: payload offset experiments (is_64b=1, CS) ===\n");
    printf("Trying payload at word offsets 4, 6, 8 (standard) with IMM64\n");
    {
        /* Try payload at different offsets within the 56-byte descriptor */
        int payload_offsets[] = { 4, 6, 8 }; /* word offsets */
        for (int po = 0; po < 3; po++) {
            memset(jc_cpu, 0, 56);

            struct mali_job_header hdr2;
            struct mali_write_value_job_payload pay2;
            memset(&hdr2, 0, sizeof(hdr2));
            hdr2.is_64b = 1;
            hdr2.type = 2; /* WRITE_VALUE */
            hdr2.index = 1;

            memset(&pay2, 0, sizeof(pay2));
            pay2.address = dest_gpu_va;
            pay2.type = MALI_WRITE_VALUE_TYPE_IMMEDIATE_64;
            pay2.immediate_value = 0xDEADBEEFCAFEBABEULL;

            pack_job_header(jc_cpu, &hdr2);
            pack_write_value_payload(jc_cpu + payload_offsets[po], &pay2);

            memset(dest_cpu, 0xAA, 4096);
            msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

            printf("  payload@word%d: ", payload_offsets[po]);
            for (int w = 0; w < 14; w++)
                printf("%08x ", jc_cpu[w]);

            if (submit_write_value_job(fd, jc_gpu_va, an++, BASE_JD_REQ_CS, 1) < 0) {
                printf("SUBMIT FAILED\n");
                continue;
            }
            struct base_jd_event_v2 ev2;
            if (read_event(fd, &ev2) < 0) continue;

            msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
            uint64_t val = dest_cpu[0];
            printf("dest=0x%016llx%s\n", (unsigned long long)val,
                   (val != 0 && val != 0xAAAAAAAAAAAAAAAAULL) ? " *** NON-ZERO WRITE! ***" : "");
        }
    }

    printf("\n=== PHASE 6: raw type-in-word10 sweep ===\n");
    printf("Placing different type values to confirm GPU reads word 10\n");
    {
        /* Sweep the type field to see if any value produces non-zero write */
        uint32_t types_to_try[] = {
            0, 1, 2, 3, 4, 5, 6, 7,
            0x100, 0x200, 0x300, 0x700,
        };
        for (int ti = 0; ti < 12; ti++) {
            memset(jc_cpu, 0, 56);
            struct mali_job_header hdr3;
            memset(&hdr3, 0, sizeof(hdr3));
            hdr3.is_64b = 1;
            hdr3.type = 2;
            hdr3.index = 1;
            pack_job_header(jc_cpu, &hdr3);

            /* pack payload manually */
            jc_cpu[8] = (uint32_t)dest_gpu_va;
            jc_cpu[9] = (uint32_t)(dest_gpu_va >> 32);
            jc_cpu[10] = types_to_try[ti];
            jc_cpu[11] = 0;
            jc_cpu[12] = 0xCAFEBABE;
            jc_cpu[13] = 0xDEADBEEF;

            memset(dest_cpu, 0xBB, 4096);
            msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

            if (submit_write_value_job(fd, jc_gpu_va, an++, BASE_JD_REQ_CS, 1) < 0)
                continue;
            struct base_jd_event_v2 ev3;
            if (read_event(fd, &ev3) < 0) continue;

            msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
            uint64_t val = dest_cpu[0];
            printf("  type=0x%03x → dest=0x%016llx ev=0x%x%s\n",
                   types_to_try[ti],
                   (unsigned long long)val,
                   ev3.event_code,
                   (val != 0 && val != 0xBBBBBBBBBBBBBBBBULL) ? " *** CHANGED ***" : "");
        }
    }

    printf("\n=== PHASE 7: saturate descriptor with imm value ===\n");
    {
        uint32_t *d32 = (uint32_t *)dest_cpu;

        /* Fill EVERYTHING except the header type field and address with
         * our target value so no matter where the GPU reads from, it
         * will find 0xCAFEBABE / 0xDEADBEEF */
        struct mali_job_header hdr5;
        memset(&hdr5, 0, sizeof(hdr5));
        hdr5.is_64b = 1;
        hdr5.type = 2;
        hdr5.index = 1;

        memset(jc_cpu, 0, 4096);
        pack_job_header(jc_cpu, &hdr5);
        jc_cpu[8] = (uint32_t)dest_gpu_va;
        jc_cpu[9] = (uint32_t)(dest_gpu_va >> 32);
        jc_cpu[10] = MALI_WRITE_VALUE_TYPE_IMMEDIATE_64; /* 7 */
        jc_cpu[11] = 0;
        /* Fill words 12-13 AND also stuff value into reserved/padding
         * areas of the header in case the GPU reads from there */
        jc_cpu[12] = 0xCAFEBABE;
        jc_cpu[13] = 0xDEADBEEF;
        /* Also place value at other potential offsets within 64-byte range */
        jc_cpu[2] = 0xCAFEBABE;  /* fault_pointer lo */
        jc_cpu[3] = 0xDEADBEEF;  /* fault_pointer hi */
        /* Also at word 0-1 (exception_status + first_incomplete) */
        jc_cpu[0] = 0xCAFEBABE;
        jc_cpu[1] = 0xDEADBEEF;

        /* Re-pack header on top since we just clobbered word 0-3 */
        /* Actually don't — let's see if the GPU uses these fields as value */

        printf("  Saturated desc (value everywhere):\n");
        for (int r = 0; r < 16; r += 4)
            printf("    [%2d]: %08x %08x %08x %08x\n",
                   r, jc_cpu[r], jc_cpu[r+1], jc_cpu[r+2], jc_cpu[r+3]);

        memset(dest_cpu, 0xDD, 4096);
        msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

        if (submit_write_value_job(fd, jc_gpu_va, an++, BASE_JD_REQ_CS, 1) == 0) {
            struct base_jd_event_v2 ev5;
            if (read_event(fd, &ev5) == 0) {
                msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
                printf("  event=0x%x dest[0-3]: %08x %08x %08x %08x\n",
                       ev5.event_code, d32[0], d32[1], d32[2], d32[3]);
            }
        }

        /* Now a clean test: proper header, IMMEDIATE_64, value in words 12-13
         * BUT also place value at words 6-7 (the 'next' field of header).
         * If the GPU hardware uses 'next' pointer area as immediate, we'd see it */
        printf("\n  Test 2: proper header + value in next field (words 6-7)\n");
        memset(jc_cpu, 0, 64);
        pack_job_header(jc_cpu, &hdr5);
        jc_cpu[6] = 0xCAFEBABE; /* next lo — overwrite header next ptr */
        jc_cpu[7] = 0xDEADBEEF; /* next hi */
        jc_cpu[8] = (uint32_t)dest_gpu_va;
        jc_cpu[9] = (uint32_t)(dest_gpu_va >> 32);
        jc_cpu[10] = MALI_WRITE_VALUE_TYPE_IMMEDIATE_64;
        jc_cpu[11] = 0;
        jc_cpu[12] = 0xCAFEBABE;
        jc_cpu[13] = 0xDEADBEEF;

        memset(dest_cpu, 0xDD, 4096);
        msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

        if (submit_write_value_job(fd, jc_gpu_va, an++, BASE_JD_REQ_CS, 1) == 0) {
            struct base_jd_event_v2 ev6;
            if (read_event(fd, &ev6) == 0) {
                msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
                printf("  event=0x%x dest[0-3]: %08x %08x %08x %08x\n",
                       ev6.event_code, d32[0], d32[1], d32[2], d32[3]);
            }
        }

        /* Test 3: what if we use the GHSL approach — map_gpu style with
         * SAME_VA? On this device GPU VA != CPU VA, so this is a control test.
         * Actually, try the simplest thing: write the VALUE at byte offset 32
         * from the JC page start (the standard payload offset) but with type=ZERO
         * which should zero out the address. If type=ZERO always works regardless,
         * then the issue IS specifically with immediate reads. */
        printf("\n  Test 3: IMMEDIATE_32 with value=0x12345678\n");
        memset(jc_cpu, 0, 64);
        pack_job_header(jc_cpu, &hdr5);
        jc_cpu[8] = (uint32_t)dest_gpu_va;
        jc_cpu[9] = (uint32_t)(dest_gpu_va >> 32);
        jc_cpu[10] = MALI_WRITE_VALUE_TYPE_IMMEDIATE_32;
        jc_cpu[11] = 0;
        jc_cpu[12] = 0x12345678;
        jc_cpu[13] = 0;

        memset(dest_cpu, 0xDD, 4096);
        msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

        if (submit_write_value_job(fd, jc_gpu_va, an++, BASE_JD_REQ_CS, 1) == 0) {
            struct base_jd_event_v2 ev7;
            if (read_event(fd, &ev7) == 0) {
                msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
                printf("  event=0x%x dest[0-7]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                       ev7.event_code,
                       d32[0], d32[1], d32[2], d32[3],
                       d32[4], d32[5], d32[6], d32[7]);
            }
        }
    }

    printf("\nDone.\n");

out:
    if (dest2_cpu != MAP_FAILED)
        munmap(dest2_cpu, 4096);
    if (dest_cpu != MAP_FAILED)
        munmap(dest_cpu, 4096);
    if (jc_cpu != MAP_FAILED)
        munmap(jc_cpu, 4096);
    if (jc_gpu_va)
        mali_free(fd, jc_gpu_va);
    if (dest_gpu_va)
        mali_free(fd, dest_gpu_va);
    if (dest2_gpu_va)
        mali_free(fd, dest2_gpu_va);
    close(fd);
}

int main(void)
{
    pid_t pid = fork();
    int status = 0;

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        alarm(20);
        run_probe();
        _exit(0);
    }

    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("Child died by signal %d\n", WTERMSIG(status));
        return 1;
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
