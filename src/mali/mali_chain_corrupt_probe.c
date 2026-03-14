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

#define BASE_MEM_PROT_CPU_RD      (1U << 0)
#define BASE_MEM_PROT_CPU_WR      (1U << 1)
#define BASE_MEM_PROT_GPU_RD      (1U << 2)
#define BASE_MEM_PROT_GPU_WR      (1U << 3)
#define BASE_MEM_COHERENT_LOCAL   (1U << 11)

#define BASE_JD_REQ_CS            (1U << 1)

#define BASE_JD_DEP_TYPE_DATA     (1U << 0)

#define MALI_JOB_TYPE_WRITE_VALUE 2
#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_JD_EVENT_DONE               0x00000001
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x00000058
#define BASE_JD_EVENT_JOB_CANCELLED      0x00004002
#define BASE_JD_EVENT_JOB_INVALID        0x00004003

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

_Static_assert(sizeof(struct base_jd_atom_v2_old56) == 56, "old56 atom size mismatch");
_Static_assert(sizeof(struct kbase_uk_job_submit_trace) == 32, "submit trace size mismatch");
_Static_assert(sizeof(struct base_jd_event_v2) == 24, "event size mismatch");

static int mali_ioctl(int fd, void *buf, size_t size)
{
    errno = 0;
    return ioctl(fd, MALI_IOCTL(size), buf);
}

static const char *event_name(uint32_t code)
{
    switch (code) {
    case BASE_JD_EVENT_DONE:
        return "DONE";
    case BASE_JD_EVENT_DATA_INVALID_FAULT:
        return "DATA_INVALID_FAULT";
    case BASE_JD_EVENT_JOB_CANCELLED:
        return "JOB_CANCELLED";
    case BASE_JD_EVENT_JOB_INVALID:
        return "JOB_INVALID";
    default:
        return "UNKNOWN";
    }
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

static uint64_t mali_alloc(int fd, uint64_t pages)
{
    struct kbase_uk_mem_alloc alloc;
    uint32_t flags;

    flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
            BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
            BASE_MEM_COHERENT_LOCAL;

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

    printf("MEM_ALLOC ret=%u gpu_va=0x%llx pages=%llu\n",
           alloc.header.ret,
           (unsigned long long)alloc.gpu_va,
           (unsigned long long)pages);

    return alloc.header.ret == 0 ? alloc.gpu_va : 0;
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, size_t size)
{
    unsigned long pgoff = (unsigned long)(gpu_va >> 12);
    void *p = (void *)syscall(__NR_mmap2, (unsigned long)NULL, size,
                              PROT_READ | PROT_WRITE, MAP_SHARED, fd, pgoff);
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

    if (!gpu_va)
        return;

    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = gpu_va;
    if (mali_ioctl(fd, &mf, sizeof(mf)) < 0) {
        printf("MEM_FREE ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    printf("MEM_FREE ret=%u gpu_va=0x%llx\n", mf.header.ret, (unsigned long long)gpu_va);
}

static uint64_t pack_bits64(uint64_t v, uint32_t start)
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
        pack_bits64(h->is_64b, 0) |
        pack_bits64(h->type, 1) |
        pack_bits64(h->barrier, 8) |
        pack_bits64(h->invalidate_cache, 9) |
        pack_bits64(h->suppress_prefetch, 11) |
        pack_bits64(h->enable_texture_mapper, 12) |
        pack_bits64(h->relax_dependency_1, 14) |
        pack_bits64(h->relax_dependency_2, 15) |
        pack_bits64(h->index, 16));
    cl[5] = (uint32_t)(
        pack_bits64(h->dependency_1, 0) |
        pack_bits64(h->dependency_2, 16));
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

static void build_zero_job(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    struct mali_job_header header;
    struct mali_write_value_job_payload payload;

    memset(&header, 0, sizeof(header));
    header.is_64b = 1;
    header.type = MALI_JOB_TYPE_WRITE_VALUE;
    header.index = 1;

    memset(&payload, 0, sizeof(payload));
    payload.address = target_gpu_va;
    payload.type = MALI_WRITE_VALUE_TYPE_ZERO;

    memset(jc_cpu, 0, 56);
    pack_job_header(jc_cpu, &header);
    pack_write_value_payload(jc_cpu + 8, &payload);
}

static int submit_atoms(int fd, struct base_jd_atom_v2_old56 *atoms, uint32_t nr_atoms)
{
    struct kbase_uk_job_submit_trace submit;
    int rc;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)atoms;
    submit.nr_atoms = nr_atoms;
    submit.stride = sizeof(*atoms);

    rc = mali_ioctl(fd, &submit, sizeof(submit));
    printf("JOB_SUBMIT rc=%d errno=%d (%s) ret=%u nr_atoms=%u stride=%u\n",
           rc, errno, strerror(errno), submit.header.ret, nr_atoms, submit.stride);
    return (rc == 0 && submit.header.ret == 0) ? 0 : -1;
}

static int read_one_event(int fd, struct base_jd_event_v2 *ev)
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

    memset(ev, 0, sizeof(*ev));
    n = read(fd, ev, sizeof(*ev));
    if (n != (ssize_t)sizeof(*ev)) {
        printf("read returned %lld errno=%d (%s)\n", (long long)n, errno, strerror(errno));
        return -1;
    }

    printf("event atom=%u code=0x%08x (%s) udata=[0x%016llx,0x%016llx]\n",
           ev->atom_number, ev->event_code, event_name(ev->event_code),
           (unsigned long long)ev->udata.blob[0],
           (unsigned long long)ev->udata.blob[1]);
    return 0;
}

static void dump_words(const char *label, const uint32_t *buf, size_t words)
{
    size_t i;

    printf("%s", label);
    for (i = 0; i < words; i++)
        printf(" %08x", buf[i]);
    printf("\n");
}

static void run_case(int fd,
                     const char *label,
                     uint64_t atom1_target,
                     uint32_t *jc1_cpu,
                     uint32_t *jc2_cpu,
                     uint64_t jc1_gpu_va,
                     uint64_t jc2_gpu_va,
                     uint64_t *dest_cpu,
                     uint64_t dest_gpu_va)
{
    struct base_jd_atom_v2_old56 atoms[2];
    struct base_jd_event_v2 ev;
    int seen[3] = { 0 };
    int i;

    printf("\n=== %s ===\n", label);

    build_zero_job(jc1_cpu, atom1_target);
    build_zero_job(jc2_cpu, dest_gpu_va);
    memset(dest_cpu, 0xAA, 4096);
    msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

    dump_words("jc1 before:", jc1_cpu, 14);
    dump_words("jc2 before:", jc2_cpu, 14);
    printf("dest before=0x%016llx\n", (unsigned long long)dest_cpu[0]);

    memset(atoms, 0, sizeof(atoms));

    atoms[0].jc = jc1_gpu_va;
    atoms[0].udata.blob[0] = 0x1111111111111111ULL;
    atoms[0].udata.blob[1] = 0xAAAAAAAAAAAAAAAAULL;
    atoms[0].core_req = BASE_JD_REQ_CS;
    atoms[0].atom_number = 1;

    atoms[1].jc = jc2_gpu_va;
    atoms[1].udata.blob[0] = 0x2222222222222222ULL;
    atoms[1].udata.blob[1] = 0xBBBBBBBBBBBBBBBBULL;
    atoms[1].core_req = BASE_JD_REQ_CS;
    atoms[1].pre_dep[0].atom_id = 1;
    atoms[1].pre_dep[0].dependency_type = BASE_JD_DEP_TYPE_DATA;
    atoms[1].atom_number = 2;

    if (submit_atoms(fd, atoms, 2) < 0)
        return;

    for (i = 0; i < 2; i++) {
        if (read_one_event(fd, &ev) < 0)
            break;
        if (ev.atom_number < 3)
            seen[ev.atom_number] = ev.event_code;
    }

    msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    printf("dest after =0x%016llx\n", (unsigned long long)dest_cpu[0]);
    dump_words("jc2 after: ", jc2_cpu, 14);
    printf("summary atom1=0x%08x (%s) atom2=0x%08x (%s)\n",
           seen[1], event_name(seen[1]),
           seen[2], event_name(seen[2]));
}

static void run_probe(void)
{
    uint64_t jc1_gpu_va = 0, jc2_gpu_va = 0, dest_gpu_va = 0, scratch_gpu_va = 0;
    uint32_t *jc1_cpu = MAP_FAILED, *jc2_cpu = MAP_FAILED;
    uint64_t *dest_cpu = MAP_FAILED;
    int fd;

    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        printf("open failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    printf("Opened /dev/mali0 fd=%d\n", fd);
    if (mali_init(fd) < 0 || mali_setup_mtp(fd) < 0)
        goto out;

    jc1_gpu_va = mali_alloc(fd, 1);
    jc2_gpu_va = mali_alloc(fd, 1);
    dest_gpu_va = mali_alloc(fd, 1);
    scratch_gpu_va = mali_alloc(fd, 1);
    if (!jc1_gpu_va || !jc2_gpu_va || !dest_gpu_va || !scratch_gpu_va)
        goto out;

    jc1_cpu = (uint32_t *)mali_cpu_map(fd, jc1_gpu_va, 4096);
    jc2_cpu = (uint32_t *)mali_cpu_map(fd, jc2_gpu_va, 4096);
    dest_cpu = (uint64_t *)mali_cpu_map(fd, dest_gpu_va, 4096);
    if (jc1_cpu == MAP_FAILED || jc2_cpu == MAP_FAILED || dest_cpu == MAP_FAILED)
        goto out;

    run_case(fd, "control: atom1 zeros scratch, atom2 zeros dest",
             scratch_gpu_va, jc1_cpu, jc2_cpu,
             jc1_gpu_va, jc2_gpu_va, dest_cpu, dest_gpu_va);

    run_case(fd, "corrupt atom2 payload address before atom2 runs",
             jc2_gpu_va + 32, jc1_cpu, jc2_cpu,
             jc1_gpu_va, jc2_gpu_va, dest_cpu, dest_gpu_va);

    run_case(fd, "corrupt atom2 payload type before atom2 runs",
             jc2_gpu_va + 40, jc1_cpu, jc2_cpu,
             jc1_gpu_va, jc2_gpu_va, dest_cpu, dest_gpu_va);

out:
    if (dest_cpu != MAP_FAILED)
        munmap(dest_cpu, 4096);
    if (jc2_cpu != MAP_FAILED)
        munmap(jc2_cpu, 4096);
    if (jc1_cpu != MAP_FAILED)
        munmap(jc1_cpu, 4096);
    mali_free(fd, scratch_gpu_va);
    mali_free(fd, dest_gpu_va);
    mali_free(fd, jc2_gpu_va);
    mali_free(fd, jc1_gpu_va);
    close(fd);
}

int main(void)
{
    pid_t pid;
    int status = 0;

    pid = fork();
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

    printf("Child exit status %d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status);
}
