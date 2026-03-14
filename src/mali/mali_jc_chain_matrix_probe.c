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

#define BASE_JD_REQ_CS        (1U << 1)
#define BASE_JD_DEP_TYPE_DATA (1U << 0)

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
    if (mali_ioctl(fd, &ver, sizeof(ver)) < 0)
        return -1;

    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    if (mali_ioctl(fd, &flags, sizeof(flags)) < 0)
        return -1;
    return 0;
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
    return mtp == MAP_FAILED ? -1 : 0;
}

static uint64_t mali_alloc(int fd)
{
    struct kbase_uk_mem_alloc alloc;

    memset(&alloc, 0, sizeof(alloc));
    alloc.header.id = KBASE_FUNC_MEM_ALLOC;
    alloc.va_pages = 1;
    alloc.commit_pages = 1;
    alloc.extent = 1;
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

    if (!gpu_va)
        return;
    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = gpu_va;
    mali_ioctl(fd, &mf, sizeof(mf));
}

static void *mali_cpu_map(int fd, uint64_t gpu_va)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, 4096,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                           (unsigned long)(gpu_va >> 12));
}

static void pack_write_value_desc(uint32_t *cl, uint64_t target_gpu_va, uint64_t next_gpu_va)
{
    struct mali_job_header h;

    memset(&h, 0, sizeof(h));
    h.is_64b = 1;
    h.type = MALI_JOB_TYPE_WRITE_VALUE;
    h.index = 1;
    h.next = next_gpu_va;

    memset(cl, 0, 56);
    cl[0] = h.exception_status;
    cl[1] = h.first_incomplete_task;
    cl[2] = (uint32_t)h.fault_pointer;
    cl[3] = (uint32_t)(h.fault_pointer >> 32);
    cl[4] = (uint32_t)((uint64_t)h.is_64b |
                       ((uint64_t)h.type << 1) |
                       ((uint64_t)h.index << 16));
    cl[5] = 0;
    cl[6] = (uint32_t)h.next;
    cl[7] = (uint32_t)(h.next >> 32);
    cl[8] = (uint32_t)target_gpu_va;
    cl[9] = (uint32_t)(target_gpu_va >> 32);
    cl[10] = MALI_WRITE_VALUE_TYPE_ZERO;
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
    return (rc == 0 && submit.header.ret == 0) ? 0 : -1;
}

static int read_event(int fd, struct base_jd_event_v2 *ev)
{
    struct pollfd pfd;
    ssize_t n;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR | POLLHUP;
    if (poll(&pfd, 1, 1000) <= 0)
        return -1;
    n = read(fd, ev, sizeof(*ev));
    return n == (ssize_t)sizeof(*ev) ? 0 : -1;
}

static void reset_chain(uint32_t *writer_jc_cpu, uint32_t *chain_cpu,
                        uint64_t writer_target_gpu_va, uint64_t chain_gpu_va,
                        uint64_t scratch_gpu_va, uint64_t mid_gpu_va,
                        uint64_t dest_gpu_va)
{
    uint64_t chain2_gpu = chain_gpu_va + 64;
    uint64_t chain3_gpu = chain_gpu_va + 128;

    pack_write_value_desc(writer_jc_cpu, writer_target_gpu_va, 0);
    pack_write_value_desc(chain_cpu, scratch_gpu_va, chain2_gpu);
    pack_write_value_desc(chain_cpu + 16, mid_gpu_va, chain3_gpu);
    pack_write_value_desc(chain_cpu + 32, dest_gpu_va, 0);
}

static void run_case(int fd, const char *label,
                     struct base_jd_atom_v2_old56 *atoms,
                     uint32_t *writer_jc_cpu, uint32_t *chain_cpu,
                     uint64_t writer_jc_gpu_va, uint64_t chain_gpu_va,
                     uint64_t scratch_gpu_va, uint64_t mid_gpu_va, uint64_t dest_gpu_va,
                     uint64_t *scratch_cpu, uint64_t *mid_cpu, uint64_t *dest_cpu,
                     uint64_t writer_target_gpu_va)
{
    struct base_jd_event_v2 ev;
    uint32_t atom1 = 0, atom2 = 0;
    int i;

    memset(atoms, 0, 2 * sizeof(*atoms));
    atoms[0].jc = writer_jc_gpu_va;
    atoms[0].udata.blob[0] = 0x1111111111111111ULL;
    atoms[0].udata.blob[1] = 0xAAAAAAAAAAAAAAAAULL;
    atoms[0].core_req = BASE_JD_REQ_CS;
    atoms[0].atom_number = 1;

    atoms[1].jc = chain_gpu_va;
    atoms[1].udata.blob[0] = 0x2222222222222222ULL;
    atoms[1].udata.blob[1] = 0xBBBBBBBBBBBBBBBBULL;
    atoms[1].core_req = BASE_JD_REQ_CS;
    atoms[1].pre_dep[0].atom_id = 1;
    atoms[1].pre_dep[0].dependency_type = BASE_JD_DEP_TYPE_DATA;
    atoms[1].atom_number = 2;

    reset_chain(writer_jc_cpu, chain_cpu, writer_target_gpu_va, chain_gpu_va,
                scratch_gpu_va, mid_gpu_va, dest_gpu_va);

    memset(scratch_cpu, 0xAA, 4096);
    memset(mid_cpu, 0xCC, 4096);
    memset(dest_cpu, 0xBB, 4096);
    msync(writer_jc_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    msync(chain_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    msync(scratch_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    msync(mid_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

    if (submit_atoms(fd, atoms, 2) < 0) {
        printf("%s submit=failed\n", label);
        return;
    }

    for (i = 0; i < 2; i++) {
        if (read_event(fd, &ev) < 0)
            break;
        if (ev.atom_number == 1)
            atom1 = ev.event_code;
        else if (ev.atom_number == 2)
            atom2 = ev.event_code;
    }

    msync(chain_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    msync(scratch_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    msync(mid_cpu, 4096, MS_SYNC | MS_INVALIDATE);
    msync(dest_cpu, 4096, MS_SYNC | MS_INVALIDATE);

    printf("%-16s atom1=%-18s atom2=%-18s scratch=%016llx mid=%016llx dest=%016llx\n",
           label,
           event_name(atom1),
           event_name(atom2),
           (unsigned long long)scratch_cpu[0],
           (unsigned long long)mid_cpu[0],
           (unsigned long long)dest_cpu[0]);
}

static void run_matrix(int fd, struct base_jd_atom_v2_old56 *atoms,
                       uint32_t *writer_jc_cpu, uint32_t *chain_cpu,
                       uint64_t writer_jc_gpu_va, uint64_t chain_gpu_va,
                       uint64_t scratch_gpu_va, uint64_t mid_gpu_va, uint64_t dest_gpu_va,
                       uint64_t *scratch_cpu, uint64_t *mid_cpu, uint64_t *dest_cpu,
                       int desc_index)
{
    static const int offsets[] = { 0, 8, 16, 24, 32, 40, 48 };
    char label[32];
    int i;

    printf("\n=== descriptor %d qword sweep ===\n", desc_index);
    run_case(fd, "control", atoms, writer_jc_cpu, chain_cpu,
             writer_jc_gpu_va, chain_gpu_va, scratch_gpu_va, mid_gpu_va, dest_gpu_va,
             scratch_cpu, mid_cpu, dest_cpu, chain_gpu_va + 192);

    for (i = 0; i < (int)(sizeof(offsets) / sizeof(offsets[0])); i++) {
        snprintf(label, sizeof(label), "desc%d+%d", desc_index, offsets[i]);
        run_case(fd, label, atoms, writer_jc_cpu, chain_cpu,
                 writer_jc_gpu_va, chain_gpu_va, scratch_gpu_va, mid_gpu_va, dest_gpu_va,
                 scratch_cpu, mid_cpu, dest_cpu,
                 chain_gpu_va + (uint64_t)desc_index * 64 + (uint64_t)offsets[i]);
    }
}

static void run_probe(void)
{
    uint64_t atoms_gpu_va = 0, writer_jc_gpu_va = 0, chain_gpu_va = 0;
    uint64_t scratch_gpu_va = 0, mid_gpu_va = 0, dest_gpu_va = 0;
    struct base_jd_atom_v2_old56 *atoms = MAP_FAILED;
    uint32_t *writer_jc_cpu = MAP_FAILED, *chain_cpu = MAP_FAILED;
    uint64_t *scratch_cpu = MAP_FAILED, *mid_cpu = MAP_FAILED, *dest_cpu = MAP_FAILED;
    int fd;

    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return;
    if (mali_init(fd) < 0 || mali_setup_mtp(fd) < 0)
        goto out;

    atoms_gpu_va = mali_alloc(fd);
    writer_jc_gpu_va = mali_alloc(fd);
    chain_gpu_va = mali_alloc(fd);
    scratch_gpu_va = mali_alloc(fd);
    mid_gpu_va = mali_alloc(fd);
    dest_gpu_va = mali_alloc(fd);
    if (!atoms_gpu_va || !writer_jc_gpu_va || !chain_gpu_va || !scratch_gpu_va ||
        !mid_gpu_va || !dest_gpu_va)
        goto out;

    atoms = (struct base_jd_atom_v2_old56 *)mali_cpu_map(fd, atoms_gpu_va);
    writer_jc_cpu = (uint32_t *)mali_cpu_map(fd, writer_jc_gpu_va);
    chain_cpu = (uint32_t *)mali_cpu_map(fd, chain_gpu_va);
    scratch_cpu = (uint64_t *)mali_cpu_map(fd, scratch_gpu_va);
    mid_cpu = (uint64_t *)mali_cpu_map(fd, mid_gpu_va);
    dest_cpu = (uint64_t *)mali_cpu_map(fd, dest_gpu_va);
    if (atoms == MAP_FAILED || writer_jc_cpu == MAP_FAILED || chain_cpu == MAP_FAILED ||
        scratch_cpu == MAP_FAILED || mid_cpu == MAP_FAILED || dest_cpu == MAP_FAILED)
        goto out;

    printf("3-descriptor chain sweep: writer zeros a chosen qword in a later descriptor before chain execution.\n");
    printf("Interpretation: scratch/mid/dest show which chain elements still ran.\n");
    run_matrix(fd, atoms, writer_jc_cpu, chain_cpu, writer_jc_gpu_va, chain_gpu_va,
               scratch_gpu_va, mid_gpu_va, dest_gpu_va,
               scratch_cpu, mid_cpu, dest_cpu, 1);
    run_matrix(fd, atoms, writer_jc_cpu, chain_cpu, writer_jc_gpu_va, chain_gpu_va,
               scratch_gpu_va, mid_gpu_va, dest_gpu_va,
               scratch_cpu, mid_cpu, dest_cpu, 2);

out:
    if (dest_cpu != MAP_FAILED)
        munmap(dest_cpu, 4096);
    if (mid_cpu != MAP_FAILED)
        munmap(mid_cpu, 4096);
    if (scratch_cpu != MAP_FAILED)
        munmap(scratch_cpu, 4096);
    if (chain_cpu != MAP_FAILED)
        munmap(chain_cpu, 4096);
    if (writer_jc_cpu != MAP_FAILED)
        munmap(writer_jc_cpu, 4096);
    if (atoms != MAP_FAILED)
        munmap(atoms, 4096);
    mali_free(fd, dest_gpu_va);
    mali_free(fd, mid_gpu_va);
    mali_free(fd, scratch_gpu_va);
    mali_free(fd, chain_gpu_va);
    mali_free(fd, writer_jc_gpu_va);
    mali_free(fd, atoms_gpu_va);
    close(fd);
}

int main(void)
{
    pid_t pid;
    int status = 0;

    pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        alarm(30);
        run_probe();
        _exit(0);
    }
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
