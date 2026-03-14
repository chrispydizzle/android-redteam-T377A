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
#define KBASE_IOCTL_TYPE 0x80

#define UKP_FUNC_ID_CHECK_VERSION 0
#define UK_FUNC_ID 512
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_JD_REQ_SOFT_JOB        (1U << 9)
#define BASE_JD_REQ_SOFT_JIT_ALLOC  (BASE_JD_REQ_SOFT_JOB | 0x9)
#define BASE_JD_REQ_SOFT_JIT_FREE   (BASE_JD_REQ_SOFT_JOB | 0xA)

#define BASE_JD_EVENT_DONE 0x01

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
    uint8_t padding[3];
    struct base_jd_udata udata;
};

struct kbase_ioctl_get_ddk_version {
    uint64_t version_buffer;
    uint32_t size;
    uint32_t padding;
};

struct kbase_ioctl_version_check {
    uint16_t major;
    uint16_t minor;
};

struct kbase_ioctl_set_flags {
    uint32_t create_flags;
};

struct kbase_ioctl_mem_jit_init_10_2 {
    uint64_t va_pages;
};

struct kbase_ioctl_mem_jit_init_11_5 {
    uint64_t va_pages;
    uint8_t max_allocations;
    uint8_t trim_level;
    uint8_t group_id;
    uint8_t padding[5];
};

struct kbase_ioctl_mem_jit_init {
    uint64_t va_pages;
    uint8_t max_allocations;
    uint8_t trim_level;
    uint8_t group_id;
    uint8_t padding[5];
    uint64_t phys_pages;
};

union kbase_ioctl_mem_query {
    struct {
        uint64_t gpu_addr;
        uint64_t query;
    } in;
    struct {
        uint64_t value;
    } out;
};

struct kbase_ioctl_mem_free {
    uint64_t gpu_addr;
};

struct base_jit_alloc_info_v10 {
    uint64_t gpu_alloc_addr;
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extension;
    uint64_t pad;
};

struct base_jit_alloc_info_v11 {
    uint64_t gpu_alloc_addr;
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extension;
    uint8_t id;
    uint8_t bin_id;
    uint8_t max_allocations;
    uint8_t flags;
    uint8_t padding[2];
    uint16_t usage_id;
    uint64_t heap_info_gpu_addr;
};

#define KBASE_IOCTL_GET_DDK_VERSION \
    _IOW(KBASE_IOCTL_TYPE, 13, struct kbase_ioctl_get_ddk_version)
#define KBASE_IOCTL_VERSION_CHECK \
    _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS \
    _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_MEM_JIT_INIT_10_2 \
    _IOW(KBASE_IOCTL_TYPE, 14, struct kbase_ioctl_mem_jit_init_10_2)
#define KBASE_IOCTL_MEM_JIT_INIT_11_5 \
    _IOW(KBASE_IOCTL_TYPE, 14, struct kbase_ioctl_mem_jit_init_11_5)
#define KBASE_IOCTL_MEM_JIT_INIT \
    _IOW(KBASE_IOCTL_TYPE, 14, struct kbase_ioctl_mem_jit_init)
#define KBASE_IOCTL_MEM_QUERY \
    _IOWR(KBASE_IOCTL_TYPE, 6, union kbase_ioctl_mem_query)
#define KBASE_IOCTL_MEM_FREE \
    _IOW(KBASE_IOCTL_TYPE, 7, struct kbase_ioctl_mem_free)

#define KBASE_MEM_QUERY_COMMIT_SIZE ((uint64_t)1)
#define KBASE_MEM_QUERY_VA_SIZE     ((uint64_t)2)
#define KBASE_MEM_QUERY_FLAGS       ((uint64_t)3)

_Static_assert(sizeof(struct base_jd_atom_v2_old56) == 56, "old56 atom size mismatch");
_Static_assert(sizeof(struct kbase_uk_job_submit_trace) == 32, "submit trace size mismatch");
_Static_assert(sizeof(struct base_jd_event_v2) == 24, "event size mismatch");
_Static_assert(sizeof(struct base_jit_alloc_info_v10) == 40, "v10 JIT alloc size mismatch");
_Static_assert(sizeof(struct base_jit_alloc_info_v11) == 48, "v11 JIT alloc size mismatch");

static int mali_ioctl(int fd, void *buf, size_t size)
{
    errno = 0;
    return ioctl(fd, MALI_IOCTL(size), buf);
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

static void fetch_ddk_version(int fd)
{
    struct kbase_ioctl_get_ddk_version req;
    char buf[128];
    int rc;

    memset(buf, 0, sizeof(buf));
    memset(&req, 0, sizeof(req));
    req.version_buffer = (uint64_t)(uintptr_t)buf;
    req.size = sizeof(buf);
    errno = 0;
    rc = ioctl(fd, KBASE_IOCTL_GET_DDK_VERSION, &req);
    printf("GET_DDK_VERSION rc=%d errno=%d (%s) buf=\"%s\"\n",
           rc, errno, strerror(errno), rc == 0 ? buf : "");
}

static void try_direct_api_basics(int fd)
{
    struct kbase_ioctl_version_check ver;
    struct kbase_ioctl_set_flags flags;
    int rc;

    memset(&ver, 0, sizeof(ver));
    ver.major = 11;
    ver.minor = 5;
    errno = 0;
    rc = ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &ver);
    printf("KBASE_IOCTL_VERSION_CHECK rc=%d errno=%d (%s) version=%u.%u\n",
           rc, errno, strerror(errno), ver.major, ver.minor);

    memset(&flags, 0, sizeof(flags));
    errno = 0;
    rc = ioctl(fd, KBASE_IOCTL_SET_FLAGS, &flags);
    printf("KBASE_IOCTL_SET_FLAGS rc=%d errno=%d (%s) create_flags=0x%x\n",
           rc, errno, strerror(errno), flags.create_flags);
}

static int try_jit_init_10_2(int fd)
{
    struct kbase_ioctl_mem_jit_init_10_2 req;
    int rc;

    memset(&req, 0, sizeof(req));
    req.va_pages = 0x40;
    errno = 0;
    rc = ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT_10_2, &req);
    printf("MEM_JIT_INIT_10_2 rc=%d errno=%d (%s) va_pages=0x%llx\n",
           rc, errno, strerror(errno), (unsigned long long)req.va_pages);
    return rc;
}

static int try_jit_init_11_5(int fd)
{
    struct kbase_ioctl_mem_jit_init_11_5 req;
    int rc;

    memset(&req, 0, sizeof(req));
    req.va_pages = 0x40;
    req.max_allocations = 8;
    req.group_id = 0;
    errno = 0;
    rc = ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT_11_5, &req);
    printf("MEM_JIT_INIT_11_5 rc=%d errno=%d (%s) va_pages=0x%llx max_alloc=%u trim=%u group=%u\n",
           rc, errno, strerror(errno),
           (unsigned long long)req.va_pages,
           req.max_allocations,
           req.trim_level,
           req.group_id);
    return rc;
}

static int try_jit_init_current(int fd)
{
    struct kbase_ioctl_mem_jit_init req;
    int rc;

    memset(&req, 0, sizeof(req));
    req.va_pages = 0x40;
    req.max_allocations = 8;
    req.group_id = 0;
    req.phys_pages = 0x20;
    errno = 0;
    rc = ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT, &req);
    printf("MEM_JIT_INIT current rc=%d errno=%d (%s) va_pages=0x%llx phys_pages=0x%llx\n",
           rc, errno, strerror(errno),
           (unsigned long long)req.va_pages,
           (unsigned long long)req.phys_pages);
    return rc;
}

static int read_event(int fd, struct base_jd_event_v2 *ev, const char *label)
{
    struct pollfd pfd;
    ssize_t n;
    int rc;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR | POLLHUP;

    rc = poll(&pfd, 1, 1000);
    if (rc <= 0) {
        printf("%s poll rc=%d errno=%d (%s)\n", label, rc, errno, strerror(errno));
        return -1;
    }

    memset(ev, 0, sizeof(*ev));
    n = read(fd, ev, sizeof(*ev));
    if (n != (ssize_t)sizeof(*ev)) {
        printf("%s read returned %lld errno=%d (%s)\n",
               label, (long long)n, errno, strerror(errno));
        return -1;
    }

    printf("%s event_code=0x%08x atom=%u udata=[0x%016llx,0x%016llx]%s\n",
           label,
           ev->event_code,
           ev->atom_number,
           (unsigned long long)ev->udata.blob[0],
           (unsigned long long)ev->udata.blob[1],
           ev->event_code == BASE_JD_EVENT_DONE ? " (DONE)" : "");
    return 0;
}

static int submit_soft_job(int fd, uint64_t jc_addr, uint16_t core_req,
                           uint16_t nr_extres, uint8_t atom_number,
                           uint64_t tag0, uint64_t tag1)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
    int rc;

    memset(&atom, 0, sizeof(atom));
    atom.jc = jc_addr;
    atom.udata.blob[0] = tag0;
    atom.udata.blob[1] = tag1;
    atom.nr_extres = nr_extres;
    atom.core_req = core_req;
    atom.atom_number = atom_number;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)&atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(atom);

    rc = mali_ioctl(fd, &submit, sizeof(submit));
    printf("JOB_SUBMIT core_req=0x%x nr_extres=%u jc=0x%llx rc=%d errno=%d (%s) ret=%u\n",
           core_req, nr_extres, (unsigned long long)jc_addr,
           rc, errno, strerror(errno), submit.header.ret);
    return (rc == 0 && submit.header.ret == 0) ? 0 : -1;
}

static void dump_qwords(const char *label, const void *buf, size_t bytes)
{
    const uint64_t *q = (const uint64_t *)buf;
    size_t count = bytes / sizeof(*q);
    size_t i;

    printf("%s", label);
    for (i = 0; i < count; i++)
        printf(" [%zu]=0x%016llx", i, (unsigned long long)q[i]);
    printf("\n");
}

static void query_gpu_region(int fd, uint64_t gpu_va)
{
    union kbase_ioctl_mem_query query;
    const struct {
        uint64_t id;
        const char *name;
    } queries[] = {
        { KBASE_MEM_QUERY_COMMIT_SIZE, "COMMIT_SIZE" },
        { KBASE_MEM_QUERY_VA_SIZE, "VA_SIZE" },
        { KBASE_MEM_QUERY_FLAGS, "FLAGS" },
    };
    size_t i;

    for (i = 0; i < sizeof(queries) / sizeof(queries[0]); i++) {
        memset(&query, 0, sizeof(query));
        query.in.gpu_addr = gpu_va;
        query.in.query = queries[i].id;
        errno = 0;
        if (ioctl(fd, KBASE_IOCTL_MEM_QUERY, &query) < 0) {
            printf("MEM_QUERY %s failed for 0x%llx: errno=%d (%s)\n",
                   queries[i].name,
                   (unsigned long long)gpu_va,
                   errno,
                   strerror(errno));
            continue;
        }
        printf("MEM_QUERY %s gpu_va=0x%llx -> 0x%llx\n",
               queries[i].name,
               (unsigned long long)gpu_va,
               (unsigned long long)query.out.value);
    }
}

static void try_direct_mem_free(int fd, uint64_t gpu_va)
{
    struct kbase_ioctl_mem_free req;
    int rc;

    memset(&req, 0, sizeof(req));
    req.gpu_addr = gpu_va;
    errno = 0;
    rc = ioctl(fd, KBASE_IOCTL_MEM_FREE, &req);
    printf("MEM_FREE direct gpu_va=0x%llx rc=%d errno=%d (%s)\n",
           (unsigned long long)gpu_va, rc, errno, strerror(errno));
}

static void test_jit_alloc_v10(int fd, uint8_t *next_atom)
{
    struct base_jit_alloc_info_v10 info;
    struct base_jd_event_v2 ev;

    printf("\n=== SOFT_JIT_ALLOC probe: v10 layout (%zu bytes) ===\n", sizeof(info));
    memset(&info, 0, sizeof(info));
    info.va_pages = 8;
    info.commit_pages = 1;
    info.extension = 1;
    dump_qwords("before v10", &info, sizeof(info));

    if (submit_soft_job(fd,
                        (uint64_t)(uintptr_t)&info,
                        BASE_JD_REQ_SOFT_JIT_ALLOC,
                        1,
                        (*next_atom)++,
                        0x1010101010101010ULL,
                        0x1111111111111111ULL) < 0) {
        return;
    }

    if (read_event(fd, &ev, "JIT_ALLOC[v10]") < 0)
        return;

    dump_qwords("after v10 ", &info, sizeof(info));
    if (info.gpu_alloc_addr != 0)
        query_gpu_region(fd, info.gpu_alloc_addr);
}

static void test_jit_alloc_v11(int fd, uint8_t *next_atom)
{
    struct base_jit_alloc_info_v11 info;
    struct base_jd_event_v2 ev;
    uint8_t ids[2];

    printf("\n=== SOFT_JIT_ALLOC probe: v11-ish layout (%zu bytes) ===\n", sizeof(info));
    memset(&info, 0, sizeof(info));
    info.va_pages = 8;
    info.commit_pages = 1;
    info.extension = 1;
    info.id = 1;
    info.max_allocations = 8;
    info.usage_id = 0x1234;
    dump_qwords("before v11", &info, sizeof(info));

    if (submit_soft_job(fd,
                        (uint64_t)(uintptr_t)&info,
                        BASE_JD_REQ_SOFT_JIT_ALLOC,
                        1,
                        (*next_atom)++,
                        0x2020202020202020ULL,
                        0x2222222222222222ULL) < 0) {
        return;
    }

    if (read_event(fd, &ev, "JIT_ALLOC[v11]") < 0)
        return;

    dump_qwords("after v11 ", &info, sizeof(info));
    if (info.gpu_alloc_addr != 0)
        query_gpu_region(fd, info.gpu_alloc_addr);

    memset(ids, 0, sizeof(ids));
    ids[0] = info.id;
    printf("Attempting SOFT_JIT_FREE id=%u\n", info.id);
    if (submit_soft_job(fd,
                        (uint64_t)(uintptr_t)ids,
                        BASE_JD_REQ_SOFT_JIT_FREE,
                        1,
                        (*next_atom)++,
                        0x3030303030303030ULL,
                        0x3333333333333333ULL) == 0 &&
        read_event(fd, &ev, "JIT_FREE[v11]") == 0 &&
        info.gpu_alloc_addr != 0) {
        query_gpu_region(fd, info.gpu_alloc_addr);
    }

    if (info.gpu_alloc_addr != 0)
        try_direct_mem_free(fd, info.gpu_alloc_addr);
}

static void run_probe(void)
{
    uint8_t next_atom = 1;
    int fd;

    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        printf("open /dev/mali0 failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    printf("Opened /dev/mali0 fd=%d\n", fd);
    if (mali_init(fd) < 0)
        goto out;

    try_direct_api_basics(fd);
    fetch_ddk_version(fd);

    printf("\n=== JIT init variants ===\n");
    if (try_jit_init_10_2(fd) < 0 &&
        try_jit_init_11_5(fd) < 0 &&
        try_jit_init_current(fd) < 0) {
        printf("All JIT init variants failed; still probing soft jobs.\n");
    }

    if (mali_setup_mtp(fd) < 0)
        goto out;

    test_jit_alloc_v10(fd, &next_atom);
    test_jit_alloc_v11(fd, &next_atom);

out:
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
