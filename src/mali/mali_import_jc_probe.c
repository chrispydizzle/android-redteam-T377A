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
#define KBASE_FUNC_MEM_IMPORT  (UK_FUNC_ID + 1)
#define KBASE_FUNC_MEM_FREE    (UK_FUNC_ID + 4)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_MEM_PROT_CPU_RD      (1U << 0)
#define BASE_MEM_PROT_CPU_WR      (1U << 1)
#define BASE_MEM_PROT_GPU_RD      (1U << 2)
#define BASE_MEM_PROT_GPU_WR      (1U << 3)
#define BASE_MEM_COHERENT_LOCAL   (1U << 11)
#define BASE_MEM_IMPORT_SHARED    (1U << 30)

#define BASE_JD_REQ_CS            (1U << 1)

#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_JD_EVENT_DONE               0x00000001
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x00000058
#define BASE_JD_EVENT_JOB_CANCELLED      0x00004002
#define BASE_JD_EVENT_JOB_INVALID        0x00004003

#define ION_IOC_MAGIC 'I'

typedef int32_t ion_user_handle_t;

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
    if (mali_ioctl(fd, &ver, sizeof(ver)) < 0 || ver.header.ret != 0)
        return -1;

    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    if (mali_ioctl(fd, &flags, sizeof(flags)) < 0 || flags.header.ret != 0)
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

static int mali_open_ctx(int nonblock)
{
    int flags = O_RDWR | O_CLOEXEC;
    int fd;

    if (nonblock)
        flags |= O_NONBLOCK;
    fd = open("/dev/mali0", flags);
    if (fd < 0)
        return -1;
    if (mali_init(fd) < 0 || mali_setup_mtp(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static uint64_t mali_alloc_page(int fd, uint32_t *ret_out)
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
    if (mali_ioctl(fd, &alloc, sizeof(alloc)) < 0) {
        if (ret_out)
            *ret_out = 0xFFFFFFFFU;
        return 0;
    }
    if (ret_out)
        *ret_out = alloc.header.ret;
    return alloc.header.ret == 0 ? alloc.gpu_va : 0;
}

static uint32_t mali_free_checked(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_free mf;

    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = gpu_va;
    if (mali_ioctl(fd, &mf, sizeof(mf)) < 0)
        return 0xFFFFFFFFU;
    return mf.header.ret;
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, int prot)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                           prot, MAP_SHARED, fd, (unsigned long)(gpu_va >> 12));
}

static int submit_zero_job(int fd, uint64_t jc_gpu_va)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
    int rc;

    memset(&atom, 0, sizeof(atom));
    atom.jc = jc_gpu_va;
    atom.udata.blob[0] = 0x1111111111111111ULL;
    atom.udata.blob[1] = 0x2222222222222222ULL;
    atom.core_req = BASE_JD_REQ_CS;
    atom.atom_number = 1;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)&atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(atom);
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

static void build_zero_desc(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4] = 0x00010005;
    jc_cpu[8] = (uint32_t)target_gpu_va;
    jc_cpu[9] = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
}

static int ion_alloc_buffer(int *ion_fd_out, int *dma_fd_out, ion_user_handle_t *handle_out, void **map_out)
{
    struct ion_allocation_data alloc;
    struct ion_fd_data share;
    int ion_fd;
    void *map;

    ion_fd = open("/dev/ion", O_RDWR | O_CLOEXEC);
    if (ion_fd < 0)
        return -1;

    memset(&alloc, 0, sizeof(alloc));
    alloc.len = 4096;
    alloc.align = 4096;
    alloc.heap_id_mask = 1U << 0;
    alloc.flags = 0;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        close(ion_fd);
        return -1;
    }

    memset(&share, 0, sizeof(share));
    share.handle = alloc.handle;
    if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) {
        struct ion_handle_data free_data;
        free_data.handle = alloc.handle;
        ioctl(ion_fd, ION_IOC_FREE, &free_data);
        close(ion_fd);
        return -1;
    }

    map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, share.fd, 0);
    if (map == MAP_FAILED) {
        close(share.fd);
        close(ion_fd);
        return -1;
    }

    *ion_fd_out = ion_fd;
    *dma_fd_out = share.fd;
    *handle_out = alloc.handle;
    *map_out = map;
    return 0;
}

static uint64_t try_import_layout24(int mali_fd, uint32_t flags,
                                    const char *label, uint64_t phandle, uint32_t type)
{
    uint8_t buf[48];
    int rc;
    uint32_t ret;
    uint64_t gpu_va;
    uint64_t va_pages;

    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + 0) = KBASE_FUNC_MEM_IMPORT;
    *(uint64_t *)(buf + 8) = phandle;
    *(uint32_t *)(buf + 16) = type;
    *(uint64_t *)(buf + 24) = flags;

    rc = mali_ioctl(mali_fd, buf, sizeof(buf));
    ret = *(uint32_t *)(buf + 4);
    gpu_va = *(uint64_t *)(buf + 32);
    va_pages = *(uint64_t *)(buf + 40);
    printf("%s: ioctl=%d errno=%d ret=0x%x gpu_va=0x%llx va_pages=%llu\n",
           label, rc, rc < 0 ? errno : 0, ret,
           (unsigned long long)gpu_va,
           (unsigned long long)va_pages);
    return (rc == 0 && ret == 0) ? gpu_va : 0;
}

static uint64_t try_import_layout40(int mali_fd, uint32_t flags,
                                    const char *label, uint64_t phandle, uint32_t type)
{
    uint8_t buf[48];
    int rc;
    uint32_t ret;
    uint64_t gpu_va;
    uint64_t va_pages;

    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + 0) = KBASE_FUNC_MEM_IMPORT;
    *(uint64_t *)(buf + 8) = phandle;
    *(uint32_t *)(buf + 16) = type;
    *(uint32_t *)(buf + 40) = flags;

    rc = mali_ioctl(mali_fd, buf, sizeof(buf));
    ret = *(uint32_t *)(buf + 4);
    gpu_va = *(uint64_t *)(buf + 24);
    va_pages = *(uint64_t *)(buf + 32);
    printf("%s: ioctl=%d errno=%d ret=0x%x gpu_va=0x%llx va_pages=%llu\n",
           label, rc, rc < 0 ? errno : 0, ret,
           (unsigned long long)gpu_va,
           (unsigned long long)va_pages);
    return (rc == 0 && ret == 0) ? gpu_va : 0;
}

static void run_probe(void)
{
    int ion_fd = -1, dma_fd = -1, mali_fd = -1;
    ion_user_handle_t handle = -1;
    void *ion_map = MAP_FAILED;
    uint64_t imported_gpu_va = 0, dest_gpu_va = 0, jc_gpu_va = 0;
    uint32_t alloc_ret = 0;
    uint32_t *import_map = MAP_FAILED, *jc_map = MAP_FAILED;
    uint64_t *dest_map = MAP_FAILED;
    struct base_jd_event_v2 ev;
    int handle_data = -1;
    uint32_t flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;

    if (ion_alloc_buffer(&ion_fd, &dma_fd, &handle, &ion_map) < 0) {
        printf("ION allocation failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    mali_fd = mali_open_ctx(1);
    if (mali_fd < 0) {
        printf("Mali init failed\n");
        goto out;
    }

    handle_data = dma_fd;
    memset(ion_map, 0x44, 4096);
    ((uint32_t *)ion_map)[0] = 0x1234ABCDU;
    printf("ION dma_fd=%d handle=%d ion_map=%p word0=0x%08x\n",
           dma_fd, handle, ion_map, ((uint32_t *)ion_map)[0]);

    printf("\n=== MEM_IMPORT layout attempts ===\n");
    imported_gpu_va = try_import_layout24(mali_fd, flags,
                                          "layout24 phandle=&fd type=2",
                                          (uint64_t)(uintptr_t)&handle_data, 2);
    if (!imported_gpu_va) {
        imported_gpu_va = try_import_layout24(mali_fd, flags,
                                              "layout24 phandle=&fd type=1",
                                              (uint64_t)(uintptr_t)&handle_data, 1);
    }
    if (!imported_gpu_va) {
        imported_gpu_va = try_import_layout24(mali_fd, flags,
                                              "layout24 phandle=fd type=2",
                                              (uint64_t)(uint32_t)dma_fd, 2);
    }
    if (!imported_gpu_va) {
        imported_gpu_va = try_import_layout40(mali_fd, flags,
                                              "layout40 phandle=&fd type=2",
                                              (uint64_t)(uintptr_t)&handle_data, 2);
    }

    if (!imported_gpu_va) {
        printf("No MEM_IMPORT layout succeeded\n");
        goto out;
    }

    import_map = (uint32_t *)mali_cpu_map(mali_fd, imported_gpu_va, PROT_READ | PROT_WRITE);
    printf("import_map=%p errno=%d\n", import_map, import_map == MAP_FAILED ? errno : 0);
    if (import_map != MAP_FAILED) {
        printf("imported word0 before write=0x%08x\n", import_map[0]);
        import_map[1] = 0xCAFEBABEU;
        msync(import_map, 4096, MS_SYNC | MS_INVALIDATE);
        msync(ion_map, 4096, MS_SYNC | MS_INVALIDATE);
        printf("after import_map write: import_map[1]=0x%08x ion_map[1]=0x%08x\n",
               import_map[1], ((uint32_t *)ion_map)[1]);
    }

    jc_gpu_va = mali_alloc_page(mali_fd, &alloc_ret);
    printf("jc alloc ret=0x%x gpu_va=0x%llx\n", alloc_ret, (unsigned long long)jc_gpu_va);
    dest_gpu_va = mali_alloc_page(mali_fd, &alloc_ret);
    printf("dest alloc ret=0x%x gpu_va=0x%llx\n", alloc_ret, (unsigned long long)dest_gpu_va);
    if (!jc_gpu_va || !dest_gpu_va || import_map == MAP_FAILED)
        goto out;

    jc_map = (uint32_t *)mali_cpu_map(mali_fd, jc_gpu_va, PROT_READ | PROT_WRITE);
    printf("jc_map=%p errno=%d\n", jc_map, jc_map == MAP_FAILED ? errno : 0);
    dest_map = (uint64_t *)mali_cpu_map(mali_fd, dest_gpu_va, PROT_READ | PROT_WRITE);
    printf("dest_map=%p errno=%d\n", dest_map, dest_map == MAP_FAILED ? errno : 0);
    if (jc_map == MAP_FAILED || dest_map == MAP_FAILED)
        goto out;

    memset(ion_map, 0x44, 4096);
    build_zero_desc(jc_map, imported_gpu_va);
    msync(jc_map, 4096, MS_SYNC | MS_INVALIDATE);
    msync(import_map, 4096, MS_SYNC | MS_INVALIDATE);
    if (submit_zero_job(mali_fd, jc_gpu_va) < 0) {
        printf("JOB_SUBMIT targeting imported page failed\n");
        goto out;
    }
    if (read_event(mali_fd, &ev) < 0) {
        printf("event read failed for imported target\n");
        goto out;
    }
    msync(import_map, 4096, MS_SYNC | MS_INVALIDATE);
    msync(ion_map, 4096, MS_SYNC | MS_INVALIDATE);
    printf("normal JC -> imported target event=0x%08x(%s) import_map[0]=0x%08x ion_map[0]=0x%08x\n",
           ev.event_code, event_name(ev.event_code), import_map[0], ((uint32_t *)ion_map)[0]);

    memset(dest_map, 0xAA, 4096);
    build_zero_desc(import_map, dest_gpu_va);
    msync(import_map, 4096, MS_SYNC | MS_INVALIDATE);
    msync(dest_map, 4096, MS_SYNC | MS_INVALIDATE);

    if (submit_zero_job(mali_fd, imported_gpu_va) < 0) {
        printf("JOB_SUBMIT on imported JC failed\n");
        goto out;
    }
    if (read_event(mali_fd, &ev) < 0) {
        printf("event read failed\n");
        goto out;
    }
    msync(dest_map, 4096, MS_SYNC | MS_INVALIDATE);
    printf("imported JC event=0x%08x(%s) dest=0x%016llx\n",
           ev.event_code, event_name(ev.event_code),
           (unsigned long long)dest_map[0]);

out:
    if (dest_map != MAP_FAILED)
        munmap(dest_map, 4096);
    if (jc_map != MAP_FAILED)
        munmap(jc_map, 4096);
    if (import_map != MAP_FAILED)
        munmap(import_map, 4096);
    if (dest_gpu_va)
        mali_free_checked(mali_fd, dest_gpu_va);
    if (jc_gpu_va)
        mali_free_checked(mali_fd, jc_gpu_va);
    if (imported_gpu_va)
        mali_free_checked(mali_fd, imported_gpu_va);
    if (mali_fd >= 0)
        close(mali_fd);
    if (ion_map != MAP_FAILED)
        munmap(ion_map, 4096);
    if (dma_fd >= 0)
        close(dma_fd);
    if (ion_fd >= 0) {
        if (handle >= 0) {
            struct ion_handle_data free_data;
            free_data.handle = handle;
            ioctl(ion_fd, ION_IOC_FREE, &free_data);
        }
        close(ion_fd);
    }
}

int main(void)
{
    pid_t pid;
    int status = 0;

    printf("=== Mali MEM_IMPORT JC probe ===\n");
    pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        alarm(20);
        run_probe();
        _exit(0);
    }
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
