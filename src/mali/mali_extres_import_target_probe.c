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

#define BASE_JD_REQ_CS                    (1U << 1)
#define BASE_JD_REQ_EXTERNAL_RESOURCES    (1U << 8)
#define BASE_JD_REQ_SOFT_JOB              (1U << 9)
#define BASE_JD_REQ_SOFT_EXT_RES_MAP      (BASE_JD_REQ_SOFT_JOB | 0x0b)
#define BASE_JD_REQ_SOFT_EXT_RES_UNMAP    (BASE_JD_REQ_SOFT_JOB | 0x0c)

#define BASE_JD_DEP_TYPE_INVALID  0
#define BASE_JD_DEP_TYPE_DATA     1

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

struct base_external_resource {
    uint64_t ext_resource;
};

struct base_external_resource_list {
    uint64_t count;
    struct base_external_resource ext_res[1];
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

    if ((void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                        PROT_NONE, MAP_SHARED, fd, (unsigned long)2) == MAP_FAILED &&
        (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                        PROT_NONE, MAP_SHARED, fd, (unsigned long)3) == MAP_FAILED)
        return -1;

    return 0;
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

static int submit_atom(int fd, const struct base_jd_atom_v2_old56 *atom,
                       struct base_jd_event_v2 *ev, const char *label)
{
    struct kbase_uk_job_submit_trace submit;
    int rc;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(*atom);
    rc = mali_ioctl(fd, &submit, sizeof(submit));
    printf("%s submit: rc=%d errno=%d (%s) ret=0x%x\n",
           label, rc, errno, strerror(errno), submit.header.ret);
    if (rc != 0 || submit.header.ret != 0)
        return -1;
    if (read_event(fd, ev) < 0) {
        printf("%s read_event failed errno=%d (%s)\n", label, errno, strerror(errno));
        return -1;
    }
    printf("%s event=0x%08x (%s) atom=%u udata=[0x%016llx,0x%016llx]\n",
           label, ev->event_code, event_name(ev->event_code), ev->atom_number,
           (unsigned long long)ev->udata.blob[0],
           (unsigned long long)ev->udata.blob[1]);
    return 0;
}

static int submit_atoms(int fd, const struct base_jd_atom_v2_old56 *atoms,
                        uint32_t nr_atoms, struct base_jd_event_v2 *evs,
                        const char *label)
{
    struct kbase_uk_job_submit_trace submit;
    uint32_t i;
    int rc;

    memset(&submit, 0, sizeof(submit));
    submit.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit.addr = (uint64_t)(uintptr_t)atoms;
    submit.nr_atoms = nr_atoms;
    submit.stride = sizeof(*atoms);
    rc = mali_ioctl(fd, &submit, sizeof(submit));
    printf("%s submit[%u]: rc=%d errno=%d (%s) ret=0x%x\n",
           label, nr_atoms, rc, errno, strerror(errno), submit.header.ret);
    if (rc != 0 || submit.header.ret != 0)
        return -1;
    for (i = 0; i < nr_atoms; i++) {
        if (read_event(fd, &evs[i]) < 0) {
            printf("%s read_event[%u] failed errno=%d (%s)\n",
                   label, i, errno, strerror(errno));
            return -1;
        }
        printf("%s event[%u]=0x%08x (%s) atom=%u udata=[0x%016llx,0x%016llx]\n",
               label, i, evs[i].event_code, event_name(evs[i].event_code), evs[i].atom_number,
               (unsigned long long)evs[i].udata.blob[0],
               (unsigned long long)evs[i].udata.blob[1]);
    }
    return 0;
}

static int ion_alloc_buffer(int *ion_fd_out, int *dma_fd_out,
                            ion_user_handle_t *handle_out, void **map_out)
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

static uint64_t mali_import_ion(int mali_fd, int *fd_ptr)
{
    uint8_t buf[48];
    int rc;
    uint32_t ret;
    uint64_t gpu_va;

    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + 0) = KBASE_FUNC_MEM_IMPORT;
    *(uint64_t *)(buf + 8) = (uint64_t)(uintptr_t)fd_ptr;
    *(uint32_t *)(buf + 16) = 2;
    *(uint64_t *)(buf + 24) = 0x0000000FULL;

    rc = mali_ioctl(mali_fd, buf, sizeof(buf));
    ret = *(uint32_t *)(buf + 4);
    gpu_va = *(uint64_t *)(buf + 32);
    printf("MEM_IMPORT: rc=%d errno=%d ret=0x%x gpu_va=0x%llx\n",
           rc, rc < 0 ? errno : 0, ret, (unsigned long long)gpu_va);
    return (rc == 0 && ret == 0) ? gpu_va : 0;
}

static void fill_atom(struct base_jd_atom_v2_old56 *atom, uint64_t jc,
                      uint16_t core_req, uint8_t atom_number,
                      uint64_t extres_list, uint16_t nr_extres)
{
    memset(atom, 0, sizeof(*atom));
    atom->jc = jc;
    atom->udata.blob[0] = 0x1111000000000000ULL | atom_number;
    atom->udata.blob[1] = 0x2222000000000000ULL | atom_number;
    atom->extres_list = extres_list;
    atom->nr_extres = nr_extres;
    atom->core_req = core_req;
    atom->atom_number = atom_number;
}

static void set_dep(struct base_dependency *dep, uint8_t atom_id, uint8_t dep_type)
{
    dep->atom_id = atom_id;
    dep->dependency_type = dep_type;
}

static void run_probe(void)
{
    int mali_fd = -1, ion_fd = -1, dma_fd = -1;
    ion_user_handle_t ion_handle = -1;
    void *ion_map = MAP_FAILED;
    uint64_t import_gpu_va = 0, native_gpu_va = 0, jc_gpu_va = 0, dest_gpu_va = 0;
    uint32_t *jc_cpu = MAP_FAILED;
    uint64_t *dest_cpu = MAP_FAILED;
    struct base_external_resource native_res[1], import_res_shared[1], import_res_excl[1];
    struct base_external_resource_list native_list, import_list_shared, import_list_excl;
    struct base_jd_atom_v2_old56 chain[3];
    struct base_jd_event_v2 chain_evs[3];
    struct base_jd_atom_v2_old56 atom;
    struct base_jd_event_v2 ev;

    printf("=== Mali external-resource probe ===\n");

    if (ion_alloc_buffer(&ion_fd, &dma_fd, &ion_handle, &ion_map) < 0) {
        printf("ION alloc failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    mali_fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (mali_fd < 0 || mali_init(mali_fd) < 0) {
        printf("Mali init failed errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }

    native_gpu_va = mali_alloc_page(mali_fd);
    jc_gpu_va = mali_alloc_page(mali_fd);
    dest_gpu_va = mali_alloc_page(mali_fd);
    import_gpu_va = mali_import_ion(mali_fd, &dma_fd);
    jc_cpu = (uint32_t *)mali_cpu_map(mali_fd, jc_gpu_va);
    dest_cpu = (uint64_t *)mali_cpu_map(mali_fd, dest_gpu_va);
    printf("native=0x%llx import=0x%llx jc=0x%llx dest=0x%llx jc_cpu=%p dest_cpu=%p\n",
           (unsigned long long)native_gpu_va, (unsigned long long)import_gpu_va,
           (unsigned long long)jc_gpu_va, (unsigned long long)dest_gpu_va, jc_cpu, dest_cpu);
    if (!native_gpu_va || !jc_gpu_va || !dest_gpu_va || !import_gpu_va ||
        jc_cpu == MAP_FAILED || dest_cpu == MAP_FAILED)
        goto out;

    build_zero_desc(jc_cpu, dest_gpu_va);
    memset(dest_cpu, 0xAA, 4096);
    memset(ion_map, 0xBB, 4096);

    fill_atom(&atom, jc_gpu_va, BASE_JD_REQ_CS, 1, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "baseline");
    printf("baseline dest=0x%016llx\n", (unsigned long long)dest_cpu[0]);

    build_zero_desc(jc_cpu, import_gpu_va);
    memset(ion_map, 0xBB, 4096);
    fill_atom(&atom, jc_gpu_va, BASE_JD_REQ_CS, 17, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "direct import target");
    printf("direct import target ion=0x%016llx\n", (unsigned long long)*(uint64_t *)ion_map);

    build_zero_desc(jc_cpu, dest_gpu_va);

    native_res[0].ext_resource = native_gpu_va;
    native_list.count = 1;
    native_list.ext_res[0] = native_res[0];

    memset(dest_cpu, 0xAA, 4096);
    fill_atom(&atom, jc_gpu_va, BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              2, (uint64_t)(uintptr_t)native_res, 1);
    submit_atom(mali_fd, &atom, &ev, "hw extres native");
    printf("hw extres native dest=0x%016llx\n", (unsigned long long)dest_cpu[0]);

    import_res_shared[0].ext_resource = import_gpu_va | 0;
    import_list_shared.count = 1;
    import_list_shared.ext_res[0] = import_res_shared[0];

    memset(dest_cpu, 0xAA, 4096);
    fill_atom(&atom, jc_gpu_va, BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              3, (uint64_t)(uintptr_t)import_res_shared, 1);
    submit_atom(mali_fd, &atom, &ev, "hw extres import shared");
    printf("hw extres import shared dest=0x%016llx\n", (unsigned long long)dest_cpu[0]);

    build_zero_desc(jc_cpu, import_gpu_va);
    memset(ion_map, 0xBB, 4096);
    fill_atom(&atom, jc_gpu_va, BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              18, (uint64_t)(uintptr_t)import_res_shared, 1);
    submit_atom(mali_fd, &atom, &ev, "hw extres import shared target-import");
    printf("hw extres import shared ion=0x%016llx\n", (unsigned long long)*(uint64_t *)ion_map);
    build_zero_desc(jc_cpu, dest_gpu_va);

    import_res_excl[0].ext_resource = import_gpu_va | 1;
    import_list_excl.count = 1;
    import_list_excl.ext_res[0] = import_res_excl[0];

    memset(dest_cpu, 0xAA, 4096);
    fill_atom(&atom, jc_gpu_va, BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              8, (uint64_t)(uintptr_t)import_res_excl, 1);
    submit_atom(mali_fd, &atom, &ev, "hw extres import excl");
    printf("hw extres import excl dest=0x%016llx\n", (unsigned long long)dest_cpu[0]);

    build_zero_desc(jc_cpu, import_gpu_va);
    memset(ion_map, 0xBB, 4096);
    fill_atom(&atom, jc_gpu_va, BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              19, (uint64_t)(uintptr_t)import_res_excl, 1);
    submit_atom(mali_fd, &atom, &ev, "hw extres import excl target-import");
    printf("hw extres import excl ion=0x%016llx\n", (unsigned long long)*(uint64_t *)ion_map);
    build_zero_desc(jc_cpu, dest_gpu_va);

    fill_atom(&atom, (uint64_t)(uintptr_t)&native_list, BASE_JD_REQ_SOFT_EXT_RES_MAP,
              4, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "soft map native");

    fill_atom(&atom, (uint64_t)(uintptr_t)&native_list, BASE_JD_REQ_SOFT_EXT_RES_UNMAP,
              5, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "soft unmap native");

    fill_atom(&atom, (uint64_t)(uintptr_t)&import_list_shared, BASE_JD_REQ_SOFT_EXT_RES_MAP,
              6, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "soft map import shared");

    fill_atom(&atom, (uint64_t)(uintptr_t)&import_list_shared, BASE_JD_REQ_SOFT_EXT_RES_UNMAP,
              7, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "soft unmap import shared");

    fill_atom(&atom, (uint64_t)(uintptr_t)&import_list_excl, BASE_JD_REQ_SOFT_EXT_RES_MAP,
              9, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "soft map import excl");

    fill_atom(&atom, (uint64_t)(uintptr_t)&import_list_excl, BASE_JD_REQ_SOFT_EXT_RES_UNMAP,
              10, 0, 0);
    submit_atom(mali_fd, &atom, &ev, "soft unmap import excl");

    memset(dest_cpu, 0xAA, 4096);
    fill_atom(&chain[0], (uint64_t)(uintptr_t)&import_list_shared, BASE_JD_REQ_SOFT_EXT_RES_MAP,
              11, 0, 0);
    fill_atom(&chain[1], jc_gpu_va, BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              12, (uint64_t)(uintptr_t)import_res_shared, 1);
    fill_atom(&chain[2], (uint64_t)(uintptr_t)&import_list_shared, BASE_JD_REQ_SOFT_EXT_RES_UNMAP,
              13, 0, 0);
    set_dep(&chain[1].pre_dep[0], 11, BASE_JD_DEP_TYPE_DATA);
    set_dep(&chain[2].pre_dep[0], 12, BASE_JD_DEP_TYPE_DATA);
    submit_atoms(mali_fd, chain, 3, chain_evs, "map->hw->unmap shared");
    printf("map->hw->unmap shared dest=0x%016llx\n", (unsigned long long)dest_cpu[0]);

    memset(dest_cpu, 0xAA, 4096);
    fill_atom(&chain[0], (uint64_t)(uintptr_t)&import_list_excl, BASE_JD_REQ_SOFT_EXT_RES_MAP,
              14, 0, 0);
    fill_atom(&chain[1], jc_gpu_va, BASE_JD_REQ_CS | BASE_JD_REQ_EXTERNAL_RESOURCES,
              15, (uint64_t)(uintptr_t)import_res_excl, 1);
    fill_atom(&chain[2], (uint64_t)(uintptr_t)&import_list_excl, BASE_JD_REQ_SOFT_EXT_RES_UNMAP,
              16, 0, 0);
    set_dep(&chain[1].pre_dep[0], 14, BASE_JD_DEP_TYPE_DATA);
    set_dep(&chain[2].pre_dep[0], 15, BASE_JD_DEP_TYPE_DATA);
    submit_atoms(mali_fd, chain, 3, chain_evs, "map->hw->unmap excl");
    printf("map->hw->unmap excl dest=0x%016llx\n", (unsigned long long)dest_cpu[0]);

out:
    if (dest_cpu != MAP_FAILED)
        munmap(dest_cpu, 4096);
    if (jc_cpu != MAP_FAILED)
        munmap(jc_cpu, 4096);
    mali_free_checked(mali_fd, dest_gpu_va);
    mali_free_checked(mali_fd, jc_gpu_va);
    mali_free_checked(mali_fd, native_gpu_va);
    mali_free_checked(mali_fd, import_gpu_va);
    if (mali_fd >= 0)
        close(mali_fd);
    if (ion_map != MAP_FAILED)
        munmap(ion_map, 4096);
    if (dma_fd >= 0)
        close(dma_fd);
    if (ion_fd >= 0) {
        if (ion_handle >= 0) {
            struct ion_handle_data free_data;
            free_data.handle = ion_handle;
            ioctl(ion_fd, ION_IOC_FREE, &free_data);
        }
        close(ion_fd);
    }
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
