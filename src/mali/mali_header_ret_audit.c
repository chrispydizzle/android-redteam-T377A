#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

#define UKP_FUNC_ID_CHECK_VERSION   0
#define UK_FUNC_ID                  512
#define KBASE_FUNC_MEM_ALLOC        (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_COMMIT       (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY        (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE         (UK_FUNC_ID + 4)
#define KBASE_FUNC_SET_FLAGS        (UK_FUNC_ID + 18)
#define KBASE_FUNC_MEM_FLAGS_CHANGE (UK_FUNC_ID + 5)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1ULL

#define BASE_MEM_PROT_CPU_RD    (1U << 0)
#define BASE_MEM_PROT_CPU_WR    (1U << 1)
#define BASE_MEM_PROT_GPU_RD    (1U << 2)
#define BASE_MEM_PROT_GPU_WR    (1U << 3)
#define BASE_MEM_PROT_GPU_EX    (1U << 4)
#define BASE_MEM_GROW_ON_GPF    (1U << 9)
#define BASE_MEM_COHERENT_LOCAL (1U << 11)

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

struct kbase_uk_mem_flags_change {
    uk_header header;
    uint64_t gpu_va;
    uint32_t flags;
    uint32_t mask;
};

struct kbase_uk_mem_query {
    uk_header header;
    uint64_t gpu_addr;
    uint64_t query;
    uint64_t value;
};

struct kbase_uk_mem_commit {
    uk_header header;
    uint64_t gpu_addr;
    uint64_t pages;
    uint32_t result_subcode;
    uint32_t padding;
};

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

static int mali_open_ctx(void)
{
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);

    if (fd < 0)
        return -1;
    if (mali_init(fd) < 0 || mali_setup_mtp(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static uint64_t mali_alloc(int fd, uint64_t va_pages, uint64_t commit_pages,
                           uint64_t extent, uint32_t flags, uint32_t *ret_out)
{
    struct kbase_uk_mem_alloc alloc;

    memset(&alloc, 0, sizeof(alloc));
    alloc.header.id = KBASE_FUNC_MEM_ALLOC;
    alloc.va_pages = va_pages;
    alloc.commit_pages = commit_pages;
    alloc.extent = extent;
    alloc.flags = flags;
    if (mali_ioctl(fd, &alloc, sizeof(alloc)) < 0) {
        if (ret_out)
            *ret_out = 0xFFFFFFFFU;
        return 0;
    }
    if (ret_out)
        *ret_out = alloc.header.ret;
    return alloc.header.ret == 0 ? alloc.gpu_va : 0;
}

static uint32_t mali_free(int fd, uint64_t gpu_va)
{
    struct kbase_uk_mem_free mf;

    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = gpu_va;
    if (mali_ioctl(fd, &mf, sizeof(mf)) < 0)
        return 0xFFFFFFFFU;
    return mf.header.ret;
}

static uint32_t mali_flags_change(int fd, uint64_t gpu_va, uint32_t flags, uint32_t mask)
{
    struct kbase_uk_mem_flags_change fc;

    memset(&fc, 0, sizeof(fc));
    fc.header.id = KBASE_FUNC_MEM_FLAGS_CHANGE;
    fc.gpu_va = gpu_va;
    fc.flags = flags;
    fc.mask = mask;
    if (mali_ioctl(fd, &fc, sizeof(fc)) < 0)
        return 0xFFFFFFFFU;
    return fc.header.ret;
}

static uint32_t mali_query_commit(int fd, uint64_t gpu_va, uint64_t *value_out)
{
    struct kbase_uk_mem_query q;

    memset(&q, 0, sizeof(q));
    q.header.id = KBASE_FUNC_MEM_QUERY;
    q.gpu_addr = gpu_va;
    q.query = KBASE_MEM_QUERY_COMMIT_SIZE;
    if (mali_ioctl(fd, &q, sizeof(q)) < 0)
        return 0xFFFFFFFFU;
    if (value_out)
        *value_out = q.value;
    return q.header.ret;
}

static uint32_t mali_commit(int fd, uint64_t gpu_va, int64_t pages, uint32_t *subcode_out)
{
    struct kbase_uk_mem_commit c;

    memset(&c, 0, sizeof(c));
    c.header.id = KBASE_FUNC_MEM_COMMIT;
    c.gpu_addr = gpu_va;
    c.pages = (uint64_t)pages;
    if (mali_ioctl(fd, &c, sizeof(c)) < 0)
        return 0xFFFFFFFFU;
    if (subcode_out)
        *subcode_out = c.result_subcode;
    return c.header.ret;
}

static void *mali_cpu_map(int fd, uint64_t gpu_va, int prot)
{
    return (void *)syscall(__NR_mmap2, (unsigned long)NULL, (size_t)4096,
                           prot, MAP_SHARED, fd, (unsigned long)(gpu_va >> 12));
}

static void test_double_free(int fd)
{
    uint32_t alloc_ret = 0;
    uint64_t gpu_va;
    uint32_t free1, free2;

    printf("\n=== TEST 1: same-context double free ===\n");
    gpu_va = mali_alloc(fd, 1, 1, 1,
                        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                        BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                        BASE_MEM_COHERENT_LOCAL,
                        &alloc_ret);
    printf("alloc ret=0x%x gpu_va=0x%llx\n",
           alloc_ret, (unsigned long long)gpu_va);
    if (!gpu_va)
        return;

    free1 = mali_free(fd, gpu_va);
    free2 = mali_free(fd, gpu_va);
    printf("free#1 ret=0x%x free#2 ret=0x%x\n", free1, free2);
}

static void test_flags_change(int fd)
{
    uint32_t alloc_ret = 0;
    uint64_t gpu_va;
    void *ro_map = MAP_FAILED;
    void *rw_map = MAP_FAILED;
    uint32_t ret_cpuwr, ret_gpuex, ret_grow;

    printf("\n=== TEST 2: MEM_FLAGS_CHANGE on live region ===\n");
    gpu_va = mali_alloc(fd, 1, 1, 1,
                        BASE_MEM_PROT_CPU_RD |
                        BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                        BASE_MEM_COHERENT_LOCAL,
                        &alloc_ret);
    printf("alloc ret=0x%x gpu_va=0x%llx\n",
           alloc_ret, (unsigned long long)gpu_va);
    if (!gpu_va)
        return;

    ro_map = mali_cpu_map(fd, gpu_va, PROT_READ);
    printf("initial PROT_READ mmap=%p errno=%d\n", ro_map, ro_map == MAP_FAILED ? errno : 0);

    ret_cpuwr = mali_flags_change(fd, gpu_va, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_CPU_WR);
    ret_gpuex = mali_flags_change(fd, gpu_va, BASE_MEM_PROT_GPU_EX, BASE_MEM_PROT_GPU_EX);
    ret_grow = mali_flags_change(fd, gpu_va, BASE_MEM_GROW_ON_GPF, BASE_MEM_GROW_ON_GPF);
    printf("FLAGS_CHANGE +CPU_WR ret=0x%x +GPU_EX ret=0x%x +GROW_ON_GPF ret=0x%x\n",
           ret_cpuwr, ret_gpuex, ret_grow);

    if (ro_map != MAP_FAILED)
        munmap(ro_map, 4096);
    rw_map = mali_cpu_map(fd, gpu_va, PROT_READ | PROT_WRITE);
    printf("post-change PROT_READ|PROT_WRITE mmap=%p errno=%d\n",
           rw_map, rw_map == MAP_FAILED ? errno : 0);
    if (rw_map != MAP_FAILED) {
        volatile uint32_t *w = (volatile uint32_t *)rw_map;
        w[0] = 0xDEADBEEF;
        printf("write/readback=0x%08x\n", w[0]);
        munmap(rw_map, 4096);
    }

    printf("cleanup free ret=0x%x\n", mali_free(fd, gpu_va));
}

static void test_flags_change_freed(int fd)
{
    uint32_t alloc_ret = 0;
    uint64_t gpu_va;
    uint32_t free_ret, fc_ret;

    printf("\n=== TEST 3: MEM_FLAGS_CHANGE on freed region ===\n");
    gpu_va = mali_alloc(fd, 1, 1, 1,
                        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                        BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                        BASE_MEM_COHERENT_LOCAL,
                        &alloc_ret);
    printf("alloc ret=0x%x gpu_va=0x%llx\n",
           alloc_ret, (unsigned long long)gpu_va);
    if (!gpu_va)
        return;

    free_ret = mali_free(fd, gpu_va);
    fc_ret = mali_flags_change(fd, gpu_va, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_CPU_WR);
    printf("free ret=0x%x FLAGS_CHANGE-after-free ret=0x%x\n", free_ret, fc_ret);
}

static void test_commit(int fd)
{
    uint32_t alloc_ret = 0;
    uint64_t gpu_va;
    uint64_t before = 0, after = 0;
    uint32_t qret_before, qret_after;
    uint32_t sub_neg1 = 0, sub_big = 0;
    uint32_t cret_neg1, cret_big;
    uint32_t post_ret = 0;
    uint64_t post_va;

    printf("\n=== TEST 4: MEM_COMMIT / QUERY validation ===\n");
    gpu_va = mali_alloc(fd, 16, 1, 15,
                        BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                        BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                        BASE_MEM_GROW_ON_GPF | BASE_MEM_COHERENT_LOCAL,
                        &alloc_ret);
    printf("alloc ret=0x%x gpu_va=0x%llx\n",
           alloc_ret, (unsigned long long)gpu_va);
    if (!gpu_va)
        return;

    qret_before = mali_query_commit(fd, gpu_va, &before);
    cret_neg1 = mali_commit(fd, gpu_va, -1, &sub_neg1);
    qret_after = mali_query_commit(fd, gpu_va, &after);
    cret_big = mali_commit(fd, gpu_va, 0x7FFFFFFF, &sub_big);
    printf("QUERY before ret=0x%x value=%llu\n",
           qret_before, (unsigned long long)before);
    printf("COMMIT(-1) ret=0x%x sub=0x%x\n", cret_neg1, sub_neg1);
    printf("QUERY after ret=0x%x value=%llu\n",
           qret_after, (unsigned long long)after);
    printf("COMMIT(0x7fffffff) ret=0x%x sub=0x%x\n", cret_big, sub_big);

    post_va = mali_alloc(fd, 1, 1, 1,
                         BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                         BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                         BASE_MEM_COHERENT_LOCAL,
                         &post_ret);
    printf("post-commit alloc ret=0x%x gpu_va=0x%llx\n",
           post_ret, (unsigned long long)post_va);
    if (post_va)
        printf("post-commit free ret=0x%x\n", mali_free(fd, post_va));

    printf("cleanup free ret=0x%x\n", mali_free(fd, gpu_va));
}

static void run_probe(void)
{
    int fd = mali_open_ctx();

    if (fd < 0) {
        printf("failed to open/init Mali context\n");
        return;
    }
    test_double_free(fd);
    test_flags_change(fd);
    test_flags_change_freed(fd);
    test_commit(fd);
    close(fd);
}

int main(void)
{
    pid_t pid;
    int status = 0;

    printf("=== Mali header.ret audit probe ===\n");
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
