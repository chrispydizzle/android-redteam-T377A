#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/syscall.h>

#define DEV_PATH "/dev/mali0"
#define CALL_MAX_SIZE 536

// Function IDs (Samsung/ARM UK)
#define UKP_FUNC_ID_CHECK_VERSION      0
#define KBASE_FUNC_MEM_ALLOC           512
#define KBASE_FUNC_MEM_IMPORT          513
#define KBASE_FUNC_MEM_COMMIT          514
#define KBASE_FUNC_MEM_QUERY           515
#define KBASE_FUNC_MEM_FREE            516
#define KBASE_FUNC_MEM_FLAGS_CHANGE    517
#define KBASE_FUNC_MEM_ALIAS           518
#define KBASE_FUNC_JOB_SUBMIT_UK6      519 // Older
#define KBASE_FUNC_SYNC                520
#define KBASE_FUNC_POST_TERM           521
#define KBASE_FUNC_HWCNT_SETUP         522
#define KBASE_FUNC_HWCNT_DUMP          523
#define KBASE_FUNC_HWCNT_CLEAR         524
#define KBASE_FUNC_GPU_PROPS_REG_DUMP  526
#define KBASE_FUNC_GET_VERSION         528
#define KBASE_FUNC_SET_FLAGS           530
#define KBASE_FUNC_STREAM_CREATE       536
#define KBASE_FUNC_DISJOINT_QUERY      541
#define KBASE_FUNC_GET_CONTEXT_ID      543
#define KBASE_FUNC_TLSTREAM_ACQUIRE    544
#define KBASE_FUNC_TLSTREAM_TEST       545
#define KBASE_FUNC_TLSTREAM_STATS      546
#define KBASE_FUNC_TLSTREAM_FLUSH      547
#define KBASE_FUNC_JOB_SUBMIT          540 // Newer

#define KBASE_MEM_QUERY_COMMIT_SIZE    1ULL

/* --- Real structs from Samsung GPL source --- */

union uk_header {
    uint32_t id;     /* input: function ID */
    uint32_t ret;    /* output: mali error code (0=ok, 3=function_failed) */
    uint64_t sizer;  /* force 8-byte size/alignment */
};

/* sizeof = 16 */
struct uku_version_check_args {
    union uk_header header;
    uint16_t major;
    uint16_t minor;
    uint8_t padding[4];
};

/* sizeof = 16 */
struct kbase_uk_set_flags {
    union uk_header header;
    uint32_t create_flags;
    uint32_t padding;
};

/* sizeof = 80 */
#define KBASE_GET_VERSION_BUFFER_SIZE 64
struct kbase_uk_get_ddk_version {
    union uk_header header;
    char version_buffer[KBASE_GET_VERSION_BUFFER_SIZE];
    uint32_t version_string_size;
    uint32_t padding;
};

/* sizeof = 56 */
struct kbase_uk_mem_alloc {
    union uk_header header;
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extent;
    uint64_t flags;
    uint64_t gpu_va;
    uint16_t va_alignment;
    uint8_t  padding[6];
};

/* sizeof = 16 */
struct kbase_uk_mem_free {
    union uk_header header;
    uint64_t gpu_addr;
};

/* sizeof = 32 */
struct kbase_uk_mem_query {
    union uk_header header;
    uint64_t gpu_addr;
    uint64_t query;
    uint64_t value;
};

/* sizeof = 32 */
struct kbase_uk_mem_flags_change {
    union uk_header header;
    uint64_t gpu_va;
    uint64_t flags;
    uint64_t mask;
};

/* sizeof = 48 */
struct kbase_uk_mem_alias {
    union uk_header header;
    uint64_t flags;
    uint64_t stride;
    uint64_t nents;
    uint64_t aliasing_info; // pointer to array
    uint64_t gpu_va;
};

/* sizeof = 32 */
struct kbase_uk_mem_import {
    union uk_header header;
    uint64_t phandle; // fd
    uint64_t type;
    uint64_t flags; // output?
    uint64_t gpu_va; // output
    uint64_t va_pages; // output
    uint64_t usage;
};

/* sizeof = 32 */
struct kbase_uk_job_submit {
    union uk_header header;
    uint64_t addr; // pointer to atoms
    uint32_t nr_atoms;
    uint32_t stride;
};

/* sizeof = 536 */
#define KBASE_UK_GPUPROPS_SIZE 536

/* ---- Fuzzer plumbing ---- */

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

/* xorshift64 */
static __thread uint64_t rng_state = 0;

static void seed_rng(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rng_state = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec ^ (uint64_t)syscall(SYS_gettid);
}

static uint64_t rnd64(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}
static uint32_t rnd32(void) { return (uint32_t)rnd64(); }

static unsigned long make_cmd(uint32_t size) {
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, size);
}

static void fill_random(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rnd32();
}

static int uk_ioctl(int fd, void *buf, uint32_t size) {
    errno = 0;
    return ioctl(fd, make_cmd(size), buf);
}

static int do_handshake(int fd) {
    struct uku_version_check_args ver;
    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10;
    ver.minor = 0;
    if (uk_ioctl(fd, &ver, (uint32_t)sizeof(ver)) < 0) return -1;
    if (ver.header.ret != 0) return -1;

    struct kbase_uk_set_flags flags;
    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    flags.create_flags = 0;
    if (uk_ioctl(fd, &flags, (uint32_t)sizeof(flags)) < 0) return -1;
    if (flags.header.ret != 0) return -1;

    return 0;
}

/* ---- Shared allocation table for Race Conditions ---- */

#define MAX_ALLOCS 256
struct alloc_entry {
    uint64_t gpu_va;
    uint64_t va_pages;
    uint64_t flags;
    int in_use;
};
static struct alloc_entry g_allocs[MAX_ALLOCS];
static pthread_mutex_t g_allocs_lock = PTHREAD_MUTEX_INITIALIZER;

static void allocs_add(uint64_t gpu_va, uint64_t va_pages, uint64_t flags) {
    if (!gpu_va) return;
    pthread_mutex_lock(&g_allocs_lock);
    for (int i = 0; i < MAX_ALLOCS; i++) {
        if (!g_allocs[i].in_use) {
            g_allocs[i].in_use = 1;
            g_allocs[i].gpu_va = gpu_va;
            g_allocs[i].va_pages = va_pages;
            g_allocs[i].flags = flags;
            pthread_mutex_unlock(&g_allocs_lock);
            return;
        }
    }
    // overwrite random slot
    int j = (int)(rnd32() % MAX_ALLOCS);
    g_allocs[j].in_use = 1;
    g_allocs[j].gpu_va = gpu_va;
    g_allocs[j].va_pages = va_pages;
    g_allocs[j].flags = flags;
    pthread_mutex_unlock(&g_allocs_lock);
}

static uint64_t allocs_pick_any(int *out_index) {
    int live[MAX_ALLOCS];
    int n = 0;
    pthread_mutex_lock(&g_allocs_lock);
    for (int i = 0; i < MAX_ALLOCS; i++) if (g_allocs[i].in_use) live[n++] = i;
    
    if (n == 0) {
        pthread_mutex_unlock(&g_allocs_lock);
        return 0;
    }
    int idx = live[rnd32() % (uint32_t)n];
    if (out_index) *out_index = idx;
    uint64_t val = g_allocs[idx].gpu_va;
    pthread_mutex_unlock(&g_allocs_lock);
    return val;
}

static void allocs_free_index(int idx) {
    pthread_mutex_lock(&g_allocs_lock);
    if (idx >= 0 && idx < MAX_ALLOCS) g_allocs[idx].in_use = 0;
    pthread_mutex_unlock(&g_allocs_lock);
}

/* ---- Structured ops ---- */

static void op_get_version(int fd) {
    struct kbase_uk_get_ddk_version v;
    memset(&v, 0, sizeof(v));
    v.header.id = KBASE_FUNC_GET_VERSION;
    v.version_string_size = KBASE_GET_VERSION_BUFFER_SIZE;
    uk_ioctl(fd, &v, (uint32_t)sizeof(v));
}

static void op_gpu_props(int fd) {
    uint8_t buf[KBASE_UK_GPUPROPS_SIZE];
    memset(buf, 0, sizeof(buf));
    ((union uk_header*)buf)->id = KBASE_FUNC_GPU_PROPS_REG_DUMP;
    uk_ioctl(fd, buf, (uint32_t)sizeof(buf));
}

static void op_mem_alloc(int fd) {
    struct kbase_uk_mem_alloc m;
    memset(&m, 0, sizeof(m));
    m.header.id = KBASE_FUNC_MEM_ALLOC;

    const uint64_t base_flags = 0x20fULL;
    uint64_t flags = base_flags;

    if ((rnd32() % 3) == 0) flags ^= (1ULL << (rnd32() % 16));
    
    uint64_t va_pages = (rnd32() % 16) + 1;
    
    m.va_pages = va_pages;
    m.commit_pages = va_pages;
    m.flags = flags;

    int r = uk_ioctl(fd, &m, (uint32_t)sizeof(m));
    if (r == 0 && m.header.ret == 0) {
        allocs_add(m.gpu_va, m.va_pages, m.flags);
    }
}

static void op_mem_free(int fd) {
    int idx = -1;
    uint64_t va = allocs_pick_any(&idx);
    if (!va) return;

    struct kbase_uk_mem_free f;
    memset(&f, 0, sizeof(f));
    f.header.id = KBASE_FUNC_MEM_FREE;
    f.gpu_addr = va;

    int r = uk_ioctl(fd, &f, (uint32_t)sizeof(f));
    if (r == 0 && f.header.ret == 0) {
        allocs_free_index(idx);
    }
}

static void op_mem_flags_change(int fd) {
    int idx = -1;
    uint64_t va = allocs_pick_any(&idx);
    if (!va) return;

    struct kbase_uk_mem_flags_change f;
    memset(&f, 0, sizeof(f));
    f.header.id = KBASE_FUNC_MEM_FLAGS_CHANGE;
    f.gpu_va = va;
    f.flags = rnd32();
    f.mask = rnd32();
    uk_ioctl(fd, &f, (uint32_t)sizeof(f));
}

static void op_mem_alias(int fd) {
    struct kbase_uk_mem_alias a;
    memset(&a, 0, sizeof(a));
    a.header.id = KBASE_FUNC_MEM_ALIAS;
    a.nents = rnd32() % 10;
    a.aliasing_info = (uint64_t)malloc(a.nents * sizeof(uint64_t) * 2); // Leak intentionally or free?
    // Not freeing to avoid complexity, OS will clean up process.
    // Actually leaks inside thread are bad.
    void *ptr = (void*)(uintptr_t)a.aliasing_info;
    
    uk_ioctl(fd, &a, (uint32_t)sizeof(a));
    
    if (ptr) free(ptr);
}

static void op_mem_import(int fd) {
    struct kbase_uk_mem_import imp;
    memset(&imp, 0, sizeof(imp));
    imp.header.id = KBASE_FUNC_MEM_IMPORT;
    imp.type = rnd32() % 4;
    imp.phandle = rnd32() % 100; // Random FDs
    uk_ioctl(fd, &imp, (uint32_t)sizeof(imp));
}

static void op_job_submit(int fd) {
    struct kbase_uk_job_submit js;
    memset(&js, 0, sizeof(js));
    js.header.id = KBASE_FUNC_JOB_SUBMIT;
    js.nr_atoms = (rnd32() % 5) + 1;
    js.stride = sizeof(uint64_t) * 8; // Dummy stride
    js.addr = (uint64_t)calloc(js.nr_atoms, js.stride);
    
    uk_ioctl(fd, &js, (uint32_t)sizeof(js));
    
    free((void*)(uintptr_t)js.addr);
}

static void op_stream_create(int fd) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    ((union uk_header*)buf)->id = KBASE_FUNC_STREAM_CREATE;
    fill_random(buf + 8, sizeof(buf) - 8);
    uk_ioctl(fd, buf, sizeof(buf));
}

static void op_tlstream_acquire(int fd) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    ((union uk_header*)buf)->id = KBASE_FUNC_TLSTREAM_ACQUIRE;
    uk_ioctl(fd, buf, sizeof(buf));
}

static void op_tlstream_flush(int fd) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    ((union uk_header*)buf)->id = KBASE_FUNC_TLSTREAM_FLUSH;
    uk_ioctl(fd, buf, sizeof(buf));
}

static void op_raw_size_fuzz(int fd) {
    uint8_t buf[CALL_MAX_SIZE];
    uint32_t size = (uint32_t)(rnd64() % (CALL_MAX_SIZE + 1));
    if (size < sizeof(union uk_header)) size = (uint32_t)sizeof(union uk_header);

    memset(buf, 0, sizeof(buf));
    fill_random(buf, size);
    
    // Pick ANY ID from range
    uint32_t id = 512 + (rnd32() % 60);
    ((union uk_header*)buf)->id = id;

    uk_ioctl(fd, buf, size);
}

/* ---- Thread Worker ---- */

void *worker_thread(void *arg) {
    seed_rng();
    int fd = (int)(intptr_t)arg;
    
    while (!g_stop) {
        int ops = 10 + (rnd32() % 20);
        for (int i=0; i<ops && !g_stop; i++) {
            uint32_t r = rnd32() % 100;
            if (r < 10) op_get_version(fd);
            else if (r < 20) op_mem_alloc(fd);
            else if (r < 30) op_mem_free(fd);
            else if (r < 35) op_mem_flags_change(fd);
            else if (r < 40) op_mem_alias(fd);
            else if (r < 45) op_mem_import(fd);
            else if (r < 55) op_job_submit(fd);
            else if (r < 60) op_gpu_props(fd);
            else if (r < 65) op_stream_create(fd);
            else if (r < 70) op_tlstream_acquire(fd);
            else if (r < 75) op_tlstream_flush(fd);
            else op_raw_size_fuzz(fd);
        }
        usleep(1000); // slight yield
    }
    return NULL;
}

int main(int argc, char **argv) {
    int num_threads = 4;
    uint64_t duration = 30;

    if (argc >= 2) duration = strtoull(argv[1], NULL, 0);
    if (argc >= 3) num_threads = atoi(argv[2]);

    printf("[*] Mali Multithreaded Fuzzer\n");
    printf("[*] Threads: %d, Duration: %llu sec\n", num_threads, duration);

    signal(SIGINT, on_sigint);

    // Open one FD per thread? Or share? 
    // Sharing FD tests locking on same context. 
    // Separate FDs test locking across contexts.
    // Let's do both. Half threads share one FD, others have their own.
    
    pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
    int shared_fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (shared_fd < 0) {
        perror("open shared");
        return 1;
    }
    if (do_handshake(shared_fd) != 0) {
        perror("handshake shared");
        return 1;
    }

    for (int i = 0; i < num_threads; i++) {
        int fd;
        if (i < num_threads / 2) {
            fd = shared_fd; // Share context
        } else {
            fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
            if (fd < 0 || do_handshake(fd) != 0) {
                printf("[-] Thread %d failed to open/handshake\n", i);
                fd = shared_fd; // Fallback
            }
        }
        pthread_create(&threads[i], NULL, worker_thread, (void*)(intptr_t)fd);
    }

    printf("[*] Fuzzing...\n");
    sleep(duration);
    g_stop = 1;

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("[*] Done.\n");
    return 0;
}
