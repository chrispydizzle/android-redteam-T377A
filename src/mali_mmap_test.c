/*
 * mali_mmap_test.c — Focus on getting Mali mmap working
 * 
 * Try every flag + offset combination to successfully mmap GPU memory.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DEV_PATH "/dev/mali0"
#define PAGE_SIZE 4096

struct uk_header { uint32_t id; uint32_t ret; };

static unsigned int make_cmd(uint32_t size) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, size);
}

static void *do_mmap2(void *addr, size_t len, int prot, int flags,
                      int fd, unsigned long pgoff) {
    return (void*)syscall(__NR_mmap2, addr, len, prot, flags, fd, pgoff);
}

static int mali_fd;

static int do_handshake(void) {
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = 0;
    buf[8] = 10;
    if (ioctl(mali_fd, make_cmd(16), buf) < 0) return -1;
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = 530;
    if (ioctl(mali_fd, make_cmd(16), buf) < 0) return -1;
    return 0;
}

static uint64_t gpu_alloc(uint32_t pages, uint32_t flags) {
    uint8_t buf[56];
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = 512;
    *(uint64_t*)(buf + 8)  = pages;
    *(uint64_t*)(buf + 16) = pages;
    *(uint32_t*)(buf + 32) = flags;
    if (ioctl(mali_fd, make_cmd(56), buf) < 0) return 0;
    return *(uint64_t*)(buf + 40);
}

static int gpu_free(uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    return ioctl(mali_fd, make_cmd(16), buf);
}

/* All user-facing memory flags to try */
#define F_CR  (1U << 0)   /* CPU_RD */
#define F_CW  (1U << 1)   /* CPU_WR */
#define F_GR  (1U << 2)   /* GPU_RD */
#define F_GW  (1U << 3)   /* GPU_WR */
#define F_GX  (1U << 4)   /* GPU_EX */
#define F_GPF (1U << 9)   /* GROW_ON_GPF */
#define F_CL  (1U << 11)  /* COHERENT_LOCAL */
#define F_CC  (1U << 12)  /* CACHED_CPU */
#define F_SV  (1U << 17)  /* SAME_VA */
#define F_NM  (1U << 18)  /* NEED_MMAP */

int main(void) {
    fprintf(stderr, "=== Mali mmap brute-force test ===\n");

    mali_fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (mali_fd < 0) { perror("open"); return 1; }
    if (do_handshake() < 0) { fprintf(stderr, "handshake fail\n"); return 1; }
    fprintf(stderr, "[+] Ready\n\n");

    /* Try every useful flag combination */
    uint32_t flag_sets[] = {
        F_CR | F_CW | F_GR | F_GW,
        F_CR | F_CW | F_GR | F_GW | F_CC,
        F_CR | F_CW | F_GR | F_GW | F_NM,
        F_CR | F_CW | F_GR | F_GW | F_CC | F_NM,
        F_CR | F_CW | F_GR,
        F_CR | F_CW | F_GR | F_NM,
        F_CR | F_CW | F_GR | F_CC,
        F_CR | F_CW | F_GR | F_CC | F_NM,
        F_CR | F_GR,
        F_CR | F_GR | F_NM,
        F_CR | F_CW,
        F_CR | F_CW | F_NM,
        F_CR | F_CW | F_CC,
        F_CR | F_CW | F_CC | F_NM,
        F_CR | F_CW | F_GR | F_GW | F_CL,
        F_CR | F_CW | F_GR | F_GW | F_CL | F_NM,
        F_CR | F_CW | F_GR | F_GW | F_GPF,
        F_CR | F_CW | F_GR | F_GW | F_GPF | F_NM,
        /* SAME_VA variants — might fail on 32-bit */
        F_CR | F_CW | F_GR | F_GW | F_SV,
        F_CR | F_CW | F_GR | F_GW | F_SV | F_CC,
    };

    for (int fi = 0; fi < (int)(sizeof(flag_sets)/sizeof(flag_sets[0])); fi++) {
        uint32_t flags = flag_sets[fi];
        uint64_t va = gpu_alloc(1, flags);
        if (!va) {
            if (flags & (F_SV|F_NM))
                continue; /* expected failure */
            fprintf(stderr, "[*] flags=0x%05x: alloc failed\n", flags);
            continue;
        }

        /* Calculate pgoff variants */
        unsigned long pgoff_variants[] = {
            (unsigned long)(va >> 12),           /* gpu_va / PAGE_SIZE */
            (unsigned long)(va & 0xFFFFFFFF),    /* lower 32 bits raw */
            (unsigned long)((va >> 12) & 0xFFFFF),/* 20-bit page offset */
            (unsigned long)(va >> 12) & 0xFFFFFFFF,
            0,                                    /* offset=0 */
        };

        int mmap_ok = 0;
        for (int pi = 0; pi < 5 && !mmap_ok; pi++) {
            for (int prot = PROT_READ | PROT_WRITE; prot >= PROT_READ;
                 prot = (prot == (PROT_READ|PROT_WRITE)) ? PROT_READ : -1) {
                if (prot < 0) break;

                void *p = do_mmap2(NULL, PAGE_SIZE, prot, MAP_SHARED,
                                   mali_fd, pgoff_variants[pi]);
                if (p != MAP_FAILED) {
                    fprintf(stderr, "[!] flags=0x%05x pgoff=0x%lx prot=%d → %p !\n",
                            flags, pgoff_variants[pi], prot, p);

                    /* Test read */
                    volatile uint32_t v = *(volatile uint32_t*)p;
                    fprintf(stderr, "    Read: 0x%08x\n", v);

                    if (prot & PROT_WRITE) {
                        *(volatile uint32_t*)p = 0xDEADBEEF;
                        v = *(volatile uint32_t*)p;
                        fprintf(stderr, "    Write+Read: 0x%08x\n", v);
                    }

                    munmap(p, PAGE_SIZE);
                    mmap_ok = 1;
                    break;
                }
            }
        }

        if (!mmap_ok) {
            fprintf(stderr, "[*] flags=0x%05x va=0x%llx: all mmap failed (e=%d)\n",
                    flags, (unsigned long long)va, errno);
        }

        gpu_free(va);
    }

    /* Also test: open a second mali fd and mmap with it */
    fprintf(stderr, "\n[*] Testing mmap on second Mali fd...\n");
    int fd2 = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd2 >= 0) {
        /* Handshake on fd2 */
        uint8_t hbuf[16];
        memset(hbuf, 0, 16);
        ((struct uk_header*)hbuf)->id = 0;
        hbuf[8] = 10;
        ioctl(fd2, make_cmd(16), hbuf);
        memset(hbuf, 0, 16);
        ((struct uk_header*)hbuf)->id = 530;
        ioctl(fd2, make_cmd(16), hbuf);

        /* Allocate on fd2 */
        uint8_t abuf[56];
        memset(abuf, 0, sizeof(abuf));
        ((struct uk_header*)abuf)->id = 512;
        *(uint64_t*)(abuf + 8) = 1;
        *(uint64_t*)(abuf + 16) = 1;
        *(uint32_t*)(abuf + 32) = F_CR | F_CW | F_GR | F_GW | F_CC;
        if (ioctl(fd2, make_cmd(56), abuf) >= 0) {
            uint64_t va2 = *(uint64_t*)(abuf + 40);
            fprintf(stderr, "[*] fd2 alloc @ 0x%llx\n", (unsigned long long)va2);

            unsigned long pgoff2 = (unsigned long)(va2 >> 12);
            void *p2 = do_mmap2(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                MAP_SHARED, fd2, pgoff2);
            if (p2 != MAP_FAILED) {
                fprintf(stderr, "[!] fd2 mmap OK @ %p\n", p2);
                *(volatile uint32_t*)p2 = 0x12345678;
                fprintf(stderr, "[!] fd2 write: 0x%08x\n",
                        *(volatile uint32_t*)p2);
                munmap(p2, PAGE_SIZE);
            } else {
                fprintf(stderr, "[*] fd2 mmap failed: %s\n", strerror(errno));
            }

            /* Free on fd2 */
            memset(abuf, 0, 16);
            ((struct uk_header*)abuf)->id = 516;
            *(uint64_t*)(abuf + 8) = va2;
            ioctl(fd2, make_cmd(16), abuf);
        }
        close(fd2);
    }

    /* Also try mmap with offset=0 for the first page */
    fprintf(stderr, "\n[*] Testing mmap offset=0...\n");
    {
        void *p = do_mmap2(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, mali_fd, 0);
        if (p != MAP_FAILED) {
            fprintf(stderr, "[!] mmap(offset=0) OK @ %p, val=0x%08x\n",
                    p, *(volatile uint32_t*)p);
            munmap(p, PAGE_SIZE);
        } else {
            fprintf(stderr, "[*] mmap(offset=0) failed: %s\n", strerror(errno));
        }
    }

    close(mali_fd);
    fprintf(stderr, "\n=== Done ===\n");
    return 0;
}
