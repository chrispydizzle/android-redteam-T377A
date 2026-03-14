/*
 * mali_mmap_debug.c — Exhaustive mmap parameter sweep for Mali r7p0
 * 
 * Try MAP_PRIVATE vs MAP_SHARED, every pgoff encoding,
 * and also COHERENT flags which may set KBASE_REG_SHARE_BOTH.
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
static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}
static void *do_mmap2(void *a, size_t l, int p, int f, int fd, unsigned long pg) {
    return (void*)syscall(__NR_mmap2, a, l, p, f, fd, pg);
}

int main(void) {
    int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open"); return 1; }

    /* Handshake */
    uint8_t hb[16];
    memset(hb, 0, 16); ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    ioctl(fd, make_cmd(16), hb);
    memset(hb, 0, 16); ((struct uk_header*)hb)->id = 530;
    ioctl(fd, make_cmd(16), hb);
    fprintf(stderr, "[+] Ready\n");

    /* Allocate with COHERENT flags */
    uint32_t alloc_flags[] = {
        0x0F,       /* CPU_RD|CPU_WR|GPU_RD|GPU_WR */
        0x0F | (1U<<10),  /* + COHERENT_SYSTEM */
        0x0F | (1U<<11),  /* + COHERENT_LOCAL */
        0x0F | (1U<<10) | (1U<<11), /* + COHERENT_SYSTEM + LOCAL */
        0x0F | (1U<<12),  /* + CACHED_CPU */
        0x0F | (1U<<12) | (1U<<10), /* CACHED + COHERENT_SYSTEM */
        0x0F | (1U<<12) | (1U<<11), /* CACHED + COHERENT_LOCAL */
        0x0F | (1U<<12) | (1U<<10) | (1U<<11), /* CACHED + both coherent */
    };

    int mmap_flags[] = { MAP_SHARED, MAP_PRIVATE };
    const char *mmap_names[] = { "SHARED", "PRIVATE" };
    int prots[] = { PROT_READ, PROT_READ|PROT_WRITE };
    const char *prot_names[] = { "RD", "RW" };

    for (int ai = 0; ai < 8; ai++) {
        uint8_t ab[56];
        memset(ab, 0, 56);
        ((struct uk_header*)ab)->id = 512;
        *(uint64_t*)(ab + 8) = 1;
        *(uint64_t*)(ab + 16) = 1;
        *(uint32_t*)(ab + 32) = alloc_flags[ai];

        if (ioctl(fd, make_cmd(56), ab) < 0) continue;
        uint32_t va32 = *(uint32_t*)(ab + 40);
        uint64_t va64 = *(uint64_t*)(ab + 40);
        if (!va32 && !va64) continue;

        fprintf(stderr, "\n[*] alloc_flags=0x%05x va32=0x%08x va64=0x%llx\n",
                alloc_flags[ai], va32, (unsigned long long)va64);

        /* Build pgoff candidates */
        unsigned long pgoffs[8];
        int npg = 0;
        pgoffs[npg++] = (unsigned long)(va64 >> 12);
        pgoffs[npg++] = (unsigned long)(va32 >> 12);
        if ((va64 >> 12) != (va32 >> 12))
            pgoffs[npg++] = (unsigned long)((va64 >> 12) & 0xFFFFFFFF);
        pgoffs[npg++] = va32;
        pgoffs[npg++] = 0;

        for (int mi = 0; mi < 2; mi++) {
            for (int pi = 0; pi < 2; pi++) {
                for (int gi = 0; gi < npg; gi++) {
                    void *p = do_mmap2(NULL, PAGE_SIZE, prots[pi],
                                       mmap_flags[mi], fd, pgoffs[gi]);
                    if (p != MAP_FAILED) {
                        fprintf(stderr, "[!!!] SUCCESS: flags=0x%05x %s %s pgoff=0x%lx → %p\n",
                                alloc_flags[ai], mmap_names[mi],
                                prot_names[pi], pgoffs[gi], p);
                        volatile uint32_t v = *(volatile uint32_t*)p;
                        fprintf(stderr, "     read=0x%08x\n", v);
                        if (prots[pi] & PROT_WRITE) {
                            *(volatile uint32_t*)p = 0xDEADBEEF;
                            fprintf(stderr, "     write=0x%08x\n",
                                    *(volatile uint32_t*)p);
                        }
                        munmap(p, PAGE_SIZE);
                    }
                }
            }
        }

        /* Free */
        memset(ab, 0, 16);
        ((struct uk_header*)ab)->id = 516;
        *(uint64_t*)(ab + 8) = va64;
        ioctl(fd, make_cmd(16), ab);
    }

    /* Also try special mmap handles */
    fprintf(stderr, "\n[*] Testing special mmap offsets...\n");
    /* BASE_MEM_MAP_TRACKING_HANDLE = 0x2000 (in r7p0) */
    unsigned long special_pgoffs[] = {
        0x2000, 0x3000, 0x4000,
        0x2000 >> 12, 0x3000 >> 12,
        1, 2, 3, 4,
    };
    for (int i = 0; i < 9; i++) {
        void *p = do_mmap2(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED,
                           fd, special_pgoffs[i]);
        if (p != MAP_FAILED) {
            fprintf(stderr, "[!] special pgoff=0x%lx → %p\n",
                    special_pgoffs[i], p);
            munmap(p, PAGE_SIZE);
        }
    }

    close(fd);
    fprintf(stderr, "\n=== Done ===\n");
    return 0;
}
