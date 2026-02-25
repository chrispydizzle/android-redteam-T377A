/*
 * priv_probe.c - Privilege escalation capability probe
 * Tests which syscalls/APIs work from current context
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sched.h>
#include <sys/prctl.h>

#ifndef __NR_add_key
#define __NR_add_key 309
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 311
#endif
#ifndef __NR_bpf
#define __NR_bpf 386
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

int main(void) {
    int s, pm;
    long kr, br, pfd;

    printf("=== Priv Escalation Capability Probe ===\n");
    printf("UID=%d EUID=%d GID=%d EGID=%d\n\n",
           getuid(), geteuid(), getgid(), getegid());

    /* 1. AF_PACKET */
    printf("--- AF_PACKET ---\n");
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s >= 0) {
        int val = 2;
        printf("  [!!!] SOCK_RAW: OK fd=%d\n", s);
        if (setsockopt(s, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) == 0)
            printf("  [!!!] TPACKET_V3: OK\n");
        else
            printf("  TPACKET_V3: %s\n", strerror(errno));
        close(s);
    } else {
        printf("  SOCK_RAW: %s (%d)\n", strerror(errno), errno);
    }
    s = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (s >= 0) { printf("  SOCK_DGRAM: OK fd=%d\n", s); close(s); }
    else printf("  SOCK_DGRAM: %s\n", strerror(errno));

    /* 2. Namespaces */
    printf("\n--- Namespaces ---\n");
    if (unshare(CLONE_NEWUSER) == 0) printf("  [!!!] NEWUSER: OK\n");
    else printf("  NEWUSER: %s\n", strerror(errno));
    if (unshare(CLONE_NEWNET) == 0) printf("  [!!!] NEWNET: OK\n");
    else printf("  NEWNET: %s\n", strerror(errno));

    /* 3. Keyring */
    printf("\n--- Keyring ---\n");
    kr = syscall(__NR_add_key, "user", "testk", "data", 4, -2);
    if (kr >= 0) {
        printf("  [!!!] add_key: OK serial=%ld\n", kr);
        syscall(__NR_keyctl, 3, kr);
    } else {
        printf("  add_key: %s (%d)\n", strerror(errno), errno);
    }

    /* 4. BPF */
    printf("\n--- BPF ---\n");
    {
        struct { unsigned int a,b,c,d; } ba = {1,4,4,64};
        br = syscall(__NR_bpf, 0, &ba, sizeof(ba));
        if (br >= 0) { printf("  [!!!] bpf: OK fd=%ld\n", br); close((int)br); }
        else printf("  bpf: %s (%d)\n", strerror(errno), errno);
    }

    /* 5. perf_event_open */
    printf("\n--- perf_event ---\n");
    {
        struct { unsigned int type, size; unsigned long long config;
                 unsigned long long a,b,c,d; } pe;
        memset(&pe, 0, sizeof(pe));
        pe.size = sizeof(pe);
        pfd = syscall(364, &pe, 0, -1, -1, 0);
        if (pfd >= 0) { printf("  [!!!] perf: OK fd=%ld\n", pfd); close((int)pfd); }
        else printf("  perf: %s (%d)\n", strerror(errno), errno);
    }

    /* 6. pagemap */
    printf("\n--- pagemap ---\n");
    pm = open("/proc/self/pagemap", O_RDONLY);
    if (pm >= 0) {
        unsigned long vaddr = (unsigned long)&pm;
        unsigned long long entry = 0;
        printf("  [!!!] pagemap: READABLE\n");
        if (pread(pm, &entry, 8, (vaddr/4096)*8) == 8) {
            if (entry & (1ULL << 63)) {
                unsigned long long pfn = entry & 0x7FFFFFULL;
                printf("  PFN=0x%llx phys=0x%llx kern=0x%llx\n",
                       pfn, pfn*4096, pfn*4096 + 0xA0000000ULL);
            } else printf("  not present: 0x%llx\n", entry);
        } else printf("  pread: %s\n", strerror(errno));
        close(pm);
    } else {
        printf("  pagemap: %s (%d)\n", strerror(errno), errno);
    }

    /* 7. mprotect RWX */
    printf("\n--- mprotect ---\n");
    {
        void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            if (mprotect(p, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) == 0)
                printf("  [!!!] RWX: OK\n");
            else printf("  RWX: %s\n", strerror(errno));
            munmap(p, 4096);
        }
    }

    /* 8. prctl */
    printf("\n--- prctl ---\n");
    printf("  dumpable=%d securebits=%d\n",
           prctl(PR_GET_DUMPABLE), prctl(PR_GET_SECUREBITS));

    /* 9. Device nodes */
    printf("\n--- Devices ---\n");
    {
        const char *d[] = {"/dev/ion","/dev/binder","/dev/ashmem",
                           "/dev/mali0","/dev/ptmx","/dev/kmem",
                           "/dev/mem","/dev/kmsg","/dev/fuse",NULL};
        int i;
        for (i = 0; d[i]; i++) {
            int fd = open(d[i], O_RDWR);
            if (fd >= 0) { printf("  %s: OK(%d)\n", d[i], fd); close(fd); }
            else printf("  %s: %s\n", d[i], strerror(errno));
        }
    }

    /* 10. Kernel tunables */
    printf("\n--- Tunables ---\n");
    {
        const char *t[] = {
            "/proc/sys/kernel/perf_event_paranoid",
            "/proc/sys/kernel/kptr_restrict",
            "/proc/sys/kernel/dmesg_restrict",
            "/proc/sys/vm/mmap_min_addr",
            "/proc/sys/fs/suid_dumpable",
            NULL};
        int i;
        for (i = 0; t[i]; i++) {
            char buf[64] = {0};
            int fd = open(t[i], O_RDONLY);
            if (fd >= 0) {
                int n = read(fd, buf, 63);
                if (n > 0 && buf[n-1] == '\n') buf[n-1] = 0;
                close(fd);
                fd = open(t[i], O_WRONLY);
                printf("  %s=%s %s\n", t[i], buf, fd>=0?"[W]":"[R]");
                if (fd >= 0) close(fd);
            } else printf("  %s: %s\n", t[i], strerror(errno));
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
