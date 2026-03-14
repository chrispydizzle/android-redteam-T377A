/*
 * k256_spray_finder.c — Exhaustive kmalloc-256 spray search
 *
 * Tests: BPF socket filter, IP multicast, INET socket options,
 * pipes with various sizes, epoll items, ashmem, mali, ptmx,
 * file creates, Unix DGRAM messages, and full slab diffs.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static int get_slab(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512]; int val = -1;
    while (fgets(line, sizeof(line), f)) {
        char n[64]; int a;
        if (sscanf(line, "%63s %d", n, &a) == 2 && !strcmp(n, name)) {
            val = a; break;
        }
    }
    fclose(f);
    return val;
}

/* SO_ATTACH_FILTER: persistent BPF filter on socket */
static void test_bpf(void) {
    printf("\n=== BPF socket filters ===\n");
    int counts[] = {1,4,8,12,16,22,26,30,38,46,54,62};
    for (int t = 0; t < 12; t++) {
        int n = counts[t];
        int est = 16 + n * 8;
        int b256 = get_slab("kmalloc-256");
        int b192 = get_slab("kmalloc-192");
        int b128 = get_slab("kmalloc-128");
        int b512 = get_slab("kmalloc-512");
        int socks[50]; int c = 0;
        for (int i = 0; i < 50; i++) {
            socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (socks[i] < 0) break;
            struct sock_filter insns[64];
            for (int j = 0; j < n-1; j++)
                insns[j] = (struct sock_filter){BPF_LD|BPF_W|BPF_ABS, 0, 0, 0};
            insns[n-1] = (struct sock_filter){BPF_RET|BPF_K, 0, 0, 0xFFFF};
            struct sock_fprog fp = { .len = n, .filter = insns };
            if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) < 0) {
                if (i == 0) printf("  ATTACH_FILTER(%d): %s\n", n, strerror(errno));
                close(socks[i]); break;
            }
            c++;
        }
        printf("  BPF %2d insns (est ~%3d): k128=%+d k192=%+d k256=%+d k512=%+d [%d]\n",
               n, est,
               get_slab("kmalloc-128")-b128, get_slab("kmalloc-192")-b192,
               get_slab("kmalloc-256")-b256, get_slab("kmalloc-512")-b512, c);
        for (int i = 0; i < c; i++) close(socks[i]);
    }
}

/* INET socket creation overhead */
static void test_inet(void) {
    printf("\n=== INET socket allocs ===\n");
    int b = get_slab("kmalloc-256");
    int socks[50];
    for (int i = 0; i < 50; i++) socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
    int a = get_slab("kmalloc-256");
    printf("  50 UDP: k256=%+d\n", a-b);
    for (int i = 0; i < 50; i++) close(socks[i]);

    b = get_slab("kmalloc-256");
    for (int i = 0; i < 50; i++) socks[i] = socket(AF_INET, SOCK_STREAM, 0);
    a = get_slab("kmalloc-256");
    printf("  50 TCP: k256=%+d\n", a-b);
    for (int i = 0; i < 50; i++) close(socks[i]);

    b = get_slab("kmalloc-256");
    for (int i = 0; i < 50; i++) socks[i] = socket(AF_INET6, SOCK_DGRAM, 0);
    printf("  50 UDP6: k256=%+d (first errno=%d)\n",
           get_slab("kmalloc-256")-b, socks[0]<0?errno:0);
    for (int i = 0; i < 50; i++) if(socks[i]>=0) close(socks[i]);

    b = get_slab("kmalloc-256");
    for (int i = 0; i < 50; i++) socks[i] = socket(AF_NETLINK, SOCK_RAW, 15);
    printf("  50 NETLINK: k256=%+d (first errno=%d)\n",
           get_slab("kmalloc-256")-b, socks[0]<0?errno:0);
    for (int i = 0; i < 50; i++) if(socks[i]>=0) close(socks[i]);
}

/* Pipes with different buffer sizes */
static void test_pipes(void) {
    printf("\n=== Pipe buffer sizes ===\n");
    int sizes[] = {4096, 2*4096, 4*4096, 8*4096, 16*4096, 32*4096};
    for (int t = 0; t < 6; t++) {
        int b = get_slab("kmalloc-256");
        int p[50][2];
        for (int i = 0; i < 50; i++) {
            pipe(p[i]);
            fcntl(p[i][0], 1031, sizes[t]); /* F_SETPIPE_SZ */
        }
        printf("  F_SETPIPE_SZ(%5d): k256=%+d\n", sizes[t], get_slab("kmalloc-256")-b);
        for (int i = 0; i < 50; i++) { close(p[i][0]); close(p[i][1]); }
    }
}

/* ashmem, mali, ptmx, /dev nodes */
static void test_devnodes(void) {
    printf("\n=== /dev node allocs ===\n");
    int b, fds[50];

    b = get_slab("kmalloc-256");
    for (int i = 0; i < 50; i++) fds[i] = open("/dev/ashmem", O_RDWR);
    printf("  50 ashmem: k256=%+d\n", get_slab("kmalloc-256")-b);
    for (int i = 0; i < 50; i++) if(fds[i]>=0) close(fds[i]);

    b = get_slab("kmalloc-256");
    for (int i = 0; i < 20; i++) fds[i] = open("/dev/mali0", O_RDWR);
    printf("  20 mali0: k256=%+d (e=%d)\n", get_slab("kmalloc-256")-b, fds[0]<0?errno:0);
    for (int i = 0; i < 20; i++) if(fds[i]>=0) close(fds[i]);

    b = get_slab("kmalloc-256");
    for (int i = 0; i < 50; i++) fds[i] = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    printf("  50 ptmx: k256=%+d\n", get_slab("kmalloc-256")-b);
    for (int i = 0; i < 50; i++) if(fds[i]>=0) close(fds[i]);

    b = get_slab("kmalloc-256");
    for (int i = 0; i < 50; i++) fds[i] = open("/dev/ion", O_RDWR);
    printf("  50 ion: k256=%+d\n", get_slab("kmalloc-256")-b);
    for (int i = 0; i < 50; i++) if(fds[i]>=0) close(fds[i]);
}

/* Epoll items */
static void test_epoll(void) {
    printf("\n=== epoll items ===\n");
    int b = get_slab("kmalloc-256");
    int epfd = epoll_create1(0);
    int fds[50];
    for (int i = 0; i < 50; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i], &ev);
    }
    printf("  50 epoll items: k256=%+d\n", get_slab("kmalloc-256")-b);
    for (int i = 0; i < 50; i++) close(fds[i]);
    close(epfd);
}

/* Full slab diff for BPF(26) */
static void test_full_diff(void) {
    printf("\n=== Full slab diff: 50 BPF(26 insns) sockets ===\n");
    #define MC 200
    struct { char n[64]; int a; } sb[MC], sa[MC];
    FILE *f = fopen("/proc/slabinfo", "r");
    char l[512]; int nb = 0;
    fgets(l,sizeof(l),f); fgets(l,sizeof(l),f);
    while (fgets(l,sizeof(l),f) && nb < MC) { sscanf(l,"%63s %d",sb[nb].n,&sb[nb].a); nb++; }
    fclose(f);

    int socks[50];
    for (int i = 0; i < 50; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (socks[i] < 0) break;
        struct sock_filter insns[26];
        for (int j = 0; j < 25; j++)
            insns[j] = (struct sock_filter){BPF_LD|BPF_W|BPF_ABS, 0, 0, 0};
        insns[25] = (struct sock_filter){BPF_RET|BPF_K, 0, 0, 0xFFFF};
        struct sock_fprog fp = { .len = 26, .filter = insns };
        setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp));
    }

    f = fopen("/proc/slabinfo", "r");
    int na = 0;
    fgets(l,sizeof(l),f); fgets(l,sizeof(l),f);
    while (fgets(l,sizeof(l),f) && na < MC) { sscanf(l,"%63s %d",sa[na].n,&sa[na].a); na++; }
    fclose(f);

    for (int i = 0; i < na; i++)
        for (int j = 0; j < nb; j++)
            if (!strcmp(sa[i].n, sb[j].n) && abs(sa[i].a - sb[j].a) > 3)
                printf("  %-24s %+d\n", sa[i].n, sa[i].a - sb[j].a);

    for (int i = 0; i < 50; i++) if(socks[i]>=0) close(socks[i]);
}

int main(void) {
    printf("=== kmalloc-256 Persistent Spray Finder ===\n");
    printf("PID=%d UID=%d\n", getpid(), getuid());
    test_bpf();
    test_inet();
    test_pipes();
    test_devnodes();
    test_epoll();
    test_full_diff();
    printf("\n=== Done ===\n");
    return 0;
}
