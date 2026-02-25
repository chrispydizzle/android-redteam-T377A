/*
 * k64_object_audit.c — Comprehensive kmalloc-64 object audit for ION UAF exploitation
 *
 * Target: Samsung SM-T377A, Android 6.0.1, kernel 3.10.9, ARM32
 *
 * Tests 20 primitives for kmalloc-64 slab impact, then performs deep
 * pipe_buffer analysis with function pointer trigger verification.
 *
 * Usage: adb shell /data/local/tmp/k64_object_audit
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>

/* ION definitions */
typedef int ion_user_handle_t;
struct ion_allocation_data {
    size_t len; size_t align;
    unsigned int heap_id_mask; unsigned int flags;
    ion_user_handle_t handle;
};
struct ion_handle_data { ion_user_handle_t handle; };
#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)

/* fanotify/inotify1 syscall numbers for ARM */
#ifndef __NR_fanotify_init
#define __NR_fanotify_init  367
#endif
#ifndef __NR_inotify_init1
#define __NR_inotify_init1  360
#endif

#define N 50
#define PAGE_SIZE 4096

/* ------------------------------------------------------------------ */
/* Slab reading helpers                                                */
/* ------------------------------------------------------------------ */

struct slab_snapshot {
    int k32;
    int k64;
    int k128;
    int k192;
    int k256;
};

static int parse_slab_active(const char *line) {
    char name[64];
    int active;
    if (sscanf(line, "%63s %d", name, &active) == 2)
        return active;
    return -1;
}

static void read_slab(struct slab_snapshot *s) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) { memset(s, 0, sizeof(*s)); return; }
    s->k32 = s->k64 = s->k128 = s->k192 = s->k256 = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "kmalloc-32 ", 11) == 0 || strncmp(line, "kmalloc-32\t", 11) == 0)
            s->k32 = parse_slab_active(line);
        else if (strncmp(line, "kmalloc-64 ", 11) == 0 || strncmp(line, "kmalloc-64\t", 11) == 0)
            s->k64 = parse_slab_active(line);
        else if (strncmp(line, "kmalloc-128 ", 12) == 0 || strncmp(line, "kmalloc-128\t", 12) == 0)
            s->k128 = parse_slab_active(line);
        else if (strncmp(line, "kmalloc-192 ", 12) == 0 || strncmp(line, "kmalloc-192\t", 12) == 0)
            s->k192 = parse_slab_active(line);
        else if (strncmp(line, "kmalloc-256 ", 12) == 0 || strncmp(line, "kmalloc-256\t", 12) == 0)
            s->k256 = parse_slab_active(line);
    }
    fclose(f);
}

static void print_delta(const char *label, struct slab_snapshot *before,
                        struct slab_snapshot *after) {
    int d64 = after->k64 - before->k64;
    int d32 = after->k32 - before->k32;
    int d128 = after->k128 - before->k128;
    printf("  %-38s k64=%+4d  k32=%+4d  k128=%+4d",
           label, d64, d32, d128);
    if (d64 >= N/2)
        printf("  *** HIT k64 ***");
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* PART 1: Slab differential analysis — 20 primitives                  */
/* ------------------------------------------------------------------ */

static void test_proc_stat(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/proc/self/stat", O_RDONLY);
    read_slab(&a);
    print_delta("[1] /proc/self/stat (seq_ops)", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_pipes(void) {
    struct slab_snapshot b, a, c;
    int pp[N][2];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        pipe(pp[i]);
    read_slab(&a);
    print_delta("[2] pipe() (pipe_buffer)", &b, &a);
    for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_ion(void) {
    struct slab_snapshot b, a, c;
    int ion_fd = open("/dev/ion", O_RDONLY);
    if (ion_fd < 0) {
        printf("  [3] /dev/ion: SKIP (cannot open: %s)\n", strerror(errno));
        return;
    }
    ion_user_handle_t handles[N];
    int cnt = 0;
    read_slab(&b);
    for (int i = 0; i < N; i++) {
        struct ion_allocation_data ad = {
            .len = 4096, .align = 4096,
            .heap_id_mask = 1, .flags = 0
        };
        if (ioctl(ion_fd, ION_IOC_ALLOC, &ad) == 0)
            handles[cnt++] = ad.handle;
    }
    read_slab(&a);
    char lbl[64];
    snprintf(lbl, sizeof(lbl), "[3] ION alloc (%d handles)", cnt);
    print_delta(lbl, &b, &a);
    for (int i = 0; i < cnt; i++) {
        struct ion_handle_data hd = { .handle = handles[i] };
        ioctl(ion_fd, ION_IOC_FREE, &hd);
    }
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on ION_FREE)\n", "  -> after free", c.k64 - a.k64);
    close(ion_fd);
}

static void test_epoll(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = epoll_create(1);
    read_slab(&a);
    print_delta("[4] epoll_create", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_eventfd(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = eventfd(0, 0);
    read_slab(&a);
    print_delta("[5] eventfd", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_signalfd(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = signalfd(-1, &mask, 0);
    read_slab(&a);
    print_delta("[6] signalfd", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_timerfd(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = timerfd_create(CLOCK_MONOTONIC, 0);
    read_slab(&a);
    print_delta("[7] timerfd_create", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_inotify(void) {
    struct slab_snapshot b, a, c;
    int ifd = inotify_init();
    if (ifd < 0) {
        printf("  [8] inotify: SKIP (%s)\n", strerror(errno));
        return;
    }
    int wds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        wds[i] = inotify_add_watch(ifd, "/data/local/tmp", IN_ALL_EVENTS);
    read_slab(&a);
    print_delta("[8] inotify watches", &b, &a);
    for (int i = 0; i < N; i++)
        if (wds[i] >= 0) inotify_rm_watch(ifd, wds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on rm_watch)\n", "  -> after rm", c.k64 - a.k64);
    close(ifd);
}

static void test_unix_socket(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = socket(AF_UNIX, SOCK_STREAM, 0);
    read_slab(&a);
    print_delta("[9] AF_UNIX SOCK_STREAM", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_ashmem(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/dev/ashmem", O_RDWR);
    read_slab(&a);
    print_delta("[10] /dev/ashmem", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_dup(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = dup(0);
    read_slab(&a);
    print_delta("[11] dup(0) (file struct?)", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_proc_maps(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/proc/self/maps", O_RDONLY);
    read_slab(&a);
    print_delta("[12] /proc/self/maps (seq_ops)", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_proc_status(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/proc/self/status", O_RDONLY);
    read_slab(&a);
    print_delta("[13] /proc/self/status (seq_ops)", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_proc_cmdline(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/proc/self/cmdline", O_RDONLY);
    read_slab(&a);
    print_delta("[14] /proc/self/cmdline", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_dev_null(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/dev/null", O_RDWR);
    read_slab(&a);
    print_delta("[15] /dev/null", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_dev_zero(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/dev/zero", O_RDONLY);
    read_slab(&a);
    print_delta("[16] /dev/zero", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_dev_urandom(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = open("/dev/urandom", O_RDONLY);
    read_slab(&a);
    print_delta("[17] /dev/urandom", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_udp_socket(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
    read_slab(&a);
    print_delta("[18] AF_INET SOCK_DGRAM (UDP)", &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_raw_socket(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    read_slab(&a);
    int ok = 0;
    for (int i = 0; i < N; i++) if (fds[i] >= 0) ok++;
    char lbl[64];
    snprintf(lbl, sizeof(lbl), "[19] SOCK_RAW ICMP (%d ok)", ok);
    print_delta(lbl, &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

static void test_inotify_init1(void) {
    struct slab_snapshot b, a, c;
    int fds[N];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        fds[i] = syscall(__NR_inotify_init1, 0);
    read_slab(&a);
    int ok = 0;
    for (int i = 0; i < N; i++) if (fds[i] >= 0) ok++;
    char lbl[64];
    snprintf(lbl, sizeof(lbl), "[20] inotify_init1 (%d ok)", ok);
    print_delta(lbl, &b, &a);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

/* ------------------------------------------------------------------ */
/* Bonus: socketpair (known best spray from skill reference)           */
/* ------------------------------------------------------------------ */

static void test_socketpair(void) {
    struct slab_snapshot b, a, c;
    int sv[N][2];
    read_slab(&b);
    for (int i = 0; i < N; i++)
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]);
    read_slab(&a);
    print_delta("[+] socketpair AF_UNIX (spray ref)", &b, &a);
    for (int i = 0; i < N; i++) { close(sv[i][0]); close(sv[i][1]); }
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

/* ------------------------------------------------------------------ */
/* Bonus: epoll_ctl ADD (epitems)                                      */
/* ------------------------------------------------------------------ */

static void test_epoll_ctl(void) {
    struct slab_snapshot b, a, c;
    int ep = epoll_create(1);
    if (ep < 0) {
        printf("  [+] epoll_ctl: SKIP\n");
        return;
    }
    int pp[N][2];
    read_slab(&b);
    for (int i = 0; i < N; i++) {
        pipe(pp[i]);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = pp[i][0] };
        epoll_ctl(ep, EPOLL_CTL_ADD, pp[i][0], &ev);
    }
    read_slab(&a);
    print_delta("[+] epoll_ctl ADD (epitem)", &b, &a);
    for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    close(ep);
    read_slab(&c);
    printf("  %-38s k64=%+4d  (freed on close)\n", "  -> after close", c.k64 - a.k64);
}

/* ------------------------------------------------------------------ */
/* PART 3: pipe_buffer deep analysis                                   */
/* ------------------------------------------------------------------ */

static void deep_pipe_analysis(void) {
    printf("\n");
    printf("============================================================\n");
    printf("  PART 3: pipe_buffer Deep Analysis\n");
    printf("============================================================\n\n");

    struct slab_snapshot b, a;

    /* 3a: Default pipe — what slab does the buffer array land in? */
    printf("--- 3a: Default pipe (no F_SETPIPE_SZ) ---\n");
    {
        int pp[N][2];
        read_slab(&b);
        for (int i = 0; i < N; i++)
            pipe(pp[i]);
        read_slab(&a);
        printf("  k32=%+d  k64=%+d  k128=%+d  k192=%+d  k256=%+d\n",
               a.k32-b.k32, a.k64-b.k64, a.k128-b.k128, a.k192-b.k192, a.k256-b.k256);
        /* Check actual pipe size */
        int sz = fcntl(pp[0][0], F_GETPIPE_SZ);
        printf("  Default pipe size: %d bytes (%d pages, %d buffers)\n",
               sz, sz / PAGE_SIZE, sz / PAGE_SIZE);
        for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    }

    /* 3b: Pipe resized to 1 page (1 buffer → sizeof(pipe_buffer) → kmalloc-32?) */
    printf("\n--- 3b: Pipe with F_SETPIPE_SZ(PAGE_SIZE) → 1 buffer ---\n");
    {
        int pp[N][2];
        read_slab(&b);
        for (int i = 0; i < N; i++) {
            pipe(pp[i]);
            fcntl(pp[i][0], F_SETPIPE_SZ, PAGE_SIZE);
        }
        read_slab(&a);
        printf("  k32=%+d  k64=%+d  k128=%+d\n",
               a.k32-b.k32, a.k64-b.k64, a.k128-b.k128);
        int sz = fcntl(pp[0][0], F_GETPIPE_SZ);
        printf("  Actual pipe size: %d bytes (%d pages, %d buffers)\n",
               sz, sz / PAGE_SIZE, sz / PAGE_SIZE);
        for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    }

    /* 3c: Pipe resized to 2 pages (2 buffers → 2*sizeof(pipe_buffer) → kmalloc-64?) */
    printf("\n--- 3c: Pipe with F_SETPIPE_SZ(2*PAGE) → 2 buffers ---\n");
    {
        int pp[N][2];
        read_slab(&b);
        for (int i = 0; i < N; i++) {
            pipe(pp[i]);
            fcntl(pp[i][0], F_SETPIPE_SZ, PAGE_SIZE * 2);
        }
        read_slab(&a);
        printf("  k32=%+d  k64=%+d  k128=%+d\n",
               a.k32-b.k32, a.k64-b.k64, a.k128-b.k128);
        int sz = fcntl(pp[0][0], F_GETPIPE_SZ);
        printf("  Actual pipe size: %d bytes (%d pages, %d buffers)\n",
               sz, sz / PAGE_SIZE, sz / PAGE_SIZE);
        for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    }

    /* 3d: Write 1 byte to pipe — does this populate pipe_buffer? */
    printf("\n--- 3d: pipe + write 1 byte (populates pipe_buffer.page/ops) ---\n");
    {
        int pp[N][2];
        /* Create pipes first, then measure write impact */
        for (int i = 0; i < N; i++) {
            pipe(pp[i]);
            fcntl(pp[i][0], F_SETPIPE_SZ, PAGE_SIZE);
        }
        read_slab(&b);
        char byte = 'A';
        for (int i = 0; i < N; i++)
            write(pp[i][1], &byte, 1);
        read_slab(&a);
        printf("  After write: k32=%+d  k64=%+d  k128=%+d\n",
               a.k32-b.k32, a.k64-b.k64, a.k128-b.k128);
        printf("  (write populates pipe_buf->page and pipe_buf->ops inline,\n");
        printf("   no additional kmalloc expected — ops is a static pointer)\n");
        for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    }

    /* 3e: Read from pipe — does this call ops->confirm? */
    printf("\n--- 3e: pipe write+read (triggers ops->confirm) ---\n");
    {
        int pp[N][2];
        for (int i = 0; i < N; i++) {
            pipe(pp[i]);
            fcntl(pp[i][0], F_SETPIPE_SZ, PAGE_SIZE);
        }
        char byte = 'A';
        for (int i = 0; i < N; i++)
            write(pp[i][1], &byte, 1);
        read_slab(&b);
        char rbuf;
        for (int i = 0; i < N; i++)
            read(pp[i][0], &rbuf, 1);
        read_slab(&a);
        printf("  After read:  k32=%+d  k64=%+d  k128=%+d\n",
               a.k32-b.k32, a.k64-b.k64, a.k128-b.k128);
        printf("  (pipe_read calls buf->ops->confirm then buf->ops->release\n");
        printf("   when buffer is fully consumed)\n");
        for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    }

    /* 3f: Close write end, then read — triggers ops->release cleanup */
    printf("\n--- 3f: Close analysis (ops->release trigger) ---\n");
    {
        int pp[N][2];
        for (int i = 0; i < N; i++) {
            pipe(pp[i]);
            fcntl(pp[i][0], F_SETPIPE_SZ, PAGE_SIZE);
        }
        char byte = 'X';
        for (int i = 0; i < N; i++)
            write(pp[i][1], &byte, 1);
        read_slab(&b);
        /* Close both ends — triggers free_pipe_info → ops->release */
        for (int i = 0; i < N; i++) {
            close(pp[i][1]); /* close write end */
            close(pp[i][0]); /* close read end — frees pipe_buffer array */
        }
        read_slab(&a);
        printf("  After close: k32=%+d  k64=%+d  k128=%+d\n",
               a.k32-b.k32, a.k64-b.k64, a.k128-b.k128);
        printf("  (free_pipe_info calls ops->release for each buf with page,\n");
        printf("   then kfrees the pipe_buffer array)\n");
    }

    /* 3g: Verify pipe_buffer struct size */
    printf("\n--- 3g: pipe_buffer struct size analysis (kernel 3.10 ARM32) ---\n");
    printf("  struct pipe_buffer {\n");
    printf("    struct page *page;       // 4 bytes (ARM32 pointer)\n");
    printf("    unsigned int offset;     // 4 bytes\n");
    printf("    unsigned int len;        // 4 bytes\n");
    printf("    const struct pipe_buf_operations *ops; // 4 bytes (FUNCTION TABLE)\n");
    printf("    unsigned int flags;      // 4 bytes\n");
    printf("    unsigned long private;   // 4 bytes\n");
    printf("  }; // = 24 bytes on ARM32\n");
    printf("\n");
    printf("  pipe_buf_operations contains:\n");
    printf("    int (*can_merge)(struct pipe_inode_info *, struct pipe_buffer *);\n");
    printf("    void *(*map)(struct pipe_inode_info *, struct pipe_buffer *, int);\n");
    printf("    void (*unmap)(struct pipe_inode_info *, struct pipe_buffer *, void *);\n");
    printf("    int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);\n");
    printf("    void (*release)(struct pipe_inode_info *, struct pipe_buffer *);\n");
    printf("    int (*steal)(struct pipe_inode_info *, struct pipe_buffer *);\n");
    printf("    void (*get)(struct pipe_inode_info *, struct pipe_buffer *);\n");
    printf("\n");
    printf("  For 1 buffer:  1 * 24 = 24 bytes → kmalloc-32\n");
    printf("  For 2 buffers: 2 * 24 = 48 bytes → kmalloc-64  ← TARGET\n");
    printf("  For 4 buffers: 4 * 24 = 96 bytes → kmalloc-128\n");
    printf("  For default (16 bufs): 16 * 24 = 384 → kmalloc-512\n");

    /* 3h: Verify with all nearby sizes */
    printf("\n--- 3h: Pipe size sweep (1-8 pages) ---\n");
    int sizes[] = {1, 2, 3, 4, 5, 6, 7, 8};
    for (int s = 0; s < 8; s++) {
        int pp[N][2];
        read_slab(&b);
        for (int i = 0; i < N; i++) {
            pipe(pp[i]);
            fcntl(pp[i][0], F_SETPIPE_SZ, PAGE_SIZE * sizes[s]);
        }
        read_slab(&a);
        int actual = fcntl(pp[0][0], F_GETPIPE_SZ);
        printf("  %d pages (actual=%d, bufs=%d): k32=%+d k64=%+d k128=%+d k192=%+d k256=%+d\n",
               sizes[s], actual/PAGE_SIZE, actual/PAGE_SIZE,
               a.k32-b.k32, a.k64-b.k64, a.k128-b.k128, a.k192-b.k192, a.k256-b.k256);
        for (int i = 0; i < N; i++) { close(pp[i][0]); close(pp[i][1]); }
    }
}

/* ------------------------------------------------------------------ */
/* PART 2: Function pointer analysis summary                           */
/* ------------------------------------------------------------------ */

static void function_pointer_analysis(void) {
    printf("\n");
    printf("============================================================\n");
    printf("  PART 2: Function Pointer Analysis (kernel 3.10 ARM32)\n");
    printf("============================================================\n\n");

    printf("Object              | fptrs in struct?  | Triggered by         | Exploit quality\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("seq_operations      | 4 (start/stop/    | read() on /proc fd   | EXCELLENT\n");
    printf("                    |  next/show)       | (single_open path)   | - read() calls\n");
    printf("                    |                   |                      |   seq->op->start\n");
    printf("                    |                   |                      |   then ->show\n");
    printf("                    |                   |                      |   then ->next\n");
    printf("                    |                   |                      |   then ->stop\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("pipe_buffer (x2)    | 1 (ops ptr to     | read() calls         | EXCELLENT\n");
    printf("                    |  ops table with   |   ops->confirm       | - ops->confirm\n");
    printf("                    |  7 fptrs)         | close() calls        |   on pipe_read\n");
    printf("                    |                   |   ops->release       | - ops->release\n");
    printf("                    |                   | splice calls         |   on close/consume\n");
    printf("                    |                   |   ops->steal         | - controllable via\n");
    printf("                    |                   |                      |   UAF replacement\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("ion_handle          | 0 (no fptrs)      | N/A                  | DATA ONLY\n");
    printf("                    | has rb_node,      | (useful as UAF       | - target of our\n");
    printf("                    | ion_buffer*,      |  victim, not as      |   UAF, not spray\n");
    printf("                    | refcount          |  replacement)        |\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("epoll: eventpoll    | 0 in k64 part     | poll() machinery     | LOW\n");
    printf("                    | (if any k64 alloc |                      | - internal struct\n");
    printf("                    |  it's metadata)   |                      | - no direct fptrs\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("epitem              | 0 direct, but has | epoll_wait calls     | MEDIUM\n");
    printf("(epoll_ctl ADD)     | ffd.file ptr      |   ep_poll_callback   | - if in k64, the\n");
    printf("                    |                   |                      |   file ptr is useful\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("socketpair allocs   | indirect via      | read/write/poll      | HIGH (spray)\n");
    printf("(unix_sock, etc)    | sock->ops table   | all trigger ops      | - best k64 spray\n");
    printf("                    |                   |                      | - 1169 objs/200ops\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("inotify_watch       | 0 (event-based)   | filesystem events    | LOW\n");
    printf("                    |                   |                      | - no fptrs in k64\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("signalfd_ctx        | 0                 | read() blocks        | NONE\n");
    printf("                    |                   |                      | - no fptrs\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("timerfd_ctx         | 0 (callback is    | timer expiry         | LOW\n");
    printf("                    |  in hrtimer, not  | (kernel-internal)    | - callback not in\n");
    printf("                    |  in ctx itself)   |                      |   the k64 object\n");
    printf("--------------------|-------------------|----------------------|----------------\n");
    printf("eventfd_ctx         | 0                 | read/write/poll      | NONE\n");
    printf("                    |                   |                      | - no fptrs\n");
    printf("--------------------|-------------------|----------------------|----------------\n");

    printf("\n=== RANKING: Best k64 objects for ION UAF replacement ===\n\n");
    printf("1. seq_operations (via /proc/self/stat open)\n");
    printf("   - 4 function pointers at offsets 0, 4, 8, 12\n");
    printf("   - Triggered deterministically by read() on the fd\n");
    printf("   - 16 bytes on ARM32, may pad to kmalloc-32 or kmalloc-64\n");
    printf("   - MUST VERIFY actual slab from test results above\n\n");

    printf("2. pipe_buffer[2] (via pipe + F_SETPIPE_SZ(8192))\n");
    printf("   - ops pointer at offset 12 in each 24-byte buffer\n");
    printf("   - ops->confirm called on read(), ops->release on close()\n");
    printf("   - 2 * 24 = 48 bytes → fits kmalloc-64\n");
    printf("   - Write to pipe fills page ptr and ops ptr\n");
    printf("   - MOST CONTROLLABLE: page ptr + ops ptr in same object\n\n");

    printf("3. socketpair internal allocs\n");
    printf("   - Highest allocation rate (+1169/200 ops per reference)\n");
    printf("   - Best for SPRAYING (filling freed slot)\n");
    printf("   - Function pointers called via sock->ops on read/write/poll\n");
    printf("   - Less direct control over content than pipe_buffer\n\n");

    printf("4. epitem (via epoll_ctl ADD)\n");
    printf("   - Contains file pointer (ffd.file)\n");
    printf("   - If overwritten, epoll_wait dereferences corrupted file\n");
    printf("   - Useful for info leak or controlled crash\n\n");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("============================================================\n");
    printf("  kmalloc-64 Object Audit for ION UAF Exploitation\n");
    printf("  Target: SM-T377A, kernel 3.10.9, ARM32\n");
    printf("  Allocations per test: %d\n", N);
    printf("============================================================\n\n");

    /* Verify slabinfo access */
    struct slab_snapshot test;
    read_slab(&test);
    if (test.k64 <= 0) {
        printf("[!] Cannot read /proc/slabinfo (k64=%d)\n", test.k64);
        printf("[!] Need root or permissive slabinfo access\n");
        return 1;
    }
    printf("[*] Baseline kmalloc-64 active_objs: %d\n\n", test.k64);

    printf("============================================================\n");
    printf("  PART 1: Slab Differential Analysis (20 primitives)\n");
    printf("============================================================\n");
    printf("  Format: k64=delta  k32=delta  k128=delta\n\n");

    test_proc_stat();       /* 1 */
    test_pipes();           /* 2 */
    test_ion();             /* 3 */
    test_epoll();           /* 4 */
    test_eventfd();         /* 5 */
    test_signalfd();        /* 6 */
    test_timerfd();         /* 7 */
    test_inotify();         /* 8 */
    test_unix_socket();     /* 9 */
    test_ashmem();          /* 10 */
    test_dup();             /* 11 */
    test_proc_maps();       /* 12 */
    test_proc_status();     /* 13 */
    test_proc_cmdline();    /* 14 */
    test_dev_null();        /* 15 */
    test_dev_zero();        /* 16 */
    test_dev_urandom();     /* 17 */
    test_udp_socket();      /* 18 */
    test_raw_socket();      /* 19 */
    test_inotify_init1();   /* 20 */

    printf("\n--- Bonus sprays ---\n");
    test_socketpair();
    test_epoll_ctl();

    /* Part 2 */
    function_pointer_analysis();

    /* Part 3 */
    deep_pipe_analysis();

    printf("\n============================================================\n");
    printf("  AUDIT COMPLETE\n");
    printf("============================================================\n");
    return 0;
}
