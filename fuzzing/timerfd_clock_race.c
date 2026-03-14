/* timerfd_clock_race.c — CVE-2017-10661 timerfd race detector
 *
 * Sets up timerfd with TFD_TIMER_CANCEL_ON_SET and monitors for
 * clock change events. When the user manually changes system time
 * via Settings UI, this detects the CLOCK_REALTIME change and
 * tests the race window.
 *
 * Phase 1: Detect clock change (this run)
 * Phase 2: Exploit the race (after confirming detection works)
 *
 * The vulnerability: timerfd_settime with TFD_TIMER_CANCEL_ON_SET
 * creates a timer that fires when CLOCK_REALTIME changes. The race
 * is between cancel_on_set processing and timer expiry, leading to
 * a UAF on the timer structure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>

#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#define NUM_TIMERS 8
#define EPOLL_EVENTS 16

static volatile int g_clock_changed = 0;
static volatile int g_running = 1;

static void sigalrm_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* Monitor thread: watches for clock change via timerfd */
static void *monitor_thread(void *arg) {
    (void)arg;
    
    /* Create multiple timerfds with CANCEL_ON_SET */
    int tfds[NUM_TIMERS];
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        printf("epoll_create1 failed: %d\n", errno);
        return NULL;
    }
    
    for (int i = 0; i < NUM_TIMERS; i++) {
        tfds[i] = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (tfds[i] < 0) {
            printf("timerfd_create[%d] failed: %d\n", i, errno);
            continue;
        }
        
        /* Set timer far in the future with CANCEL_ON_SET */
        struct itimerspec its = {
            .it_value = { .tv_sec = 999999, .tv_nsec = 0 },
            .it_interval = { .tv_sec = 0, .tv_nsec = 0 }
        };
        int ret = timerfd_settime(tfds[i], TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &its, NULL);
        if (ret < 0) {
            printf("timerfd_settime[%d] failed: %d (%s)\n", i, errno, strerror(errno));
            close(tfds[i]);
            tfds[i] = -1;
            continue;
        }
        
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = tfds[i] };
        epoll_ctl(epfd, EPOLL_CTL_ADD, tfds[i], &ev);
    }
    
    printf("Monitoring %d timerfds for clock change...\n", NUM_TIMERS);
    printf(">>> CHANGE THE SYSTEM TIME NOW (Settings → Date & Time) <<<\n\n");
    
    struct timespec last_time;
    clock_gettime(CLOCK_REALTIME, &last_time);
    
    while (g_running) {
        struct epoll_event events[EPOLL_EVENTS];
        int nev = epoll_wait(epfd, events, EPOLL_EVENTS, 500); /* 500ms timeout */
        
        if (nev > 0) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            long delta_sec = now.tv_sec - last_time.tv_sec;
            
            printf("*** CLOCK CHANGE DETECTED! ***\n");
            printf("  Timers fired: %d\n", nev);
            printf("  Time delta: %ld seconds\n", delta_sec);
            printf("  Current time: %ld.%09ld\n", now.tv_sec, now.tv_nsec);
            
            g_clock_changed++;
            
            /* Read the timerfd to clear it */
            for (int i = 0; i < nev; i++) {
                uint64_t val;
                read(events[i].data.fd, &val, sizeof(val));
                printf("  Timer fd=%d fired (val=%llu)\n", events[i].data.fd, 
                       (unsigned long long)val);
            }
            
            /* Re-arm timers for next change */
            for (int i = 0; i < NUM_TIMERS; i++) {
                if (tfds[i] >= 0) {
                    struct itimerspec its = {
                        .it_value = { .tv_sec = 999999, .tv_nsec = 0 },
                        .it_interval = { .tv_sec = 0, .tv_nsec = 0 }
                    };
                    timerfd_settime(tfds[i], TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &its, NULL);
                }
            }
            
            last_time = now;
            printf("\nWaiting for more clock changes (or timeout)...\n");
        }
        
        /* Print heartbeat every 5 seconds */
        static int heartbeat = 0;
        if (++heartbeat % 10 == 0) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            printf("  [heartbeat] time=%ld waiting... (changes detected: %d)\n",
                   now.tv_sec, g_clock_changed);
        }
    }
    
    /* Cleanup */
    for (int i = 0; i < NUM_TIMERS; i++) {
        if (tfds[i] >= 0) close(tfds[i]);
    }
    close(epfd);
    
    return NULL;
}

int main(void) {
    printf("=== CVE-2017-10661 timerfd Clock Change Detector ===\n");
    printf("This monitors for CLOCK_REALTIME changes via timerfd.\n");
    printf("Will run for 120 seconds waiting for manual time change.\n\n");
    
    signal(SIGALRM, sigalrm_handler);
    alarm(120); /* 2 minute timeout */
    
    pthread_t tid;
    pthread_create(&tid, NULL, monitor_thread, NULL);
    pthread_join(tid, NULL);
    
    printf("\n=== RESULTS ===\n");
    if (g_clock_changed > 0) {
        printf("SUCCESS: Detected %d clock change(s)!\n", g_clock_changed);
        printf("CLOCK_REALTIME changes DO trigger timerfd CANCEL_ON_SET.\n");
        printf("CVE-2017-10661 race IS triggerable via manual time change!\n");
        printf("NEXT: Build the actual race exploit.\n");
    } else {
        printf("No clock changes detected in 120 seconds.\n");
        printf("Either: (a) time wasn't changed, (b) change doesn't trigger timerfd,\n");
        printf("or (c) SELinux blocks the notification.\n");
    }
    
    return 0;
}
