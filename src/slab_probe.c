/*
 * slab_probe.c — Determine which operations allocate from kmalloc-64
 * Reads /proc/slabinfo before and after each operation to identify
 * which userspace actions create kmalloc-64 objects.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/inotify.h>
#include <sys/xattr.h>
#include <signal.h>

static int get_kmalloc64_active(void) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    int active = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "kmalloc-64 ", 11) == 0 ||
            strncmp(line, "kmalloc-64  ", 12) == 0) {
            /* Parse: name <active_objs> <num_objs> ... */
            char name[64];
            int act, num;
            if (sscanf(line, "%s %d %d", name, &act, &num) >= 2)
                active = act;
            break;
        }
    }
    fclose(f);
    return active;
}

static int get_slab_active(const char *slab_name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    int active = -1;
    int name_len = strlen(slab_name);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, slab_name, name_len) == 0 &&
            (line[name_len] == ' ' || line[name_len] == '\t')) {
            char name[64];
            int act, num;
            if (sscanf(line, "%s %d %d", name, &act, &num) >= 2)
                active = act;
            break;
        }
    }
    fclose(f);
    return active;
}

#define TEST_COUNT 200

int main(void) {
    printf("=== Slab Allocation Probe ===\n\n");
    
    int before, after;
    int fds[TEST_COUNT];
    
    /* Warm up slabinfo */
    get_kmalloc64_active();
    usleep(50000);
    
    /* Test 1: open /proc/self/stat (seq_file) */
    printf("--- Test: open /proc/self/stat x%d ---\n", TEST_COUNT);
    before = get_kmalloc64_active();
    for (int i = 0; i < TEST_COUNT; i++)
        fds[i] = open("/proc/self/stat", O_RDONLY);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) if (fds[i] >= 0) close(fds[i]);
    usleep(50000);
    
    /* Test 2: epoll_create */
    printf("--- Test: epoll_create x%d ---\n", TEST_COUNT);
    before = get_kmalloc64_active();
    for (int i = 0; i < TEST_COUNT; i++)
        fds[i] = epoll_create(1);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) if (fds[i] >= 0) close(fds[i]);
    usleep(50000);
    
    /* Test 3: timerfd_create */
    printf("--- Test: timerfd_create x%d ---\n", TEST_COUNT);
    before = get_kmalloc64_active();
    for (int i = 0; i < TEST_COUNT; i++)
        fds[i] = timerfd_create(CLOCK_MONOTONIC, 0);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) if (fds[i] >= 0) close(fds[i]);
    usleep(50000);
    
    /* Test 4: eventfd */
    printf("--- Test: eventfd x%d ---\n", TEST_COUNT);
    before = get_kmalloc64_active();
    for (int i = 0; i < TEST_COUNT; i++)
        fds[i] = eventfd(0, 0);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) if (fds[i] >= 0) close(fds[i]);
    usleep(50000);
    
    /* Test 5: signalfd */
    printf("--- Test: signalfd x%d ---\n", TEST_COUNT);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    before = get_kmalloc64_active();
    for (int i = 0; i < TEST_COUNT; i++)
        fds[i] = signalfd(-1, &mask, 0);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) if (fds[i] >= 0) close(fds[i]);
    usleep(50000);
    
    /* Test 6: inotify_init + inotify_add_watch */
    printf("--- Test: inotify watches x%d ---\n", TEST_COUNT);
    int inotify_fd = inotify_init();
    before = get_kmalloc64_active();
    int wd[TEST_COUNT];
    for (int i = 0; i < TEST_COUNT; i++)
        wd[i] = inotify_add_watch(inotify_fd, "/data/local/tmp", IN_ALL_EVENTS);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) 
        if (wd[i] >= 0) inotify_rm_watch(inotify_fd, wd[i]);
    close(inotify_fd);
    usleep(50000);
    
    /* Test 7: socketpair */
    printf("--- Test: socketpair x%d ---\n", TEST_COUNT);
    int sv[TEST_COUNT][2];
    before = get_kmalloc64_active();
    for (int i = 0; i < TEST_COUNT; i++)
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) {
        close(sv[i][0]); close(sv[i][1]);
    }
    usleep(50000);
    
    /* Test 8: open /dev/ptmx */
    printf("--- Test: open /dev/ptmx x%d ---\n", TEST_COUNT);
    before = get_kmalloc64_active();
    int ptmx_before = get_slab_active("kmalloc-128");
    int ptmx_before_256 = get_slab_active("kmalloc-256");
    int ptmx_before_512 = get_slab_active("kmalloc-512");
    int ptmx_before_1024 = get_slab_active("kmalloc-1024");
    for (int i = 0; i < TEST_COUNT; i++)
        fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    after = get_kmalloc64_active();
    printf("  kmalloc-64:   %d → %d (delta: %+d)\n", before, after, after - before);
    printf("  kmalloc-128:  %d → %d (delta: %+d)\n", ptmx_before, get_slab_active("kmalloc-128"), get_slab_active("kmalloc-128") - ptmx_before);
    printf("  kmalloc-256:  %d → %d (delta: %+d)\n", ptmx_before_256, get_slab_active("kmalloc-256"), get_slab_active("kmalloc-256") - ptmx_before_256);
    printf("  kmalloc-512:  %d → %d (delta: %+d)\n", ptmx_before_512, get_slab_active("kmalloc-512"), get_slab_active("kmalloc-512") - ptmx_before_512);
    printf("  kmalloc-1024: %d → %d (delta: %+d)\n", ptmx_before_1024, get_slab_active("kmalloc-1024"), get_slab_active("kmalloc-1024") - ptmx_before_1024);
    for (int i = 0; i < TEST_COUNT; i++) if (fds[i] >= 0) close(fds[i]);
    usleep(50000);

    /* Test 9: pipe */
    printf("--- Test: pipe x%d ---\n", TEST_COUNT);
    int pipes[TEST_COUNT][2];
    before = get_kmalloc64_active();
    for (int i = 0; i < TEST_COUNT; i++)
        pipe(pipes[i]);
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    for (int i = 0; i < TEST_COUNT; i++) {
        close(pipes[i][0]); close(pipes[i][1]);
    }
    usleep(50000);
    
    /* Test 10: epoll_ctl with pipe fds */
    printf("--- Test: epoll_ctl ADD x%d ---\n", TEST_COUNT);
    int ep = epoll_create(1);
    int pp[2]; pipe(pp);
    before = get_kmalloc64_active();
    /* We can only add once per fd, so create many pipes */
    int ep_pipes[TEST_COUNT][2];
    for (int i = 0; i < TEST_COUNT; i++) {
        pipe(ep_pipes[i]);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = ep_pipes[i][0] };
        epoll_ctl(ep, EPOLL_CTL_ADD, ep_pipes[i][0], &ev);
    }
    after = get_kmalloc64_active();
    printf("  kmalloc-64: %d → %d (delta: %+d)\n", before, after, after - before);
    printf("  kmalloc-128: delta: %+d\n", get_slab_active("kmalloc-128") - ptmx_before);
    for (int i = 0; i < TEST_COUNT; i++) {
        close(ep_pipes[i][0]); close(ep_pipes[i][1]);
    }
    close(ep); close(pp[0]); close(pp[1]);
    
    printf("\n=== Done ===\n");
    return 0;
}
