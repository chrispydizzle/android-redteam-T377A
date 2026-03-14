/*
 * binder_slab_full.c — Full slabinfo diff for binder operations
 * Dumps ALL slab caches and finds any that change.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT     _IOW('b', 8, int32_t)
#define BINDER_MMAP_SIZE       (128 * 1024)

#define MAX_CACHES 512
struct ci { char name[64]; int active; int total; int objsize; };

static int read_all_slabs(struct ci *c) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return 0;
    char line[512]; int n = 0;
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f) && n < MAX_CACHES) {
        sscanf(line, "%63s %d %d %d", c[n].name, &c[n].active, &c[n].total, &c[n].objsize);
        n++;
    }
    fclose(f);
    return n;
}

static void diff_all(struct ci *a, int na, struct ci *b, int nb, const char *label) {
    printf("[%s]\n", label);
    int found = 0;
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < na; j++) {
            if (!strcmp(b[i].name, a[j].name) && b[i].active != a[j].active) {
                printf("  %-30s size=%-4d %d → %d (%+d)\n",
                       b[i].name, b[i].objsize, a[j].active, b[i].active,
                       b[i].active - a[j].active);
                found++;
            }
        }
    }
    if (!found) printf("  (no changes)\n");
}

int main(void) {
    struct ci s1[MAX_CACHES], s2[MAX_CACHES], s3[MAX_CACHES], s4[MAX_CACHES];
    int n1, n2, n3, n4;

    printf("=== Full Slabinfo Diff for Binder ===\n\n");

    /* Warmup: open and close a binder to prime caches */
    int warmup = open("/dev/binder", O_RDWR);
    if (warmup >= 0) { close(warmup); }
    usleep(100000);

    /* Snapshot 1: baseline */
    n1 = read_all_slabs(s1);
    printf("Total caches: %d\n\n", n1);

    /* Open 50 binder instances with mmap + epoll */
    int bfds[50], epfds[50];
    for (int i = 0; i < 50; i++) {
        bfds[i] = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfds[i] < 0) { printf("Failed to open binder %d: %s\n", i, strerror(errno)); break; }
        mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfds[i], 0);
        uint32_t z = 0;
        ioctl(bfds[i], BINDER_SET_MAX_THREADS, &z);
        epfds[i] = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
    }

    usleep(100000); /* Let allocator settle */
    n2 = read_all_slabs(s2);
    diff_all(s1, n1, s2, n2, "After 50 binder open+mmap+epoll (creates 50 proc+thread)");

    /* THREAD_EXIT all 50 */
    int32_t dummy = 0;
    for (int i = 0; i < 50; i++) {
        ioctl(bfds[i], BINDER_THREAD_EXIT, &dummy);
    }

    usleep(100000);
    n3 = read_all_slabs(s3);
    diff_all(s2, n2, s3, n3, "After 50 THREAD_EXIT (frees 50 threads)");

    /* Close all */
    for (int i = 0; i < 50; i++) {
        epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], NULL);
        close(bfds[i]);
        close(epfds[i]);
    }

    usleep(100000);
    n4 = read_all_slabs(s4);
    diff_all(s3, n3, s4, n4, "After close all (frees 50 procs)");

    /* Also show total diff from baseline */
    diff_all(s1, n1, s4, n4, "Total diff (baseline → after cleanup)");

    printf("\n=== Done ===\n");
    return 0;
}
