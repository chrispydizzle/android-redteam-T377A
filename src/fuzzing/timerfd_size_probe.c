#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <string.h>
static long get_slab_active(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[256]; long act = -1;
    while (fgets(line, sizeof(line), f)) {
        char nm[64]; long a, b;
        if (sscanf(line, "%63s %ld %ld", nm, &a, &b) >= 2) {
            if (strcmp(nm, name) == 0) { act = a; break; }
        }
    }
    fclose(f); return act;
}
int main(void) {
    long before192 = get_slab_active("kmalloc-192");
    long before256 = get_slab_active("kmalloc-256");
    int fds[50];
    for (int i = 0; i < 50; i++) {
        fds[i] = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
        if (fds[i] < 0) { printf("create failed at %d\n", i); break; }
    }
    long after192 = get_slab_active("kmalloc-192");
    long after256 = get_slab_active("kmalloc-256");
    printf("kmalloc-192: %ld -> %ld (delta=%ld)\n", before192, after192, after192-before192);
    printf("kmalloc-256: %ld -> %ld (delta=%ld)\n", before256, after256, after256-before256);
    printf("timerfd_ctx goes to: %s\n", (after256 - before256 > 20) ? "kmalloc-256 (193-256 bytes)" : "kmalloc-192 (129-192 bytes)");
    for (int i = 0; i < 50; i++) if (fds[i] >= 0) close(fds[i]);
    return 0;
}