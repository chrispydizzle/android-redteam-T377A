/*
 * slab_readv_test.c — Verify which slab cache readv iov allocates in
 * for different iovcnt values. Also check if UIO_FASTIOV was changed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <stdint.h>
#include <unistd.h>

struct rd_args {
    int pipe_rd;
    struct iovec iov[256];
    int iovcnt;
    volatile int started;
};

static void *readv_fn(void *a) {
    struct rd_args *r = (struct rd_args *)a;
    cpu_set_t c; CPU_ZERO(&c); CPU_SET(0, &c);
    sched_setaffinity(0, sizeof(c), &c);
    r->started = 1;
    readv(r->pipe_rd, r->iov, r->iovcnt);
    return NULL;
}

static int get_slab(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512]; int val = -1;
    while (fgets(line, sizeof(line), f)) {
        char n[64]; int a;
        if (sscanf(line, "%63s %d", n, &a) == 2 && !strcmp(n, name))
            { val = a; break; }
    }
    fclose(f);
    return val;
}

int main(void) {
    printf("=== readv iov Slab Allocation Test ===\n\n");

    uint8_t dummy[8];
    int test_counts[] = { 8, 9, 16, 17, 24, 32, 33, 48, 64, 128 };
    int ntests = sizeof(test_counts) / sizeof(test_counts[0]);

    for (int t = 0; t < ntests; t++) {
        int cnt = test_counts[t];
        int alloc_sz = cnt * 8;
        int n = 50;

        /* Expected slab cache */
        char *cache;
        if (alloc_sz <= 64) cache = "kmalloc-64";
        else if (alloc_sz <= 128) cache = "kmalloc-128";
        else if (alloc_sz <= 192) cache = "kmalloc-192";
        else if (alloc_sz <= 256) cache = "kmalloc-256";
        else if (alloc_sz <= 512) cache = "kmalloc-512";
        else if (alloc_sz <= 1024) cache = "kmalloc-1024";
        else cache = "kmalloc-2048";

        int before = get_slab(cache);

        int pipes[50][2];
        pthread_t tids[50];
        struct rd_args args[50];

        for (int i = 0; i < n; i++) {
            pipe(pipes[i]);
            memset(&args[i], 0, sizeof(args[i]));
            args[i].pipe_rd = pipes[i][0];
            args[i].iovcnt = cnt;
            for (int j = 0; j < cnt && j < 256; j++) {
                args[i].iov[j].iov_base = dummy;
                args[i].iov[j].iov_len = 1;
            }
            args[i].started = 0;
            pthread_create(&tids[i], NULL, readv_fn, &args[i]);
            while (!args[i].started) usleep(10);
        }
        usleep(100000);

        int after = get_slab(cache);

        printf("iovcnt=%-3d alloc=%-4d → %-12s: %d → %d (%+d) %s\n",
               cnt, alloc_sz, cache, before, after, after - before,
               (after - before >= n/2) ? "✓ HITS" :
               (after - before > 0) ? "~ partial" : "✗ MISS");

        /* Also check ALL caches for unexpected hits */
        if (after - before < n/2) {
            /* Check other caches */
            char *others[] = {"kmalloc-64","kmalloc-128","kmalloc-192",
                             "kmalloc-256","kmalloc-512","kmalloc-1024",
                             "kmalloc-2048","kmalloc-4096",NULL};
            for (int c = 0; others[c]; c++) {
                if (!strcmp(others[c], cache)) continue;
                int val = get_slab(others[c]);
                /* We don't have before values for other caches...
                   but we can note them */
            }
        }

        /* Cleanup */
        for (int i = 0; i < n; i++) close(pipes[i][1]);
        usleep(200000);
        for (int i = 0; i < n; i++) {
            pthread_join(tids[i], NULL);
            close(pipes[i][0]);
        }
    }

    /* More detailed test: snapshot ALL caches for iovcnt=32 */
    printf("\n=== Detailed: 50 readvs with iovcnt=32 ===\n");

    /* Snapshot all caches before */
    #define MAXC 200
    struct { char name[64]; int active; } sb[MAXC], sa[MAXC];
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512]; int nb = 0;
    fgets(line, sizeof(line), f); fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f) && nb < MAXC) {
        sscanf(line, "%63s %d", sb[nb].name, &sb[nb].active);
        nb++;
    }
    fclose(f);

    /* 50 blocking readvs with iovcnt=32 */
    int p2[50][2];
    pthread_t t2[50];
    struct rd_args a2[50];
    for (int i = 0; i < 50; i++) {
        pipe(p2[i]);
        memset(&a2[i], 0, sizeof(a2[i]));
        a2[i].pipe_rd = p2[i][0];
        a2[i].iovcnt = 32;
        for (int j = 0; j < 32; j++) {
            a2[i].iov[j].iov_base = line; /* reuse stack buffer, doesn't matter */
            a2[i].iov[j].iov_len = 1;
        }
        a2[i].started = 0;
        pthread_create(&t2[i], NULL, readv_fn, &a2[i]);
        while (!a2[i].started) usleep(10);
    }
    usleep(200000);

    /* Snapshot after */
    f = fopen("/proc/slabinfo", "r");
    int na = 0;
    fgets(line, sizeof(line), f); fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f) && na < MAXC) {
        sscanf(line, "%63s %d", sa[na].name, &sa[na].active);
        na++;
    }
    fclose(f);

    /* Diff */
    for (int i = 0; i < na; i++) {
        for (int j = 0; j < nb; j++) {
            if (!strcmp(sa[i].name, sb[j].name) &&
                sa[i].active != sb[j].active) {
                int d = sa[i].active - sb[j].active;
                if (d > 5 || d < -5)
                    printf("  %-24s %+d\n", sa[i].name, d);
            }
        }
    }

    /* Cleanup */
    for (int i = 0; i < 50; i++) close(p2[i][1]);
    usleep(200000);
    for (int i = 0; i < 50; i++) {
        pthread_join(t2[i], NULL);
        close(p2[i][0]);
    }

    printf("\n=== Done ===\n");
    return 0;
}
