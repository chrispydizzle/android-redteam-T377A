/*
 * slab_hunt.c — find Mali's slab cache and test dgram sendmsg persistence
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

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
    ioctl(fd, make_cmd(16), hb);
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    ioctl(fd, make_cmd(16), hb);
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
    if (((struct uk_header*)buf)->id != 0) return 0;
    return *(uint64_t*)(buf + 40);
}

static int mali_free(int fd, uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    return ioctl(fd, make_cmd(16), buf);
}

/* Parse ALL slab entries and store them */
struct slab_entry {
    char name[64];
    long active;
    long total;
    long objsize;
};

static int read_slabinfo(struct slab_entry *entries, int max) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return 0;
    char line[512];
    int count = 0;
    fgets(line, sizeof(line), f); /* skip header */
    fgets(line, sizeof(line), f); /* skip header2 */
    while (fgets(line, sizeof(line), f) && count < max) {
        sscanf(line, "%63s %ld %ld %ld",
               entries[count].name, &entries[count].active,
               &entries[count].total, &entries[count].objsize);
        count++;
    }
    fclose(f);
    return count;
}

int main(void) {
    printf("=== Slab Cache Hunter ===\n");

    /* TEST 1: Full slabinfo dump — find ALL caches */
    printf("\n--- Full slabinfo dump ---\n");
    struct slab_entry before[200], after[200];
    int nb = read_slabinfo(before, 200);
    printf("Total slab caches: %d\n", nb);

    /* Print all caches with > 0 active objects */
    for (int i = 0; i < nb; i++) {
        if (before[i].active > 0 || before[i].total > 0)
            printf("  %-40s active=%-6ld total=%-6ld objsz=%ld\n",
                   before[i].name, before[i].active, before[i].total, before[i].objsize);
    }

    /* TEST 2: Mali alloc diff — find WHICH cache grows */
    printf("\n--- Mali alloc slab diff (200 regions) ---\n");
    nb = read_slabinfo(before, 200);

    int mali_fd = mali_open_ctx();
    uint64_t vas[200];
    int count = 0;
    for (int i = 0; i < 200; i++) {
        vas[i] = mali_alloc(mali_fd, 1, 0x0F);
        if (vas[i]) count++;
    }
    printf("  Allocated %d Mali regions\n", count);

    int na = read_slabinfo(after, 200);

    printf("  Slab changes:\n");
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < na; j++) {
            if (strcmp(before[i].name, after[j].name) == 0) {
                long diff = after[j].active - before[i].active;
                if (diff != 0) {
                    printf("    %-40s: %+ld (active %ld→%ld, objsz=%ld)\n",
                           before[i].name, diff,
                           before[i].active, after[j].active,
                           before[i].objsize);
                }
                break;
            }
        }
    }

    /* Free all and check diff */
    for (int i = 0; i < 200; i++)
        if (vas[i]) mali_free(mali_fd, vas[i]);

    int nf = read_slabinfo(after, 200);
    printf("\n  After free:\n");
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < nf; j++) {
            if (strcmp(before[i].name, after[j].name) == 0) {
                long diff = after[j].active - before[i].active;
                if (diff != 0) {
                    printf("    %-40s: %+ld\n", before[i].name, diff);
                }
                break;
            }
        }
    }
    close(mali_fd);

    /* TEST 3: DGRAM sendmsg with cmsg persistence */
    printf("\n--- DGRAM sendmsg cmsg persistence ---\n");
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
            /* Increase recv buffer */
            int bufsize = 256 * 1024;
            setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
            setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

            nb = read_slabinfo(before, 200);

            /* Send many messages with cmsg data targeting kmalloc-64 */
            int sent = 0;
            for (int i = 0; i < 500; i++) {
                char data[1] = {'A'};
                struct iovec iov = { .iov_base = data, .iov_len = 1 };

                /* cmsg payload to target kmalloc-64:
                 * CMSG_SPACE adds alignment. We want total alloc ~64 bytes.
                 * cmsg_hdr = 12 bytes, so payload of ~48 → CMSG_SPACE(48)=64 */
                uint8_t cmsg_buf[CMSG_SPACE(48)];
                memset(cmsg_buf, 0x41 + (i & 0xF), sizeof(cmsg_buf));
                struct cmsghdr *cmsg = (struct cmsghdr*)cmsg_buf;
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                *(int*)CMSG_DATA(cmsg) = sv[1]; /* pass a valid fd */

                struct msghdr msg = {0};
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf;
                msg.msg_controllen = sizeof(cmsg_buf);

                int r = sendmsg(sv[0], &msg, MSG_DONTWAIT);
                if (r > 0) sent++;
                else break;
            }
            printf("  Sent %d DGRAM messages with cmsg\n", sent);

            na = read_slabinfo(after, 200);
            printf("  Slab changes:\n");
            for (int i = 0; i < nb; i++) {
                for (int j = 0; j < na; j++) {
                    if (strcmp(before[i].name, after[j].name) == 0) {
                        long diff = after[j].active - before[i].active;
                        if (diff >= 5) {
                            printf("    %-40s: %+ld (objsz=%ld)\n",
                                   before[i].name, diff, before[i].objsize);
                        }
                        break;
                    }
                }
            }

            /* Now recv all and check if freed */
            for (int i = 0; i < sent; i++) {
                char rbuf[64];
                struct iovec riov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
                uint8_t rcmsg[256];
                struct msghdr rmsg = {0};
                rmsg.msg_iov = &riov;
                rmsg.msg_iovlen = 1;
                rmsg.msg_control = rcmsg;
                rmsg.msg_controllen = sizeof(rcmsg);
                recvmsg(sv[1], &rmsg, MSG_DONTWAIT);
            }

            nf = read_slabinfo(after, 200);
            printf("  After recv:\n");
            for (int i = 0; i < nb; i++) {
                for (int j = 0; j < nf; j++) {
                    if (strcmp(before[i].name, after[j].name) == 0) {
                        long diff = after[j].active - before[i].active;
                        if (diff >= 5) {
                            printf("    %-40s: %+ld (objsz=%ld)\n",
                                   before[i].name, diff, before[i].objsize);
                        }
                        break;
                    }
                }
            }

            close(sv[0]);
            close(sv[1]);
        }
    }

    /* TEST 4: Pipe spray slab impact */
    printf("\n--- Pipe spray slab impact ---\n");
    {
        nb = read_slabinfo(before, 200);
        int pipes[200][2];
        int pipe_count = 0;
        for (int i = 0; i < 200; i++) {
            if (pipe(pipes[i]) < 0) break;
            fcntl(pipes[i][0], F_SETPIPE_SZ, 2 * 4096);
            pipe_count++;
        }
        printf("  Created %d pipes with 2-page buffers\n", pipe_count);

        na = read_slabinfo(after, 200);
        printf("  Slab changes:\n");
        for (int i = 0; i < nb; i++) {
            for (int j = 0; j < na; j++) {
                if (strcmp(before[i].name, after[j].name) == 0) {
                    long diff = after[j].active - before[i].active;
                    if (diff >= 5) {
                        printf("    %-40s: %+ld (objsz=%ld)\n",
                               before[i].name, diff, before[i].objsize);
                    }
                    break;
                }
            }
        }

        /* Close all */
        for (int i = 0; i < pipe_count; i++) {
            close(pipes[i][0]);
            close(pipes[i][1]);
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
