/* icmp_fuzz.c — ICMP/UDP/TCP socket fuzzer
 * Tests kernel socket handling from unprivileged shell.
 * Focus: ICMP (allowed due to ping_group_range), edge-case packets.
 * Cross-compile: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -Wall -o icmp_fuzz icmp_fuzz.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

static uint32_t seed;
static uint32_t rnd32(void) {
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

static unsigned long total_ops = 0;

/* Test ICMP socket with various malformed packets */
static void fuzz_icmp(int iters) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd < 0) {
        printf("[-] ICMP socket: %s\n", strerror(errno));
        return;
    }
    printf("[+] ICMP socket fd=%d\n", fd);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    for (int i = 0; i < iters; i++) {
        if (i % 1000 == 0)
            printf("  ICMP [%d] ops=%lu\n", i, total_ops);

        uint32_t op = rnd32() % 8;
        char buf[2048];

        if (op < 3) {
            /* Valid ICMP echo request with varying sizes */
            struct icmphdr hdr;
            memset(&hdr, 0, sizeof(hdr));
            hdr.type = ICMP_ECHO;
            hdr.code = 0;
            hdr.un.echo.id = htons(getpid() & 0xFFFF);
            hdr.un.echo.sequence = htons(i & 0xFFFF);
            int payload_len = rnd32() % 1400;
            memcpy(buf, &hdr, sizeof(hdr));
            for (int j = sizeof(hdr); j < (int)sizeof(hdr) + payload_len; j++)
                buf[j] = (char)(rnd32() & 0xFF);
            sendto(fd, buf, sizeof(hdr) + payload_len, MSG_DONTWAIT,
                   (struct sockaddr *)&dst, sizeof(dst));
        } else if (op < 5) {
            /* Malformed ICMP: bad type/code */
            struct icmphdr hdr;
            memset(&hdr, 0, sizeof(hdr));
            hdr.type = rnd32() % 256;
            hdr.code = rnd32() % 256;
            hdr.un.echo.id = htons(rnd32() & 0xFFFF);
            hdr.un.echo.sequence = htons(rnd32() & 0xFFFF);
            sendto(fd, &hdr, sizeof(hdr), MSG_DONTWAIT,
                   (struct sockaddr *)&dst, sizeof(dst));
        } else if (op == 5) {
            /* Zero-length send */
            sendto(fd, "", 0, MSG_DONTWAIT,
                   (struct sockaddr *)&dst, sizeof(dst));
        } else if (op == 6) {
            /* Oversized payload */
            int len = 1024 + (rnd32() % 1024);
            for (int j = 0; j < len; j++)
                buf[j] = (char)(rnd32() & 0xFF);
            sendto(fd, buf, len, MSG_DONTWAIT,
                   (struct sockaddr *)&dst, sizeof(dst));
        } else {
            /* Socket options fuzzing */
            int optval = (int)(rnd32());
            int optnames[] = {SO_RCVBUF, SO_SNDBUF, SO_RCVTIMEO, SO_SNDTIMEO,
                              SO_REUSEADDR, SO_BROADCAST, SO_KEEPALIVE};
            int idx = rnd32() % 7;
            setsockopt(fd, SOL_SOCKET, optnames[idx], &optval, sizeof(optval));
        }
        total_ops++;

        /* Non-blocking recv to drain any responses */
        char rbuf[2048];
        recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    }

    close(fd);
}

/* Test UDP socket edge cases */
static void fuzz_udp(int iters) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("[-] UDP socket: %s\n", strerror(errno));
        return;
    }
    printf("[+] UDP socket fd=%d\n", fd);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    for (int i = 0; i < iters; i++) {
        if (i % 1000 == 0)
            printf("  UDP [%d] ops=%lu\n", i, total_ops);

        char buf[2048];
        int len;
        uint32_t op = rnd32() % 5;

        if (op < 2) {
            /* Random port, random payload */
            dst.sin_port = htons(1 + (rnd32() % 65534));
            len = rnd32() % 1400;
            for (int j = 0; j < len; j++)
                buf[j] = (char)(rnd32() & 0xFF);
            sendto(fd, buf, len, MSG_DONTWAIT,
                   (struct sockaddr *)&dst, sizeof(dst));
        } else if (op == 2) {
            /* Connect then send (test connected UDP path) */
            dst.sin_port = htons(1 + (rnd32() % 65534));
            connect(fd, (struct sockaddr *)&dst, sizeof(dst));
            len = rnd32() % 512;
            for (int j = 0; j < len; j++)
                buf[j] = (char)(rnd32() & 0xFF);
            send(fd, buf, len, MSG_DONTWAIT);
        } else if (op == 3) {
            /* Bind to random port */
            struct sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            local.sin_port = htons(10000 + (rnd32() % 50000));
            bind(fd, (struct sockaddr *)&local, sizeof(local));
        } else {
            /* Shutdown/reopen cycle */
            close(fd);
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) break;
        }
        total_ops++;
    }

    if (fd >= 0) close(fd);
}

int main(int argc, char *argv[]) {
    int iters = 3000;
    if (argc > 1) iters = atoi(argv[1]);

    seed = (uint32_t)time(NULL) ^ getpid();
    printf("=== Socket Fuzzer (ICMP/UDP) ===\n");
    printf("uid=%d, iterations=%d per family\n", getuid(), iters);

    fuzz_icmp(iters);
    fuzz_udp(iters);

    printf("\n=== Done: %lu total ops ===\n", total_ops);
    return 0;
}
