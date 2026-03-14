/*
 * netlink_fuzz.c — Netlink socket fuzzer for accessible families
 *
 * Tests NETLINK_ROUTE and NETLINK_SELINUX with malformed messages,
 * oversized payloads, and boundary values.
 *
 * Build: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -Wall -o netlink_fuzz netlink_fuzz.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static unsigned long long rng_state;
static unsigned int rnd32(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (unsigned int)(rng_state & 0xFFFFFFFF);
}

static int g_ops = 0;

/* Send a netlink message and read response */
static void nl_send_recv(int fd, void *msg, int len) {
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = msg, .iov_len = len };
    struct msghdr mh = {
        .msg_name = &sa, .msg_namelen = sizeof(sa),
        .msg_iov = &iov, .msg_iovlen = 1
    };

    sendmsg(fd, &mh, MSG_DONTWAIT);

    /* Non-blocking recv */
    char rbuf[4096];
    struct iovec riov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
    struct msghdr rmh = {
        .msg_name = &sa, .msg_namelen = sizeof(sa),
        .msg_iov = &riov, .msg_iovlen = 1
    };
    recvmsg(fd, &rmh, MSG_DONTWAIT);
    g_ops++;
}

/* Test NETLINK_ROUTE */
static void fuzz_route(int iters) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        printf("[!] Cannot create NETLINK_ROUTE: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = 0 };
    bind(fd, (struct sockaddr *)&sa, sizeof(sa));

    printf("[+] NETLINK_ROUTE fd=%d, %d iterations\n", fd, iters);

    for (int i = 0; i < iters; i++) {
        uint32_t pick = rnd32() % 10;

        if (pick < 3) {
            /* Valid RTM_GETLINK dump request */
            struct {
                struct nlmsghdr nlh;
                struct ifinfomsg ifi;
            } req;
            memset(&req, 0, sizeof(req));
            req.nlh.nlmsg_len = sizeof(req);
            req.nlh.nlmsg_type = RTM_GETLINK;
            req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.nlh.nlmsg_seq = i;
            req.ifi.ifi_family = AF_UNSPEC;
            nl_send_recv(fd, &req, sizeof(req));
        } else if (pick < 5) {
            /* RTM_GETADDR dump */
            struct {
                struct nlmsghdr nlh;
                struct ifaddrmsg ifa;
            } req;
            memset(&req, 0, sizeof(req));
            req.nlh.nlmsg_len = sizeof(req);
            req.nlh.nlmsg_type = RTM_GETADDR;
            req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.nlh.nlmsg_seq = i;
            req.ifa.ifa_family = AF_INET;
            nl_send_recv(fd, &req, sizeof(req));
        } else if (pick < 7) {
            /* RTM_GETROUTE dump */
            struct {
                struct nlmsghdr nlh;
                struct rtmsg rtm;
            } req;
            memset(&req, 0, sizeof(req));
            req.nlh.nlmsg_len = sizeof(req);
            req.nlh.nlmsg_type = RTM_GETROUTE;
            req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.nlh.nlmsg_seq = i;
            req.rtm.rtm_family = AF_INET;
            nl_send_recv(fd, &req, sizeof(req));
        } else if (pick < 8) {
            /* Garbage nlmsg_type */
            struct nlmsghdr nlh;
            memset(&nlh, 0, sizeof(nlh));
            nlh.nlmsg_len = sizeof(nlh);
            nlh.nlmsg_type = rnd32() & 0xFFFF;
            nlh.nlmsg_flags = NLM_F_REQUEST;
            nlh.nlmsg_seq = i;
            nl_send_recv(fd, &nlh, sizeof(nlh));
        } else if (pick < 9) {
            /* Oversized payload */
            char buf[2048];
            memset(buf, 0, sizeof(buf));
            struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
            nlh->nlmsg_len = sizeof(buf);
            nlh->nlmsg_type = RTM_GETLINK;
            nlh->nlmsg_flags = NLM_F_REQUEST;
            nlh->nlmsg_seq = i;
            /* Fill payload with random */
            for (int j = sizeof(*nlh); j < (int)sizeof(buf); j++)
                buf[j] = rnd32() & 0xFF;
            nl_send_recv(fd, buf, sizeof(buf));
        } else {
            /* Tiny message (truncated header) */
            char buf[4];
            *(uint32_t*)buf = rnd32();
            nl_send_recv(fd, buf, sizeof(buf));
        }

        if (i % 1000 == 0)
            printf("  [%d] ops=%d\n", i, g_ops);
    }

    close(fd);
}

/* Test NETLINK_SELINUX */
static void fuzz_selinux(int iters) {
    int fd = socket(AF_NETLINK, SOCK_RAW, 7 /* NETLINK_SELINUX */);
    if (fd < 0) {
        printf("[!] Cannot create NETLINK_SELINUX: %s\n", strerror(errno));
        return;
    }

    /* Subscribe to SELinux notifications */
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = 1 };
    bind(fd, (struct sockaddr *)&sa, sizeof(sa));

    printf("[+] NETLINK_SELINUX fd=%d, %d iterations\n", fd, iters);

    for (int i = 0; i < iters; i++) {
        /* Send various messages to SELinux netlink */
        char buf[256];
        int len;

        uint32_t pick = rnd32() % 5;
        if (pick < 2) {
            /* SELNL_MSG_SETENFORCE */
            struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
            memset(buf, 0, sizeof(buf));
            nlh->nlmsg_len = NLMSG_LENGTH(4);
            nlh->nlmsg_type = 0x10; /* SELNL_MSG_SETENFORCE */
            nlh->nlmsg_flags = NLM_F_REQUEST;
            len = nlh->nlmsg_len;
            nl_send_recv(fd, buf, len);
        } else if (pick < 4) {
            /* SELNL_MSG_POLICYLOAD */
            struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
            memset(buf, 0, sizeof(buf));
            nlh->nlmsg_len = NLMSG_LENGTH(4);
            nlh->nlmsg_type = 0x11; /* SELNL_MSG_POLICYLOAD */
            nlh->nlmsg_flags = NLM_F_REQUEST;
            len = nlh->nlmsg_len;
            nl_send_recv(fd, buf, len);
        } else {
            /* Random garbage */
            len = 16 + (rnd32() % 200);
            for (int j = 0; j < len; j++)
                buf[j] = rnd32() & 0xFF;
            nl_send_recv(fd, buf, len);
        }

        if (i % 1000 == 0)
            printf("  [%d] ops=%d\n", i, g_ops);
    }

    close(fd);
}

int main(int argc, char **argv) {
    int iters = 5000;
    if (argc >= 2) iters = atoi(argv[1]);

    struct { int x; } tv;
    tv.x = getpid();
    rng_state = (unsigned long long)tv.x << 32 | 0xDEADBEEF;

    printf("=== Netlink Fuzzer ===\n");
    printf("uid=%d, iterations=%d\n\n", getuid(), iters);

    fuzz_route(iters);
    printf("\n");
    fuzz_selinux(iters);

    printf("\n=== Done: %d total ops ===\n", g_ops);
    return 0;
}
