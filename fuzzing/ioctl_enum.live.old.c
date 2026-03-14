/*
 * ioctl_enum.live.c — Ioctl enumerator for the LIVE Samsung SM-T377A device
 *
 * Struct sizes derived from Samsung GPL kernel source:
 *   github.com/jcadduono/android_kernel_samsung_universal3475
 *   drivers/gpu/arm/t72x/r7p0/mali_kbase_uku.h
 *
 * Build: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -o ioctl_enum_live ioctl_enum.live.c
 * Push:  adb push ioctl_enum_live /data/local/tmp/
 * Run:   adb shell /data/local/tmp/ioctl_enum_live --mali
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>


/* ===== Binder ioctl definitions (from kernel 3.10 binder.h) ===== */
#define BINDER_WRITE_READ           _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_IDLE_TIMEOUT     _IOW('b', 3, long long)
#define BINDER_SET_MAX_THREADS      _IOW('b', 5, unsigned int)
#define BINDER_SET_IDLE_PRIORITY    _IOW('b', 6, int)
#define BINDER_SET_CONTEXT_MGR      _IOW('b', 7, int)
#define BINDER_THREAD_EXIT          _IOW('b', 8, int)
#define BINDER_VERSION              _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    long write_size;
    long write_consumed;
    unsigned long write_buffer;
    long read_size;
    long read_consumed;
    unsigned long read_buffer;
};

struct binder_version {
    long protocol_version;
};

/* ===== Ashmem ioctl definitions (from kernel 3.10 ashmem.h) ===== */
#define ASHMEM_SET_NAME             _IOW(0x77, 1, char[256])
#define ASHMEM_GET_NAME             _IOR(0x77, 2, char[256])
#define ASHMEM_SET_SIZE             _IOW(0x77, 3, size_t)
#define ASHMEM_GET_SIZE             _IO(0x77, 4)
#define ASHMEM_SET_PROT_MASK        _IOW(0x77, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK        _IO(0x77, 6)
#define ASHMEM_PIN                  _IOW(0x77, 7, struct ashmem_pin)
#define ASHMEM_UNPIN                _IOW(0x77, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS       _IO(0x77, 9)
#define ASHMEM_PURGE_ALL_CACHES     _IO(0x77, 10)

struct ashmem_pin {
    unsigned int offset;
    unsigned int len;
};

/* ===== Signal recovery for surviving crashes ===== */
static sigjmp_buf jump_env;
static volatile int got_signal = 0;

static void signal_handler(int sig) {
    got_signal = sig;
    siglongjmp(jump_env, 1);
}

/* ===== Ioctl test descriptor ===== */
struct ioctl_test {
    const char *name;
    unsigned long cmd;
    void *arg;
    size_t arg_size;
};

static void test_ioctl(int fd, const char *dev_name, struct ioctl_test *test) {
    int ret;

    got_signal = 0;
    if (sigsetjmp(jump_env, 1) != 0) {
        printf("  [!] %-30s  SIGNAL %d (recovered)\n", test->name, got_signal);
        return;
    }

    /* Set up signal handlers to survive user-space crashes */
    signal(SIGSEGV, signal_handler);
    signal(SIGBUS, signal_handler);
    signal(SIGFPE, signal_handler);

    ret = ioctl(fd, test->cmd, test->arg);

    if (ret == 0) {
        printf("  [+] %-30s  OK (ret=0)\n", test->name);
    } else {
        printf("  [-] %-30s  FAIL (ret=%d, errno=%d: %s)\n",
               test->name, ret, errno, strerror(errno));
    }

    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
}

/* ===== Binder tests ===== */
static void test_binder(void) {
    int fd;
    struct binder_version ver = { 0 };
    struct binder_write_read bwr = { 0 };
    unsigned int max_threads = 15;
    int zero = 0;

    printf("\n=== BINDER IOCTL ENUMERATION ===\n");

    fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        printf("[-] Cannot open /dev/binder: %s\n", strerror(errno));
        return;
    }
    printf("[+] /dev/binder opened (fd=%d)\n\n", fd);

    struct ioctl_test tests[] = {
        { "BINDER_VERSION",          BINDER_VERSION,          &ver,         sizeof(ver) },
        { "BINDER_SET_MAX_THREADS",  BINDER_SET_MAX_THREADS,  &max_threads, sizeof(max_threads) },
        { "BINDER_SET_CONTEXT_MGR",  BINDER_SET_CONTEXT_MGR,  &zero,        sizeof(zero) },
        { "BINDER_THREAD_EXIT",      BINDER_THREAD_EXIT,      &zero,        sizeof(zero) },
        { "BINDER_WRITE_READ(empty)", BINDER_WRITE_READ,      &bwr,         sizeof(bwr) },

        /* Malformed: NULL arg pointer */
        { "BINDER_VERSION(NULL)",    BINDER_VERSION,          NULL,         0 },
        { "BINDER_WRITE_READ(NULL)", BINDER_WRITE_READ,       NULL,         0 },

        /* Malformed: bogus pointer */
        { "BINDER_VERSION(0xdead)",  BINDER_VERSION,          (void*)0xdeadbeef, 0 },

        { NULL, 0, NULL, 0 }
    };

    for (int i = 0; tests[i].name; i++) {
        test_ioctl(fd, "/dev/binder", &tests[i]);
    }

    /* Print version if we got it */
    if (ver.protocol_version != 0) {
        printf("\n  Binder protocol version: %ld\n", ver.protocol_version);
    }

    close(fd);
}

/* ===== Ashmem tests ===== */
static void test_ashmem(void) {
    int fd;
    char name_buf[256] = { 0 };
    size_t size = 4096;
    unsigned long prot;
    struct ashmem_pin pin = { 0, 4096 };

    printf("\n=== ASHMEM IOCTL ENUMERATION ===\n");

    fd = open("/dev/ashmem", O_RDWR);
    if (fd < 0) {
        printf("[-] Cannot open /dev/ashmem: %s\n", strerror(errno));
        return;
    }
    printf("[+] /dev/ashmem opened (fd=%d)\n\n", fd);

    struct ioctl_test tests[] = {
        { "ASHMEM_SET_NAME",         ASHMEM_SET_NAME,         "testregion",  11 },
        { "ASHMEM_GET_NAME",         ASHMEM_GET_NAME,         name_buf,     sizeof(name_buf) },
        { "ASHMEM_SET_SIZE",         ASHMEM_SET_SIZE,         &size,        sizeof(size) },
        { "ASHMEM_GET_SIZE",         ASHMEM_GET_SIZE,         NULL,         0 },
        { "ASHMEM_SET_PROT_MASK",    ASHMEM_SET_PROT_MASK,    &prot,        sizeof(prot) },
        { "ASHMEM_GET_PROT_MASK",    ASHMEM_GET_PROT_MASK,    NULL,         0 },
        { "ASHMEM_PIN",              ASHMEM_PIN,              &pin,         sizeof(pin) },
        { "ASHMEM_UNPIN",            ASHMEM_UNPIN,            &pin,         sizeof(pin) },
        { "ASHMEM_GET_PIN_STATUS",   ASHMEM_GET_PIN_STATUS,   NULL,         0 },
        { "ASHMEM_PURGE_ALL_CACHES", ASHMEM_PURGE_ALL_CACHES, NULL,         0 },

        /* Malformed: NULL where struct expected */
        { "ASHMEM_SET_NAME(NULL)",   ASHMEM_SET_NAME,         NULL,         0 },
        { "ASHMEM_PIN(NULL)",        ASHMEM_PIN,              NULL,         0 },

        /* Malformed: bogus pointer */
        { "ASHMEM_SET_NAME(0xdead)", ASHMEM_SET_NAME,         (void*)0xdeadbeef, 0 },

        /* Boundary: huge size */
        { "ASHMEM_SET_SIZE(huge)",   ASHMEM_SET_SIZE,         (void*)0xffffffff, 0 },

        { NULL, 0, NULL, 0 }
    };

    for (int i = 0; tests[i].name; i++) {
        test_ioctl(fd, "/dev/ashmem", &tests[i]);
    }

    /* Print retrieved name */
    if (name_buf[0]) {
        printf("\n  Ashmem region name: '%s'\n", name_buf);
    }

    close(fd);
}

/* ===== Unknown ioctl brute-force scan ===== */
static void scan_unknown_ioctls(const char *dev, int type_start, int type_end,
                                 int nr_start, int nr_end) {
    int fd, ret, found = 0;

    printf("\n=== UNKNOWN IOCTL SCAN: %s (type 0x%02x-0x%02x, nr %d-%d) ===\n",
           dev, type_start, type_end, nr_start, nr_end);

    fd = open(dev, O_RDWR);
    if (fd < 0) {
        printf("[-] Cannot open %s: %s\n", dev, strerror(errno));
        return;
    }

    for (int type = type_start; type <= type_end; type++) {
        for (int nr = nr_start; nr <= nr_end; nr++) {
            unsigned long cmd = _IO(type, nr);

            got_signal = 0;
            if (sigsetjmp(jump_env, 1) != 0) {
                printf("  [!] type=0x%02x nr=%3d  SIGNAL %d\n", type, nr, got_signal);
                found++;
                continue;
            }

            signal(SIGSEGV, signal_handler);
            signal(SIGBUS, signal_handler);

            errno = 0;
            ret = ioctl(fd, cmd, 0);

            signal(SIGSEGV, SIG_DFL);
            signal(SIGBUS, SIG_DFL);

            /* Only report non-ENOTTY results (ENOTTY = ioctl not recognized) */
            if (errno != ENOTTY && errno != EINVAL) {
                printf("  [?] type=0x%02x nr=%3d  ret=%d errno=%d (%s)\n",
                       type, nr, ret, errno, strerror(errno));
                found++;
            }
        }
    }

    printf("[*] Scan complete: %d interesting results\n", found);
    close(fd);
}

/* ===== Mali kbase tests ===== */

/*
 * Mali uses a single ioctl number per direction+size. The "function ID"
 * is embedded in the first 8 bytes (uk_header) of the payload.
 * The ioctl cmd encodes the payload size in _IOC_SIZE.
 */
#define UK_FUNC_ID                  512
#define UKP_FUNC_ID_CHECK_VERSION   0
#define KBASE_FUNC_MEM_ALLOC        (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_FREE         (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_QUERY        (UK_FUNC_ID + 3)
#define KBASE_FUNC_SET_FLAGS        (UK_FUNC_ID + 18)
#define KBASE_FUNC_GET_VERSION      (UK_FUNC_ID + 16)
#define KBASE_FUNC_GET_CONTEXT_ID   (UK_FUNC_ID + 31)
#define KBASE_FUNC_DISJOINT_QUERY   (UK_FUNC_ID + 29)
#define KBASE_FUNC_GPU_PROPS_REG_DUMP (UK_FUNC_ID + 14)
#define KBASE_FUNC_HWCNT_SETUP      (UK_FUNC_ID + 10)
#define KBASE_FUNC_JOB_SUBMIT       (UK_FUNC_ID + 28)

union uk_header {
    uint32_t id;     // input
    uint32_t ret;    // output (same 32-bit slot)
    uint64_t sizer;  // force 8-byte size/alignment
};

static unsigned long mali_cmd(uint32_t size) {
    return _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, size);
}

static void mali_uk_call(int fd, const char *name, uint32_t func_id,
                         void *buf, uint32_t buf_size) {
    if (!buf || buf_size < sizeof(union uk_header)) {
        printf("  [-] %-30s  SKIP (bad buf)\n", name);
        return;
    }

    union uk_header *hdr = (union uk_header *)buf;

    // ABI: same u32 slot is id on input, ret on output
    hdr->id = func_id;

    errno = 0;
    int ret = ioctl(fd, mali_cmd(buf_size), buf);

    if (ret == 0) {
        printf("  [+] %-30s  OK (uk_ret=%u)\n", name, hdr->ret);
    } else {
        printf("  [-] %-30s  FAIL (ret=%d, errno=%d: %s)\n",
               name, ret, errno, strerror(errno));
    }
}

static void test_mali(void) {
    int fd;
    unsigned char buf[256];

    printf("\n=== MALI KBASE IOCTL ENUMERATION ===\n");

    fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        printf("[-] Cannot open /dev/mali0: %s\n", strerror(errno));
        return;
    }
    printf("[+] /dev/mali0 opened (fd=%d)\n\n", fd);

    /* Step 1: Version handshake (required before any other call) */
    {
        struct {
            union uk_header header;
            uint16_t major;
            uint16_t minor;
            uint8_t  pad[4];
        } ver;
        memset(&ver, 0, sizeof(ver));
        ver.major = 10;
        ver.minor = 0;
        mali_uk_call(fd, "CHECK_VERSION", UKP_FUNC_ID_CHECK_VERSION,
                     &ver, sizeof(ver));
        printf("    -> kernel version: %u.%u\n", ver.major, ver.minor);
    }

    /* Step 2: SET_FLAGS (required before normal operations) */
    {
        struct {
            union uk_header header;
            unsigned int create_flags;
            unsigned char padding[4];
        } flags;
        memset(&flags, 0, sizeof(flags));
        flags.create_flags = 0;
        mali_uk_call(fd, "SET_FLAGS", KBASE_FUNC_SET_FLAGS,
                     &flags, sizeof(flags));
    }

    /* Step 3: Normal operations */

    /* GET_VERSION */
    {
        struct {
            union uk_header header;
            uint16_t major;
            uint16_t minor;
            uint8_t  pad[4];
        } ver;
        memset(&ver, 0, sizeof(ver));
        mali_uk_call(fd, "GET_VERSION", KBASE_FUNC_GET_VERSION,
                     &ver, sizeof(ver));
        printf("    -> driver version: %u.%u\n", ver.major, ver.minor);
    }

    /* GET_CONTEXT_ID */
    {
        struct {
            union uk_header header;
            long long ctx_id;
        } cid;
        memset(&cid, 0, sizeof(cid));
        mali_uk_call(fd, "GET_CONTEXT_ID", KBASE_FUNC_GET_CONTEXT_ID,
                     &cid, sizeof(cid));
        printf("    -> context_id: %lld\n", cid.ctx_id);
    }

    /* DISJOINT_QUERY */
    {
        struct {
            union uk_header header;
            uint32_t counter;
            uint32_t pad;      // to make it 16 total
        } dq;
        memset(&dq, 0, sizeof(dq));
        mali_uk_call(fd, "DISJOINT_QUERY", KBASE_FUNC_DISJOINT_QUERY,
                     &dq, sizeof(dq));
    }

    /* MEM_ALLOC */
    {
        struct {
            union uk_header header;
            unsigned long long va_pages;
            unsigned long long commit_pages;
            unsigned long long extent;
            unsigned long long flags;
            unsigned long long gpu_va;
            unsigned short va_alignment;
        } mem;
        memset(&mem, 0, sizeof(mem));
        mem.va_pages = 16;
        mem.commit_pages = 16;
        mali_uk_call(fd, "MEM_ALLOC(16 pages)", KBASE_FUNC_MEM_ALLOC,
                     &mem, sizeof(mem));
        for (int i=0; i<64; i++) printf("%02x ", ((uint8_t*)&mem)[i]);
        printf("\n");
        printf("    -> gpu_va: 0x%llx\n", mem.gpu_va);

        /* MEM_QUERY on that allocation */
        {
            struct {
                union uk_header header;
                unsigned long long gpu_addr;
                unsigned long long query;
                unsigned long long value;
            } q;
            memset(&q, 0, sizeof(q));
            q.gpu_addr = mem.gpu_va;
            q.query = 1;
            mali_uk_call(fd, "MEM_QUERY", KBASE_FUNC_MEM_QUERY,
                         &q, sizeof(q));
            printf("    -> value: %llu\n", q.value);
        }

        /* MEM_FREE */
        {
            struct {
                union uk_header header;
                unsigned long long gpu_addr;
            } mf;
            memset(&mf, 0, sizeof(mf));
            mf.gpu_addr = mem.gpu_va;
            mali_uk_call(fd, "MEM_FREE", KBASE_FUNC_MEM_FREE,
                         &mf, sizeof(mf));
        }
    }

    /* GPU_PROPS_REG_DUMP */
    {
        memset(buf, 0, sizeof(buf));
        mali_uk_call(fd, "GPU_PROPS_REG_DUMP", KBASE_FUNC_GPU_PROPS_REG_DUMP,
                     buf, 256);
    }

    /* HWCNT_SETUP (should fail — no HW) */
    {
        memset(buf, 0, 64);
        mali_uk_call(fd, "HWCNT_SETUP", KBASE_FUNC_HWCNT_SETUP,
                     buf, 64);
    }

    /* JOB_SUBMIT (should fail — no GPU) */
    {
        memset(buf, 0, 64);
        mali_uk_call(fd, "JOB_SUBMIT", KBASE_FUNC_JOB_SUBMIT,
                     buf, 64);
    }

    /* Malformed: call before version handshake on new fd */
    close(fd);
    fd = open("/dev/mali0", O_RDWR);
    if (fd >= 0) {
        memset(buf, 0, 64);
        mali_uk_call(fd, "MEM_ALLOC(no handshake)", KBASE_FUNC_MEM_ALLOC,
                     buf, 64);
        close(fd);
    }

    /* Malformed: NULL pointer */
    fd = open("/dev/mali0", O_RDWR);
    if (fd >= 0) {
        got_signal = 0;
        if (sigsetjmp(jump_env, 1) != 0) {
            printf("  [!] %-30s  SIGNAL %d\n", "IOCTL(NULL)", got_signal);
        } else {
            signal(SIGSEGV, signal_handler);
            signal(SIGBUS, signal_handler);
            int ret = ioctl(fd, _IOWR(0x80, 0, char[16]), NULL);
            signal(SIGSEGV, SIG_DFL);
            signal(SIGBUS, SIG_DFL);
            printf("  [-] %-30s  ret=%d errno=%d (%s)\n",
                   "IOCTL(NULL ptr)", ret, errno, strerror(errno));
        }

        /* Malformed: huge size */
        got_signal = 0;
        if (sigsetjmp(jump_env, 1) != 0) {
            printf("  [!] %-30s  SIGNAL %d\n", "IOCTL(huge)", got_signal);
        } else {
            signal(SIGSEGV, signal_handler);
            signal(SIGBUS, signal_handler);
            /* Size > CALL_MAX_SIZE (536) should return ENOTTY */
            struct big { char x[600]; };
            unsigned long cmd = _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, sizeof(struct big));
            memset(buf, 0x41, sizeof(buf));
            int ret = ioctl(fd, cmd, buf);
            signal(SIGSEGV, SIG_DFL);
            signal(SIGBUS, SIG_DFL);
            printf("  [-] %-30s  ret=%d errno=%d (%s)\n",
                   "IOCTL(0x41 fill)", ret, errno, strerror(errno));
        }
        close(fd);
    }

    printf("\n  [*] Mali enumeration complete\n");
}

int main(int argc, char **argv) {
    printf("=== IOCTL Enumerator for QEMU Kernel Fuzzing Lab ===\n");
    printf("Kernel fuzzing VM — crashes are expected and educational.\n");
    printf("PID: %d  UID: %d\n", getpid(), getuid());

    if (argc > 1 && strcmp(argv[1], "--scan") == 0) {
        /* Brute-force scan mode */
        scan_unknown_ioctls("/dev/binder", 'b', 'b', 0, 20);
        scan_unknown_ioctls("/dev/ashmem", 0x77, 0x77, 0, 20);
    } else if (argc > 1 && strcmp(argv[1], "--mali") == 0) {
        /* Mali only */
        test_mali();
    } else {
        /* Full enumeration */
        test_binder();
        test_ashmem();
        test_mali();
    }

    printf("\n=== ALL TESTS COMPLETE ===\n");
    return 0;
}
