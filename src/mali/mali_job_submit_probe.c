#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MALI_IOCTL_VENDOR(size) _IOC(_IOC_READ | _IOC_WRITE, 0x80, 0, (size))
#define MALI_IOCTL_STD(size)    _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, (size))

#define UKP_FUNC_ID_CHECK_VERSION 0
#define UK_FUNC_ID 512
#define KBASE_FUNC_POST_TERM   (UK_FUNC_ID + 9)
#define KBASE_FUNC_SET_FLAGS   (UK_FUNC_ID + 18)
#define KBASE_FUNC_JOB_SUBMIT  (UK_FUNC_ID + 28)

#define BASE_JD_REQ_DEP 0

typedef union {
    uint32_t id;
    uint32_t ret;
    uint64_t align;
} uk_header;

struct uku_version_check_args {
    uk_header header;
    uint16_t major;
    uint16_t minor;
    uint8_t padding[4];
};

struct kbase_uk_set_flags {
    uk_header header;
    uint32_t create_flags;
    uint32_t padding;
};

struct base_jd_udata {
    uint64_t blob[2];
};

struct base_dependency {
    uint8_t atom_id;
    uint8_t dependency_type;
};

struct base_jd_atom_v2 {
    uint64_t jc;
    struct base_jd_udata udata;
    uint64_t extres_list;
    uint16_t nr_extres;
    uint16_t core_req;
    struct base_dependency pre_dep[2];
    uint8_t atom_number;
    uint8_t prio;
    uint8_t device_nr;
    uint8_t padding[5];
};

struct kbase_uk_job_submit {
    uk_header header;
    uint64_t addr;
    uint32_t nr_atoms;
    uint32_t stride;
};

struct kbase_uk_job_submit_trace {
    uk_header header;
    uint64_t addr;
    uint32_t nr_atoms;
    uint32_t stride;
    uint32_t gles_ctx_handle;
    uint32_t padding;
};

struct kbase_uk_post_term {
    uk_header header;
};

struct base_jd_event_v2 {
    uint32_t event_code;
    uint8_t atom_number;
    uint8_t padding[3];
    struct base_jd_udata udata;
};

_Static_assert(sizeof(struct base_jd_atom_v2) == 48, "base_jd_atom_v2 size mismatch");
_Static_assert(sizeof(struct kbase_uk_job_submit) == 24, "kbase_uk_job_submit size mismatch");
_Static_assert(sizeof(struct base_jd_event_v2) == 24, "base_jd_event_v2 size mismatch");

static int do_uk_call_raw(int fd, unsigned long cmd, void *buf, size_t size)
{
    (void)size;
    errno = 0;
    return ioctl(fd, cmd, buf);
}

static int do_uk_call_vendor(int fd, void *buf, size_t size)
{
    return do_uk_call_raw(fd, MALI_IOCTL_VENDOR(size), buf, size);
}

static int mali_init(int fd)
{
    struct uku_version_check_args ver;
    struct kbase_uk_set_flags flags;

    memset(&ver, 0, sizeof(ver));
    ver.header.id = UKP_FUNC_ID_CHECK_VERSION;
    ver.major = 10;
    ver.minor = 2;
    if (do_uk_call_vendor(fd, &ver, sizeof(ver)) < 0) {
        printf("CHECK_VERSION ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("CHECK_VERSION ret=%u version=%u.%u\n", ver.header.ret, ver.major, ver.minor);
    if (ver.header.ret != 0)
        return -1;

    memset(&flags, 0, sizeof(flags));
    flags.header.id = KBASE_FUNC_SET_FLAGS;
    if (do_uk_call_vendor(fd, &flags, sizeof(flags)) < 0) {
        printf("SET_FLAGS ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("SET_FLAGS ret=%u\n", flags.header.ret);
    return flags.header.ret == 0 ? 0 : -1;
}

static void print_event(const char *label, const struct base_jd_event_v2 *ev)
{
    printf("%s event_code=0x%08x atom=%u udata=[0x%016llx,0x%016llx]\n",
           label,
           ev->event_code,
           ev->atom_number,
           (unsigned long long)ev->udata.blob[0],
           (unsigned long long)ev->udata.blob[1]);
}

static int poll_and_read_event(int fd, int timeout_ms, const char *label)
{
    struct pollfd pfd;
    struct base_jd_event_v2 ev;
    ssize_t n;
    int rc;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR | POLLHUP;

    rc = poll(&pfd, 1, timeout_ms);
    if (rc < 0) {
        printf("%s poll failed: errno=%d (%s)\n", label, errno, strerror(errno));
        return -1;
    }
    if (rc == 0) {
        printf("%s poll timed out after %d ms\n", label, timeout_ms);
        return 1;
    }

    printf("%s poll revents=0x%x\n", label, pfd.revents);

    memset(&ev, 0, sizeof(ev));
    n = read(fd, &ev, sizeof(ev));
    if (n < 0) {
        printf("%s read failed: errno=%d (%s)\n", label, errno, strerror(errno));
        return -1;
    }
    if ((size_t)n != sizeof(ev)) {
        printf("%s short read: got %lld bytes, expected %zu\n",
               label, (long long)n, sizeof(ev));
        return -1;
    }

    print_event(label, &ev);
    return 0;
}

static void dump_submit_result(const char *label, int rc, uint32_t ret)
{
    printf("%s ioctl=%d errno=%d (%s) ret=%u\n",
           label, rc, errno, strerror(errno), ret);
}

static int submit_dep_atom(int fd)
{
    struct base_jd_atom_v2 *atom;
    struct kbase_uk_job_submit_trace submit_trace;
    int rc;
    void *buf;
    uint32_t stride;

    buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        printf("mmap atom buffer failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    atom = (struct base_jd_atom_v2 *)buf;
    memset(atom, 0, sizeof(*atom));
    atom->jc = 0;
    atom->udata.blob[0] = 0x1111222233334444ULL;
    atom->udata.blob[1] = 0x5555666677778888ULL;
    atom->core_req = BASE_JD_REQ_DEP;
    atom->atom_number = 1;

    printf("Atom buffer=%p\n", (void *)atom);

    stride = 0;
    printf("Scanning JOB_SUBMIT stride with nr_atoms=0 (trace-sized submit struct)\n");
    for (uint32_t candidate = 0; candidate <= 96; candidate += 8) {
        memset(&submit_trace, 0, sizeof(submit_trace));
        submit_trace.header.id = KBASE_FUNC_JOB_SUBMIT;
        submit_trace.addr = (uint64_t)(uintptr_t)atom;
        submit_trace.nr_atoms = 0;
        submit_trace.stride = candidate;
        rc = do_uk_call_vendor(fd, &submit_trace, sizeof(submit_trace));
        printf("  stride=%u -> ioctl=%d errno=%d (%s) ret=%u\n",
               candidate, rc, errno, strerror(errno), submit_trace.header.ret);
        if (rc == 0 && submit_trace.header.ret == 0)
            stride = candidate;
    }

    if (stride == 0)
        stride = sizeof(*atom);

    printf("Trying vendor JOB_SUBMIT trace-sized struct with nr_atoms=1 addr=0x%016llx stride=%u size=%zu\n",
           (unsigned long long)(uint64_t)(uintptr_t)atom, stride, sizeof(submit_trace));

    memset(&submit_trace, 0, sizeof(submit_trace));
    submit_trace.header.id = KBASE_FUNC_JOB_SUBMIT;
    submit_trace.addr = (uint64_t)(uintptr_t)atom;
    submit_trace.nr_atoms = 1;
    submit_trace.stride = stride;
    rc = do_uk_call_vendor(fd, &submit_trace, sizeof(submit_trace));
    dump_submit_result("JOB_SUBMIT vendor trace", rc, submit_trace.header.ret);

    munmap(buf, 4096);
    return (rc == 0 && submit_trace.header.ret == 0) ? 0 : -1;
}

static int post_term(int fd)
{
    struct kbase_uk_post_term term;

    memset(&term, 0, sizeof(term));
    term.header.id = KBASE_FUNC_POST_TERM;
    if (do_uk_call_vendor(fd, &term, sizeof(term)) < 0) {
        printf("POST_TERM ioctl failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("POST_TERM ret=%u\n", term.header.ret);
    return term.header.ret == 0 ? 0 : -1;
}

static void run_probe(void)
{
    int fd;
    int flags;

    fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("open(/dev/mali0) failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    printf("Opened /dev/mali0 fd=%d\n", fd);
    printf("sizeof(atom)=%zu sizeof(job_submit)=%zu sizeof(event)=%zu\n",
           sizeof(struct base_jd_atom_v2),
           sizeof(struct kbase_uk_job_submit),
           sizeof(struct base_jd_event_v2));

    if (mali_init(fd) == 0) {
        if (submit_dep_atom(fd) == 0)
            poll_and_read_event(fd, 500, "after JOB_SUBMIT");
        if (post_term(fd) == 0)
            poll_and_read_event(fd, 500, "after POST_TERM");
    }

    close(fd);
}

int main(void)
{
    pid_t pid = fork();
    int status = 0;

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        alarm(15);
        run_probe();
        _exit(0);
    }

    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("Child terminated by signal %d\n", WTERMSIG(status));
        return 1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
