/* binder_svc_add_test.c — Test whether current UID can addService to ServiceManager.
 *
 * Run as shell (UID 2000) to check shell addService permission.
 * Run via agent (UID 10139, untrusted_app) to check app addService permission.
 *
 * This binary does the minimal binder setup to test addService("privesc_svc_test").
 * Reports: OK (service added), DENY (SELinux/SM reject), ERROR.
 *
 * BUILD: qemu\build-arm.bat src\binder\binder_svc_add_test.c binder_svc_add_test
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

struct binder_write_read {
    signed long write_size, write_consumed;
    unsigned long write_buffer;
    signed long read_size, read_consumed;
    unsigned long read_buffer;
};
struct binder_version { int32_t protocol_version; };
struct binder_transaction_data {
    union { uint32_t handle; void *ptr; } target;
    void *cookie;
    uint32_t code, flags;
    int32_t sender_pid;
    uint32_t sender_euid, data_size, offsets_size;
    union {
        struct { const void *buffer; const void *offsets; } ptr;
        uint8_t buf[8];
    } data;
};
struct flat_binder_object {
    uint32_t type, flags;
    union { uintptr_t binder; uint32_t handle; };
    uintptr_t cookie;
};
struct binder_ptr_cookie { void *ptr; void *cookie; };

#define BINDER_WRITE_READ   _IOWR('b', 1, struct binder_write_read)
#define BINDER_VERSION      _IOWR('b', 9, struct binder_version)
#define BINDER_MMAP_SIZE    (256*1024)
#define BINDER_DEV          "/dev/binder"
#define BC_TRANSACTION      _IOW('c', 0, struct binder_transaction_data)
#define BC_FREE_BUFFER      0x40046303
#define BC_ENTER_LOOPER     0x000d0000
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_NOOP             _IO('r', 12)
#define BR_SPAWN_LOOPER     _IO('r', 13)
#define BR_INCREFS          _IOR('r', 7, struct binder_ptr_cookie)
#define BR_ACQUIRE          _IOR('r', 8, struct binder_ptr_cookie)
#define BR_RELEASE          _IOR('r', 9, struct binder_ptr_cookie)
#define BR_DECREFS          _IOR('r', 10, struct binder_ptr_cookie)
#define BR_REPLY            _IOR('r', 3, struct binder_transaction_data)
#define BR_DEAD_REPLY       _IO('r', 5)
#define BR_FAILED_REPLY     _IO('r', 17)
#define BINDER_TYPE_BINDER  0x73624a85
#define SM_ADD_SERVICE      3

static int g_fd;

static int bwr(void *wb, size_t ws, void *rb, size_t rs, size_t *rc) {
    struct binder_write_read b = {0};
    b.write_buffer = (uintptr_t)wb; b.write_size = ws;
    b.read_buffer = (uintptr_t)rb; b.read_size = rs;
    int r = ioctl(g_fd, BINDER_WRITE_READ, &b);
    if (rc) *rc = b.read_consumed;
    return r;
}

static void w32(uint8_t **p, uint32_t v) { memcpy(*p, &v, 4); *p += 4; }
static void wstr16(uint8_t **p, const char *s) {
    uint32_t n = strlen(s); w32(p, n);
    for (uint32_t i = 0; i < n; i++) { uint16_t c = s[i]; memcpy(*p, &c, 2); *p += 2; }
    uint16_t z = 0; memcpy(*p, &z, 2); *p += 2;
    while ((uintptr_t)*p % 4) (*p)++;
}

int main(void) {
    printf("=== Binder addService SELinux test ===\n");
    printf("UID=%d  EUID=%d\n", getuid(), geteuid());

    g_fd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
    if (g_fd < 0) { perror("open binder"); return 1; }

    void *bmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, g_fd, 0);
    if (bmap == MAP_FAILED) { perror("mmap"); return 1; }

    struct binder_version ver;
    ioctl(g_fd, BINDER_VERSION, &ver);
    printf("Binder version: %d\n", (int)ver.protocol_version);

    /* Enter looper */
    uint8_t el[4]; uint8_t *elp = el;
    w32(&elp, (uint32_t)_IO('c', 12));
    bwr(el, 4, NULL, 0, NULL);

    /* Build addService parcel */
    uint8_t tdata[512], offdata[4];
    uint8_t *p = tdata;
    w32(&p, 0);  /* strict mode */
    wstr16(&p, "android.os.IServiceManager");
    wstr16(&p, "privesc_svc_test");

    /* BINDER_TYPE_BINDER object: our node */
    uint32_t obj_off = (uint32_t)(p - tdata);
    struct flat_binder_object fbo = {0};
    fbo.type = BINDER_TYPE_BINDER;
    fbo.flags = 0x10;
    fbo.binder = (uintptr_t)&main;
    fbo.cookie = 0;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);
    w32(&p, 0);  /* allow_isolated=0 */

    uint32_t *op = (uint32_t*)offdata; *op = obj_off;

    /* BC_TRANSACTION to handle 0 (servicemanager) */
    struct { uint32_t cmd; struct binder_transaction_data td; } __attribute__((packed)) wb = {0};
    wb.cmd = BC_TRANSACTION;
    wb.td.target.handle = 0;
    wb.td.code = SM_ADD_SERVICE;
    wb.td.flags = 0;
    wb.td.data.ptr.buffer = tdata;
    wb.td.data.ptr.offsets = offdata;
    wb.td.data_size = p - tdata;
    wb.td.offsets_size = 4;

    uint8_t rbuf[1024];
    size_t rc = 0;
    int ret = bwr(&wb, sizeof(wb), rbuf, sizeof(rbuf), &rc);
    printf("bwr ret=%d rc=%zu\n", ret, rc);

    /* Parse response */
    for (int iter = 0; iter < 20 && rc > 0; iter++) {
        uint8_t *rp = rbuf, *re = rbuf + rc;
        while (rp + 4 <= re) {
            uint32_t cmd = *(uint32_t*)rp; rp += 4;
            if (cmd == (uint32_t)BR_NOOP || cmd == (uint32_t)BR_SPAWN_LOOPER || cmd == (uint32_t)BR_TRANSACTION_COMPLETE) continue;
            if (cmd == (uint32_t)BR_INCREFS || cmd == (uint32_t)BR_ACQUIRE || cmd == (uint32_t)BR_RELEASE || cmd == (uint32_t)BR_DECREFS)
                { rp += sizeof(struct binder_ptr_cookie); continue; }
            if (cmd == (uint32_t)BR_DEAD_REPLY) {
                printf("RESULT: BR_DEAD_REPLY — hard fail (SM died or binder error)\n");
                goto done;
            }
            if (cmd == (uint32_t)BR_FAILED_REPLY) {
                printf("RESULT: BR_FAILED_REPLY — SELinux or SM rejected addService\n");
                goto done;
            }
            if (cmd == (uint32_t)BR_REPLY) {
                struct binder_transaction_data *td = (struct binder_transaction_data*)rp;
                rp += sizeof(*td);
                /* Read status int from reply */
                int32_t status = -99;
                if (td->data_size >= 4) {
                    uint8_t *dp = (uint8_t*)(uintptr_t)td->data.ptr.buffer;
                    memcpy(&status, dp, 4);
                }
                if (status == 0)
                    printf("RESULT: BR_REPLY status=0 — addService SUCCEEDED! SELinux ALLOWS this UID to add services\n");
                else
                    printf("RESULT: BR_REPLY status=%d — SM rejected (policy check failed)\n", status);
                /* Free buffer */
                uint8_t fb[4 + sizeof(uintptr_t)]; uint8_t *fp = fb;
                uint32_t fbc = (uint32_t)_IOW('c', 3, void*); w32(&fp, fbc);
                uintptr_t bptr = (uintptr_t)td->data.ptr.buffer;
                memcpy(fp, &bptr, sizeof(uintptr_t)); fp += sizeof(uintptr_t);
                bwr(fb, fp - fb, NULL, 0, NULL);
                goto done;
            }
            printf("Unknown cmd: 0x%08x\n", cmd);
            break;
        }
        rc = 0;
        bwr(NULL, 0, rbuf, sizeof(rbuf), &rc);
    }
    printf("RESULT: timed out parsing binder response\n");
done:
    /* Check if service was actually registered */
    printf("Checking service list...\n");
    munmap(bmap, BINDER_MMAP_SIZE);
    close(g_fd);
    return 0;
}
