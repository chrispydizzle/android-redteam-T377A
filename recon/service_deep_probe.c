/*
 * service_deep_probe.c - Deep probe of high-value Android binder services
 * 
 * Priority targets:
 * 1. execute (IExecuteManager) - potential command execution
 * 2. usb (IUsbManager) - might restore ADB config
 * 3. persistent_data_block (IPersistentDataBlockService) - OEM unlock state
 * 4. iccc (IIcccManager) - TIMA integrity chain
 * 5. sedenial (ISEDenialService) - SELinux denial info
 * 6. serial (ISerialManager) - serial port access
 * 7. kiesusb - Samsung USB management
 * 8. ABTPersistenceService - Absolute persistence
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o service_deep_probe service_deep_probe.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>

/* Binder definitions */
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

#define BC_TRANSACTION 0x40286300
#define BR_REPLY       0x80287202
#define BR_NOOP        0x720C
#define BR_TRANSACTION_COMPLETE 0x720E

struct binder_transaction_data {
    union {
        uint32_t handle;
        void *ptr;
    } target;
    void *cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    int32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct {
            const void *buffer;
            const void *offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

/* Get service handle from servicemanager */
static int get_service_handle(int fd, const char *name) {
    unsigned char writebuf[512];
    unsigned char readbuf[1024];
    struct binder_write_read bwr;
    struct binder_transaction_data *txn;
    
    /* Build SVC_MGR_CHECK_SERVICE transaction */
    uint32_t *p = (uint32_t*)writebuf;
    *p++ = BC_TRANSACTION;
    
    txn = (struct binder_transaction_data *)p;
    memset(txn, 0, sizeof(*txn));
    txn->target.handle = 0; /* servicemanager */
    txn->code = 2; /* CHECK_SERVICE */
    txn->flags = 0;
    
    /* Build Parcel: strict_mode(4) + interface_token(4+4+str16+pad) + service_name(4+4+str16) */
    unsigned char parcel[512];
    int plen = 0;
    int namelen = strlen(name);
    
    /* Strict mode policy */
    *(int32_t*)(parcel + plen) = 0; plen += 4;
    
    /* Interface token: "android.os.IServiceManager" */
    const char *iface = "android.os.IServiceManager";
    int ifacelen = strlen(iface);
    *(int32_t*)(parcel + plen) = ifacelen; plen += 4;
    for (int i = 0; i <= ifacelen; i++) {
        *(uint16_t*)(parcel + plen) = (uint16_t)iface[i]; plen += 2;
    }
    if (plen % 4) plen += 4 - (plen % 4);
    
    /* Service name */
    *(int32_t*)(parcel + plen) = namelen; plen += 4;
    for (int i = 0; i <= namelen; i++) {
        *(uint16_t*)(parcel + plen) = (uint16_t)name[i]; plen += 2;
    }
    if (plen % 4) plen += 4 - (plen % 4);
    
    txn->data_size = plen;
    txn->offsets_size = 0;
    txn->data.ptr.buffer = parcel;
    txn->data.ptr.offsets = NULL;
    
    p = (uint32_t*)((char*)txn + sizeof(*txn));
    int wlen = (char*)p - (char*)writebuf;
    
    bwr.write_buffer = (unsigned long)writebuf;
    bwr.write_size = wlen;
    bwr.write_consumed = 0;
    bwr.read_buffer = (unsigned long)readbuf;
    bwr.read_size = sizeof(readbuf);
    bwr.read_consumed = 0;
    
    if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
        return -1;
    
    /* Parse reply for handle */
    unsigned char *rp = readbuf;
    unsigned char *rend = readbuf + bwr.read_consumed;
    
    while (rp < rend) {
        uint32_t cmd = *(uint32_t*)rp;
        rp += 4;
        
        if (cmd == BR_NOOP || cmd == BR_TRANSACTION_COMPLETE) {
            continue;
        }
        if (cmd == BR_REPLY) {
            struct binder_transaction_data *reply = (struct binder_transaction_data *)rp;
            if (reply->data_size >= 16) {
                /* Parse flat_binder_object from reply parcel */
                unsigned char *data = (unsigned char *)reply->data.ptr.buffer;
                /* Reply parcel: exception(4) + type(4) + flags(4) + handle(4) */
                int32_t exception = *(int32_t*)(data + 0);
                if (exception == 0 && reply->data_size >= 16) {
                    /* Look for handle in the parcel data */
                    uint32_t type = *(uint32_t*)(data + 4);
                    if (type == 0x73622A85) { /* BINDER_TYPE_HANDLE */
                        uint32_t handle = *(uint32_t*)(data + 12);
                        return handle;
                    }
                }
            }
            rp += sizeof(*reply);
            continue;
        }
        break;
    }
    return -1;
}

/* Call a service method and print the reply */
static int call_service(int fd, uint32_t handle, uint32_t code,
                       const char *iface_token,
                       const unsigned char *extra_data, int extra_len,
                       unsigned char *reply_data, int *reply_len) {
    unsigned char writebuf[1024];
    unsigned char readbuf[4096];
    struct binder_write_read bwr;
    struct binder_transaction_data *txn;
    
    uint32_t *p = (uint32_t*)writebuf;
    *p++ = BC_TRANSACTION;
    
    txn = (struct binder_transaction_data *)p;
    memset(txn, 0, sizeof(*txn));
    txn->target.handle = handle;
    txn->code = code;
    txn->flags = 0;
    
    /* Build parcel */
    unsigned char parcel[1024];
    int plen = 0;
    
    /* Strict mode */
    *(int32_t*)(parcel + plen) = 0; plen += 4;
    
    /* Interface token */
    if (iface_token) {
        int toklen = strlen(iface_token);
        *(int32_t*)(parcel + plen) = toklen; plen += 4;
        for (int i = 0; i <= toklen; i++) {
            *(uint16_t*)(parcel + plen) = (uint16_t)iface_token[i]; plen += 2;
        }
        if (plen % 4) plen += 4 - (plen % 4);
    }
    
    /* Extra data */
    if (extra_data && extra_len > 0) {
        memcpy(parcel + plen, extra_data, extra_len);
        plen += extra_len;
    }
    
    txn->data_size = plen;
    txn->offsets_size = 0;
    txn->data.ptr.buffer = parcel;
    txn->data.ptr.offsets = NULL;
    
    p = (uint32_t*)((char*)txn + sizeof(*txn));
    int wlen = (char*)p - (char*)writebuf;
    
    bwr.write_buffer = (unsigned long)writebuf;
    bwr.write_size = wlen;
    bwr.write_consumed = 0;
    bwr.read_buffer = (unsigned long)readbuf;
    bwr.read_size = sizeof(readbuf);
    bwr.read_consumed = 0;
    
    if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
        return -errno;
    }
    
    /* Parse reply */
    unsigned char *rp = readbuf;
    unsigned char *rend = readbuf + bwr.read_consumed;
    
    while (rp < rend) {
        uint32_t cmd = *(uint32_t*)rp;
        rp += 4;
        
        if (cmd == BR_NOOP || cmd == BR_TRANSACTION_COMPLETE) continue;
        
        if (cmd == BR_REPLY) {
            struct binder_transaction_data *reply = (struct binder_transaction_data *)rp;
            if (reply->data_size > 0 && reply_data) {
                int cplen = reply->data_size;
                if (cplen > *reply_len) cplen = *reply_len;
                memcpy(reply_data, (void*)reply->data.ptr.buffer, cplen);
                *reply_len = cplen;
            } else {
                *reply_len = 0;
            }
            return reply->data_size;
        }
        break;
    }
    *reply_len = 0;
    return -1;
}

static void hex_dump(const unsigned char *data, int len) {
    for (int i = 0; i < len && i < 128; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n");
}

static void print_parcel_strings(const unsigned char *data, int len) {
    /* Try to extract String16 values from parcel data */
    int i = 0;
    while (i + 4 <= len) {
        int32_t slen = *(int32_t*)(data + i);
        if (slen > 0 && slen < 256 && i + 4 + (slen + 1) * 2 <= len) {
            char str[512];
            int valid = 1;
            for (int j = 0; j < slen; j++) {
                uint16_t c = *(uint16_t*)(data + i + 4 + j * 2);
                if (c >= 32 && c < 127) {
                    str[j] = (char)c;
                } else if (c == 0 && j == slen) {
                    str[j] = 0;
                } else {
                    valid = 0;
                    break;
                }
            }
            if (valid && slen > 0) {
                str[slen] = 0;
                printf("      String16@%d: \"%s\"\n", i, str);
                i += 4 + (slen + 1) * 2;
                if (i % 4) i += 4 - (i % 4);
                continue;
            }
        }
        i += 4;
    }
}

/* Probe a single service: find method count, dump interesting methods */
static void probe_service(int fd, const char *name, const char *iface) {
    printf("\n========================================\n");
    printf("SERVICE: %s\n", name);
    printf("INTERFACE: %s\n", iface);
    printf("========================================\n");
    
    int handle = get_service_handle(fd, name);
    if (handle < 0) {
        printf("  FAILED to get handle\n");
        return;
    }
    printf("  Handle: %d\n", handle);
    
    /* Binary search for method count */
    int lo = 1, hi = 100, max_method = 0;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        unsigned char reply[4096];
        int rlen = sizeof(reply);
        int ret = call_service(fd, handle, mid, iface, NULL, 0, reply, &rlen);
        if (rlen >= 4) {
            int32_t ex = *(int32_t*)reply;
            /* UNKNOWN_TRANSACTION returns specific error */
            if (ex == -1 || rlen == 0) {
                hi = mid - 1;
            } else {
                max_method = mid;
                lo = mid + 1;
            }
        } else {
            hi = mid - 1;
        }
    }
    
    if (max_method == 0) {
        /* Try methods 1-5 individually */
        for (int m = 1; m <= 5; m++) {
            unsigned char reply[4096];
            int rlen = sizeof(reply);
            int ret = call_service(fd, handle, m, iface, NULL, 0, reply, &rlen);
            if (rlen > 0) {
                max_method = m;
            }
        }
    }
    
    printf("  Methods found: up to %d\n", max_method);
    
    /* Probe each method */
    for (int m = 1; m <= max_method && m <= 20; m++) {
        unsigned char reply[4096];
        int rlen = sizeof(reply);
        int ret = call_service(fd, handle, m, iface, NULL, 0, reply, &rlen);
        printf("  Method %d: ret=%d, reply_len=%d\n", m, ret, rlen);
        if (rlen > 0) {
            printf("    Reply hex: ");
            hex_dump(reply, rlen);
            
            /* Check for known error codes */
            if (rlen >= 4) {
                int32_t ex = *(int32_t*)reply;
                if (ex == 0 && rlen > 4) {
                    printf("    *** SUCCESS (exception=0) ***\n");
                    if (rlen >= 8) {
                        int32_t val = *(int32_t*)(reply + 4);
                        printf("    First int32 after exception: %d (0x%x)\n", val, val);
                    }
                    print_parcel_strings(reply + 4, rlen - 4);
                } else if (ex == -1) {
                    printf("    Exception: SECURITY (-1)\n");
                } else if (ex < 0) {
                    printf("    Exception: %d (0x%08x)\n", ex, ex);
                }
            }
        }
    }
    
    /* For execute service, try calling with string arguments */
    if (strstr(name, "execute") != NULL) {
        printf("\n  --- EXECUTE service special probes ---\n");
        
        /* Try method 1 with string argument "id" */
        const char *cmds[] = {"id", "whoami", "ls /", "getprop", "cat /proc/version"};
        for (int c = 0; c < 5; c++) {
            unsigned char extra[256];
            int elen = 0;
            int cmdlen = strlen(cmds[c]);
            
            /* Write string16 */
            *(int32_t*)(extra + elen) = cmdlen; elen += 4;
            for (int i = 0; i <= cmdlen; i++) {
                *(uint16_t*)(extra + elen) = (uint16_t)cmds[c][i]; elen += 2;
            }
            if (elen % 4) elen += 4 - (elen % 4);
            
            for (int m = 1; m <= 5; m++) {
                unsigned char reply[4096];
                int rlen = sizeof(reply);
                int ret = call_service(fd, handle, m, iface, extra, elen, reply, &rlen);
                printf("  Execute method %d + cmd '%s': ret=%d, rlen=%d\n", m, cmds[c], ret, rlen);
                if (rlen > 0) {
                    printf("    Reply: ");
                    hex_dump(reply, rlen);
                    if (rlen >= 4) {
                        int32_t ex = *(int32_t*)reply;
                        if (ex == 0) {
                            printf("    *** COMMAND MAY HAVE SUCCEEDED! ***\n");
                            print_parcel_strings(reply + 4, rlen - 4);
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char **argv) {
    printf("=== Service Deep Probe ===\n");
    printf("UID=%d, PID=%d\n\n", getuid(), getpid());
    
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        perror("open /dev/binder");
        return 1;
    }
    
    /* mmap binder */
    void *mapped = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap binder");
        close(fd);
        return 1;
    }
    
    /* High-priority services to probe */
    struct {
        const char *name;
        const char *iface;
    } targets[] = {
        {"execute", "com.samsung.android.app.IExecuteManager"},
        {"usb", "android.hardware.usb.IUsbManager"},
        {"persistent_data_block", "android.service.persistentdata.IPersistentDataBlockService"},
        {"iccc", "android.service.iccc.IIcccManager"},
        {"sedenial", "android.service.ISEDenialService"},
        {"serial", "android.hardware.ISerialManager"},
        {"kiesusb", ""},
        {"ABTPersistenceService", "com.absolute.android.persistence.IABTPersistence"},
        {"tima", "android.service.tima.ITimaService"},
        {"remoteinjection", "android.app.enterprise.remotecontrol.IRemoteInjection"},
        {"mdm.remotedesktop", "mdm.samsung.IRemoteDesktopService"},
        {"DirEncryptService", "IDirEncryptService"},
        {"persona", "android.os.IPersonaManager"},
        {"dlp", "android.content.IDLPManager"},
        {"sdp", "com.sec.sdp.ISdpManagerService"},
        {NULL, NULL}
    };
    
    for (int i = 0; targets[i].name; i++) {
        probe_service(fd, targets[i].name, targets[i].iface);
    }
    
    munmap(mapped, 1024*1024);
    close(fd);
    
    printf("\n=== Done ===\n");
    return 0;
}
