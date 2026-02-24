#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

/* Binder Definitions */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version {
    signed long protocol_version;
};

struct binder_transaction_data {
    union {
        uint32_t handle;
        void *ptr;
    } target;
    void *cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct {
            const void *buffer;
            const void *offsets;
        } ptr;
        uint8_t buf8[8];
    } data;
};

struct flat_binder_object {
    uint32_t type;
    uint32_t flags;
    union {
        uint32_t binder;
        uint32_t handle;
    };
    uint32_t cookie;
};

#define BC_TRANSACTION      _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY            _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER      _IOW('c', 3, void *)

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
#define BR_FINISHED         _IO('r', 14)
#define BR_DEAD_BINDER      _IOR('r', 15, void *)
#define BR_CLEAR_DEATH_NOTIFICATION_DONE _IOR('r', 16, void *)
#define BR_FAILED_REPLY     _IO('r', 17)

#define TF_ACCEPT_FDS   0x10
#define BINDER_MMAP_SIZE (1024 * 1024)

#define BINDER_TYPE_HANDLE  0x73682a85
#define BINDER_TYPE_WEAK_HANDLE 0x77682a85
#define BINDER_TYPE_FD      0x66642a85

struct binder_ptr_cookie {
    void *ptr;
    void *cookie;
};

struct binder_pri_ptr_cookie {
    int32_t priority;
    void *ptr;
    void *cookie;
};

// Interface Token: "android.os.IServiceManager"
// UTF-16: a n d r o i d . o s . I S e r v i c e M a n a g e r
const uint16_t interface_token[] = {
    'a','n','d','r','o','i','d','.','o','s','.','I','S','e','r','v','i','c','e','M','a','n','a','g','e','r', 0
};

void write_string16(uint8_t **ptr, const char *str) {
    uint32_t len = strlen(str);
    *((uint32_t*)*ptr) = len; *ptr += 4;
    for (uint32_t i=0; i<len; i++) {
        *((uint16_t*)*ptr) = (uint16_t)str[i]; *ptr += 2;
    }
    *((uint16_t*)*ptr) = 0; *ptr += 2; // null term
    while (((unsigned long)*ptr) % 4) *ptr += 1;
}

void write_interface_token(uint8_t **ptr) {
    uint32_t len = sizeof(interface_token)/2 - 1; 
    *((uint32_t*)*ptr) = len; *ptr += 4;
    memcpy(*ptr, interface_token, sizeof(interface_token));
    *ptr += sizeof(interface_token); 
    while (((unsigned long)*ptr) % 4) *ptr += 1;
}

void *g_binder_mmap = NULL;

int get_service_handle(int fd, const char *service_name) {
    uint8_t wbuf[1024];
    uint8_t rbuf[1024];
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));

    uint8_t tdata[512];
    uint8_t *ptr = tdata;
    struct binder_transaction_data td;

    for (int code = 1; code <= 3; code++) {
        printf("[*] Trying transaction code %d...\n", code);

        memset(&bwr, 0, sizeof(bwr));
        ptr = tdata;
        write_interface_token(&ptr);
        write_string16(&ptr, service_name);

        memset(&td, 0, sizeof(td));
        td.target.handle = 0; 
        td.code = code; 
        td.flags = 0; 
        td.data_size = ptr - tdata;
        td.data.ptr.buffer = tdata;
        td.offsets_size = 0;

        uint32_t cmd = BC_TRANSACTION;
        uint8_t *wptr = wbuf;
        memcpy(wptr, &cmd, 4); wptr += 4;
        memcpy(wptr, &td, sizeof(td)); wptr += sizeof(td);

        bwr.write_buffer = (unsigned long)wbuf;
        bwr.write_size = wptr - wbuf;
        bwr.read_buffer = (unsigned long)rbuf;
        bwr.read_size = sizeof(rbuf);

        int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            perror("BINDER_WRITE_READ");
            continue;
        }

        printf("    bwr.write_consumed=%ld, bwr.read_consumed=%ld\n", bwr.write_consumed, bwr.read_consumed);
        
        if (bwr.read_consumed == 0) continue;

        uint8_t *rptr = rbuf;
        uint8_t *rend = rbuf + bwr.read_consumed;

        while (rptr < rend) {
            uint32_t rcmd = *((uint32_t*)rptr); rptr += 4;
            printf("    Read cmd: 0x%x\n", rcmd);
            
            if (rcmd == BR_NOOP || rcmd == BR_TRANSACTION_COMPLETE || rcmd == BR_SPAWN_LOOPER || rcmd == BR_FINISHED) {
                continue;
            } else if (rcmd == BR_REPLY) {
                struct binder_transaction_data *tr = (struct binder_transaction_data*)rptr;
                rptr += sizeof(struct binder_transaction_data);
                printf("    BR_REPLY: offsets_size=%d\n", tr->offsets_size);
                
                if (tr->offsets_size >= 4) {
                     uint32_t *offsets = (uint32_t *)(tr->data.ptr.offsets);
                     int num_offsets = tr->offsets_size / sizeof(uint32_t);
                     uint8_t *data_ptr = (uint8_t*)(tr->data.ptr.buffer);
                     
                     for (int i=0; i<num_offsets; i++) {
                         struct flat_binder_object *obj = (struct flat_binder_object*)(data_ptr + offsets[i]);
                         printf("    Object type: 0x%x\n", obj->type);
                         if (obj->type == BINDER_TYPE_HANDLE) {
                             return obj->handle;
                         }
                     }
                }
                return -2;
            } else if (rcmd == BR_DEAD_REPLY || rcmd == BR_FAILED_REPLY) {
                printf("    BR_DEAD/FAILED_REPLY\n");
                return -3;
            } else if (rcmd == BR_INCREFS || rcmd == BR_ACQUIRE || rcmd == BR_RELEASE || rcmd == BR_DECREFS) {
                rptr += sizeof(struct binder_ptr_cookie);
            } else if (rcmd == BR_ATTEMPT_ACQUIRE) {
                rptr += sizeof(struct binder_pri_ptr_cookie);
            } else if (rcmd == BR_DEAD_BINDER || rcmd == BR_CLEAR_DEATH_NOTIFICATION_DONE) {
                rptr += sizeof(void*);
            } else {
                 printf("    Unknown cmd: 0x%x\n", rcmd);
                 break;
            }
        }
    }
    return -4; 
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <service_name>\n", argv[0]);
        return 0;
    }

    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    g_binder_mmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (g_binder_mmap == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    struct binder_version ver;
    ioctl(fd, BINDER_VERSION, &ver);
    printf("Binder version: %ld\n", ver.protocol_version);

    int handle = get_service_handle(fd, argv[1]);
    if (handle >= 0) {
        printf("Found service '%s' -> Handle %d\n", argv[1], handle);
    } else {
        printf("Failed to get service '%s' (err=%d)\n", argv[1], handle);
    }
    return 0;
}
