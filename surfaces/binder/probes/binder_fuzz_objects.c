#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <time.h>

/* Binder Definitions for 32-bit ARM (Android 6.0 kernel 3.10) */

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

#define BINDER_TYPE_BINDER  0x73622a85
#define BINDER_TYPE_WEAK_BINDER 0x77622a85
#define BINDER_TYPE_HANDLE  0x73682a85
#define BINDER_TYPE_WEAK_HANDLE 0x77682a85
#define BINDER_TYPE_FD      0x66642a85

#define BC_TRANSACTION      _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY            _IOW('c', 1, struct binder_transaction_data)

#define TF_ONE_WAY      0x01
#define TF_ROOT_OBJECT  0x04
#define TF_STATUS_CODE  0x08
#define TF_ACCEPT_FDS   0x10

#define BINDER_MMAP_SIZE (1024 * 1024)

void *g_binder_mmap = NULL;

uint32_t rnd32() {
    return (uint32_t)rand();
}

void op_transaction_objects(int fd) {
    uint8_t wbuf[4096];
    int wlen = 0;
    uint32_t cmd = BC_TRANSACTION;
    memcpy(wbuf, &cmd, 4); wlen += 4;

    struct binder_transaction_data td;
    memset(&td, 0, sizeof(td));

    // Target a valid handle (1-100)
    td.target.handle = 1 + (rnd32() % 50);
    td.code = rnd32();
    td.flags = TF_ONE_WAY; 
    if (rnd32() % 2) td.flags |= TF_ACCEPT_FDS;

    // Construct data with objects
    uint8_t tdata[1024];
    uint32_t toffsets[64]; // max 64 objects
    memset(tdata, 0, sizeof(tdata));
    memset(toffsets, 0, sizeof(toffsets));

    int num_objects = rnd32() % 5; // 0-4 objects
    if (num_objects == 0 && (rnd32() % 2)) num_objects = 1;

    int current_data_offset = 0;
    int current_obj_idx = 0;

    for (int i = 0; i < num_objects; i++) {
        // Add some random data before object?
        int pad = rnd32() % 16;
        current_data_offset += pad;
        if (current_data_offset + sizeof(struct flat_binder_object) > sizeof(tdata)) break;

        // Record offset
        toffsets[current_obj_idx] = current_data_offset;

        struct flat_binder_object *obj = (struct flat_binder_object*)(tdata + current_data_offset);
        
        int type_pick = rnd32() % 3;
        if (type_pick == 0) {
            obj->type = BINDER_TYPE_BINDER;
            obj->binder = rnd32(); // Random pointer (will likely be rejected or crash)
            obj->cookie = rnd32();
        } else if (type_pick == 1) {
            obj->type = BINDER_TYPE_HANDLE;
            obj->handle = rnd32() % 100; // Point to another handle
            obj->cookie = 0;
        } else {
            obj->type = BINDER_TYPE_FD;
            // Try stdin/stdout/stderr or random fd
            obj->handle = (rnd32() % 2) ? (rnd32() % 10) : fd; 
            obj->cookie = (rnd32() % 2); // 1 = close on free?
        }
        
        current_data_offset += sizeof(struct flat_binder_object);
        current_obj_idx++;
    }

    // Fill remaining data with garbage
    if (current_data_offset < sizeof(tdata)) {
        int fill = sizeof(tdata) - current_data_offset;
        for (int k=0; k<fill; k++) tdata[current_data_offset+k] = (uint8_t)rand();
    }
    
    td.data_size = sizeof(tdata); // Sending full buffer
    // Or send only used part? Let's send random size up to 1024
    td.data_size = (current_data_offset > 0) ? (current_data_offset + (rnd32() % 100)) : (rnd32() % 256);
    if (td.data_size > sizeof(tdata)) td.data_size = sizeof(tdata);

    td.offsets_size = current_obj_idx * 4;
    
    // Maybe corrupt offsets_size?
    if (rnd32() % 100 < 5) td.offsets_size = rnd32() % 256;

    td.data.ptr.buffer = tdata;
    td.data.ptr.offsets = toffsets;

    memcpy(wbuf + wlen, &td, sizeof(td)); wlen += sizeof(td);

    // Binder write read
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = wlen;
    bwr.write_consumed = 0;
    bwr.write_buffer = (unsigned long)wbuf;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;

    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0 && errno != EINVAL) {
        // perror("BINDER_WRITE_READ");
    }
}

int main(int argc, char **argv) {
    srand(time(NULL));
    int iters = (argc > 1) ? atoi(argv[1]) : 1000;

    printf("[*] Opening /dev/binder...\n");
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    g_binder_mmap = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (g_binder_mmap == MAP_FAILED) {
        perror("mmap");
        // continue anyway
    }

    struct binder_version ver;
    ioctl(fd, BINDER_VERSION, &ver);
    printf("[+] Binder version: %ld\n", ver.protocol_version);

    printf("[*] Fuzzing %d object transactions...\n", iters);
    for (int i=0; i<iters; i++) {
        op_transaction_objects(fd);
        if (i % 100 == 0) printf(".");
        if (i % 1000 == 0) fsync(fd);
    }
    printf("\n[+] Done.\n");
    return 0;
}
