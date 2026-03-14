#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, size_t)
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

#define BC_TRANSACTION      _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY            _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER      _IOW('c', 3, void *)
#define BC_INCREFS          _IOW('c', 4, uint32_t)
#define BC_ACQUIRE          _IOW('c', 5, uint32_t)
#define BC_RELEASE          _IOW('c', 6, uint32_t)
#define BC_DECREFS          _IOW('c', 7, uint32_t)
#define BC_ENTER_LOOPER     _IO('c', 12)
#define BC_EXIT_LOOPER      _IO('c', 13)

#define TF_ONE_WAY      0x01
#define BINDER_MMAP_SIZE (1024 * 1024)

static volatile sig_atomic_t g_stop = 0;

static __thread uint64_t rng_state = 0;

static void seed_rng(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rng_state = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec ^ (uint64_t)syscall(SYS_gettid);
}

static uint32_t rnd32(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return (uint32_t)x;
}

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

void *worker_thread(void *arg) {
    seed_rng();
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return NULL;

    // Map memory (required for binder to work)
    void *vm = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (vm == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    // Tell driver we are entering looper
    // ioctl(fd, BC_ENTER_LOOPER, 0); // Not ioctl, it's a command in BINDER_WRITE_READ
    // Actually BC_ENTER_LOOPER is sent via BINDER_WRITE_READ

    uint8_t wbuf[1024];
    struct binder_write_read bwr;
    struct binder_transaction_data td;
    uint32_t cmd;

    while (!g_stop) {
        int num_cmds = (rnd32() % 10) + 1; // 1 to 10 commands per ioctl
        uint8_t *ptr = wbuf;
        
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_buffer = (unsigned long)wbuf;

        for (int i = 0; i < num_cmds; i++) {
            if ((ptr - wbuf) > (sizeof(wbuf) - sizeof(struct binder_transaction_data) - 8)) break;

            int op = rnd32() % 10;
            if (op < 4) {
            // Random transaction
            cmd = BC_TRANSACTION;
            memset(&td, 0, sizeof(td));
            td.target.handle = rnd32() % 100; // Target random handles
            td.code = rnd32();
            td.flags = TF_ONE_WAY;
            td.data_size = 0;
            td.offsets_size = 0;
            
            memcpy(ptr, &cmd, 4); ptr += 4;
            memcpy(ptr, &td, sizeof(td)); ptr += sizeof(td);
        } else if (op < 6) {
            // Refcount ops
            cmd = (rnd32() % 2) ? BC_INCREFS : BC_ACQUIRE;
            uint32_t target = rnd32() % 100;
            memcpy(ptr, &cmd, 4); ptr += 4;
            memcpy(ptr, &target, 4); ptr += 4;
        } else if (op < 8) {
            // Release ops
            cmd = (rnd32() % 2) ? BC_DECREFS : BC_RELEASE;
            uint32_t target = rnd32() % 100;
            memcpy(ptr, &cmd, 4); ptr += 4;
            memcpy(ptr, &target, 4); ptr += 4;
        } else {
             // Loopers
             cmd = (rnd32() % 2) ? BC_ENTER_LOOPER : BC_EXIT_LOOPER;
             memcpy(ptr, &cmd, 4); ptr += 4;
        }

        }
        
        bwr.write_size = ptr - wbuf;
        bwr.write_consumed = 0;
        bwr.read_size = 0;

        ioctl(fd, BINDER_WRITE_READ, &bwr);
        
        // Yield occasionally
        if ((rnd32() % 100) == 0) usleep(1000);
    }
    
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    int num_threads = 8;
    int duration = 30;
    
    if (argc >= 2) duration = atoi(argv[1]);
    if (argc >= 3) num_threads = atoi(argv[2]);

    signal(SIGINT, on_sigint);
    printf("[*] Starting Binder Multithreaded Fuzzer (%d threads, %ds)...\n", num_threads, duration);

    pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
    for (int i=0; i<num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }

    sleep(duration);
    g_stop = 1;

    for (int i=0; i<num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("[*] Done.\n");
    return 0;
}
