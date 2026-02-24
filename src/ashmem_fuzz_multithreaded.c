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

/* Ashmem definitions */
#define __ASHMEMIOC 0x77
#define ASHMEM_NAME_LEN 256
#define ASHMEM_SET_NAME       _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME       _IOR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE       _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE       _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK  _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK  _IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN            _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN          _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)

struct ashmem_pin {
    uint32_t offset;
    uint32_t len;
};

static volatile sig_atomic_t g_stop = 0;

/* Global shared state */
#define MAX_FDS 16
static int g_fds[MAX_FDS];
static pthread_mutex_t g_locks[MAX_FDS];

static __thread uint64_t rng_state = 0;

static void seed_rng(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rng_state = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec ^ (uint64_t)syscall(SYS_gettid);
}

static uint32_t rnd32(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return (uint32_t)x;
}

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

void *worker_thread(void *arg) {
    seed_rng();
    
    while (!g_stop) {
        int idx = rnd32() % MAX_FDS;
        int fd = g_fds[idx];
        if (fd < 0) continue;

        int op = rnd32() % 100;
        
        // Randomly acquire lock (50% chance) to allow some races but prevent total chaos
        int locked = 0;
        if (rnd32() % 2 == 0) {
            pthread_mutex_lock(&g_locks[idx]);
            locked = 1;
        }

        if (op < 10) { // SET_NAME
            char name[ASHMEM_NAME_LEN];
            snprintf(name, sizeof(name), "fuzz_%u", rnd32());
            ioctl(fd, ASHMEM_SET_NAME, name);
        } else if (op < 20) { // SET_SIZE
            // Try to change size (only allowed before mmap)
            size_t sz = (rnd32() % 1024) * 4096;
            ioctl(fd, ASHMEM_SET_SIZE, sz);
        } else if (op < 30) { // SET_PROT
            ioctl(fd, ASHMEM_SET_PROT_MASK, rnd32() % 0xFF);
        } else if (op < 50) { // PIN
            struct ashmem_pin pin;
            pin.offset = 0;
            pin.len = 4096;
            ioctl(fd, ASHMEM_PIN, &pin);
        } else if (op < 70) { // UNPIN
            struct ashmem_pin pin;
            pin.offset = 0;
            pin.len = 4096;
            ioctl(fd, ASHMEM_UNPIN, &pin);
        } else if (op < 90) { // MMAP
            size_t len = 4096 * 4;
            void *ptr = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
            if (ptr != MAP_FAILED) {
                // Quick touch
                *(volatile char *)ptr = 0xAA;
                usleep(10); // Hold map briefly
                munmap(ptr, len);
            }
        } else { // PURGE
            ioctl(fd, ASHMEM_PURGE_ALL_CACHES, 0);
        }

        if (locked) pthread_mutex_unlock(&g_locks[idx]);
        
        // Occasional yield
        if ((rnd32() % 1000) == 0) usleep(100);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int num_threads = 8;
    int duration = 45;

    if (argc >= 2) duration = atoi(argv[1]);
    if (argc >= 3) num_threads = atoi(argv[2]);

    printf("[*] Opening %d shared Ashmem regions...\n", MAX_FDS);
    for (int i = 0; i < MAX_FDS; i++) {
        g_fds[i] = open("/dev/ashmem", O_RDWR);
        if (g_fds[i] < 0) perror("open ashmem");
        pthread_mutex_init(&g_locks[i], NULL);
        // Set initial size
        ioctl(g_fds[i], ASHMEM_SET_SIZE, 4096*16);
    }

    printf("[*] Starting Ashmem Multithreaded Fuzzer (%d threads, %ds)...\n", num_threads, duration);
    signal(SIGINT, on_sigint);

    pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }

    sleep(duration);
    g_stop = 1;

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("[*] Closing fds...\n");
    for (int i = 0; i < MAX_FDS; i++) {
        if (g_fds[i] >= 0) close(g_fds[i]);
    }

    printf("[*] Done.\n");
    return 0;
}
