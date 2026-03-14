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

/* ION definitions */
typedef int ion_user_handle_t;

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    ion_user_handle_t handle;
};

struct ion_fd_data {
    ion_user_handle_t handle;
    int fd;
};

struct ion_handle_data {
    ion_user_handle_t handle;
};

struct ion_custom_data {
    unsigned int cmd;
    unsigned long arg;
};

#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP     _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT  _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
#define ION_IOC_SYNC    _IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)
#define ION_IOC_CUSTOM  _IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

#define ION_FLAG_CACHED             1
#define ION_FLAG_CACHED_NEEDS_SYNC  2
#define ION_FLAG_NOZEROED           8
#define ION_FLAG_PROTECTED          16
#define ION_FLAG_SYNC_FORCE         32

/* Exynos custom ioctl */
#define ION_IOC_EXYNOS_MAGIC 'E'
#define ION_EXYNOS_SYNC_BY_HANDLE 0x01
#define ION_EXYNOS_SYNC_INV       0x10

struct ion_exynos_sync_data {
    int flags;
    union {
        int dmabuf_fd;
        ion_user_handle_t handle;
    };
    void *addr;
    size_t size;
};

#define ION_IOC_EXYNOS_SYNC _IOW(ION_IOC_EXYNOS_MAGIC, 0, struct ion_exynos_sync_data)

static volatile sig_atomic_t g_stop = 0;

/* Global shared state */
#define MAX_HANDLES 256
struct handle_entry {
    ion_user_handle_t handle;
    int share_fd;
    size_t len;
    int in_use;
    pthread_mutex_t lock;
};
static struct handle_entry g_handles[MAX_HANDLES];
static pthread_mutex_t g_global_lock = PTHREAD_MUTEX_INITIALIZER;

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

static int handles_add(ion_user_handle_t h, size_t len) {
    pthread_mutex_lock(&g_global_lock);
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (!g_handles[i].in_use) {
            pthread_mutex_lock(&g_handles[i].lock);
            g_handles[i].handle = h;
            g_handles[i].share_fd = -1;
            g_handles[i].len = len;
            g_handles[i].in_use = 1;
            pthread_mutex_unlock(&g_handles[i].lock);
            pthread_mutex_unlock(&g_global_lock);
            return i;
        }
    }
    
    // Evict random
    int j = rnd32() % MAX_HANDLES;
    pthread_mutex_lock(&g_handles[j].lock);
    if (g_handles[j].share_fd >= 0) close(g_handles[j].share_fd);
    // Note: We leak the old handle here if it wasn't freed, but that's fine for fuzzing
    g_handles[j].handle = h;
    g_handles[j].share_fd = -1;
    g_handles[j].len = len;
    g_handles[j].in_use = 1;
    pthread_mutex_unlock(&g_handles[j].lock);
    pthread_mutex_unlock(&g_global_lock);
    return j;
}

static int handles_pick(void) {
    // Just pick a random slot, doesn't matter if in use or not (adds noise)
    return rnd32() % MAX_HANDLES;
}

void *worker_thread(void *arg) {
    seed_rng();
    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) return NULL;

    while (!g_stop) {
        int op = rnd32() % 100;

        if (op < 30) { 
            // ALLOC
            struct ion_allocation_data data = {0};
            data.len = (rnd32() % 1024) * 4096;
            if (data.len == 0) data.len = 4096;
            data.align = 4096;
            
            // Safe heaps: 0 (system), 1 (noncontig), 4 (exynos_contig)
            // AVOID 2 (crash), 3 (unknown), 5+ (ENODEV)
            uint32_t hp = rnd32() % 3;
            if (hp == 0) data.heap_id_mask = (1 << 0);
            else if (hp == 1) data.heap_id_mask = (1 << 1);
            else data.heap_id_mask = (1 << 4);

            // Flags
            uint32_t fp = rnd32() % 10;
            if (fp < 5) data.flags = 0;
            else if (fp == 5) data.flags = ION_FLAG_CACHED;
            // Avoid ION_FLAG_PROTECTED to reduce log spam (WARN at ion.c:784)
            // else if (fp == 6) data.flags = ION_FLAG_PROTECTED;
            else data.flags = rnd32() & 0xFF;

            if (ioctl(fd, ION_IOC_ALLOC, &data) == 0) {
                handles_add(data.handle, data.len);
            }
        } else if (op < 50) {
            // FREE (Race candidate)
            int idx = handles_pick();
            ion_user_handle_t h = 0;
            
            pthread_mutex_lock(&g_handles[idx].lock);
            if (g_handles[idx].in_use) {
                h = g_handles[idx].handle;
                // Don't mark not-in-use yet, let other threads race on it
                if (rnd32() % 2 == 0) {
                    g_handles[idx].in_use = 0;
                    if (g_handles[idx].share_fd >= 0) {
                        close(g_handles[idx].share_fd);
                        g_handles[idx].share_fd = -1;
                    }
                }
            }
            pthread_mutex_unlock(&g_handles[idx].lock);

            if (h > 0) {
                struct ion_handle_data data = { .handle = h };
                ioctl(fd, ION_IOC_FREE, &data);
            }
        } else if (op < 70) {
            // SHARE (Race candidate)
            int idx = handles_pick();
            ion_user_handle_t h = 0;
            
            pthread_mutex_lock(&g_handles[idx].lock);
            if (g_handles[idx].in_use) h = g_handles[idx].handle;
            pthread_mutex_unlock(&g_handles[idx].lock);

            if (h > 0) {
                struct ion_fd_data data = { .handle = h };
                if (ioctl(fd, ION_IOC_SHARE, &data) == 0) {
                    pthread_mutex_lock(&g_handles[idx].lock);
                    if (g_handles[idx].in_use && g_handles[idx].handle == h) {
                        if (g_handles[idx].share_fd >= 0) close(g_handles[idx].share_fd);
                        g_handles[idx].share_fd = data.fd;
                    } else {
                        close(data.fd);
                    }
                    pthread_mutex_unlock(&g_handles[idx].lock);
                }
            }
        } else if (op < 80) {
            // IMPORT (Race candidate)
            int fd_to_import = -1;
            int idx = handles_pick();
            
            pthread_mutex_lock(&g_handles[idx].lock);
            if (g_handles[idx].in_use && g_handles[idx].share_fd >= 0) {
                fd_to_import = g_handles[idx].share_fd;
            }
            pthread_mutex_unlock(&g_handles[idx].lock);

            if (fd_to_import >= 0) {
                struct ion_fd_data data = { .fd = fd_to_import };
                if (ioctl(fd, ION_IOC_IMPORT, &data) == 0) {
                    handles_add(data.handle, 4096);
                }
            }
        } else if (op < 90) {
            // MAP & MMAP
            int idx = handles_pick();
            ion_user_handle_t h = 0;
            size_t len = 0;

            pthread_mutex_lock(&g_handles[idx].lock);
            if (g_handles[idx].in_use) {
                h = g_handles[idx].handle;
                len = g_handles[idx].len;
            }
            pthread_mutex_unlock(&g_handles[idx].lock);

            if (h > 0) {
                struct ion_fd_data data = { .handle = h };
                if (ioctl(fd, ION_IOC_MAP, &data) == 0) {
                    void *ptr = mmap(NULL, len ? len : 4096, PROT_READ|PROT_WRITE, MAP_SHARED, data.fd, 0);
                    if (ptr != MAP_FAILED) {
                        *(volatile char *)ptr = 0xCC;
                        munmap(ptr, len ? len : 4096);
                    }
                    close(data.fd);
                }
            }
        } else {
            // SYNC / CUSTOM
            int idx = handles_pick();
            int sfd = -1;
            
            pthread_mutex_lock(&g_handles[idx].lock);
            if (g_handles[idx].in_use && g_handles[idx].share_fd >= 0) {
                sfd = g_handles[idx].share_fd;
            }
            pthread_mutex_unlock(&g_handles[idx].lock);

            if (sfd >= 0) {
                struct ion_fd_data data = { .fd = sfd };
                ioctl(fd, ION_IOC_SYNC, &data);
                
                struct ion_exynos_sync_data esd = { .dmabuf_fd = sfd, .flags = 0 };
                struct ion_custom_data cd = { .cmd = ION_IOC_EXYNOS_SYNC, .arg = (unsigned long)&esd };
                ioctl(fd, ION_IOC_CUSTOM, &cd);
            }
        }
        
        // Yield occasionally
        if ((rnd32() % 1000) == 0) usleep(1000);
    }
    
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    int num_threads = 4;
    int duration = 30;
    
    if (argc >= 2) duration = atoi(argv[1]);
    if (argc >= 3) num_threads = atoi(argv[2]);

    signal(SIGINT, on_sigint);
    printf("[*] Starting ION Multithreaded Fuzzer (%d threads, %ds)...\n", num_threads, duration);
    
    // Init locks
    for (int i=0; i<MAX_HANDLES; i++) pthread_mutex_init(&g_handles[i].lock, NULL);

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
