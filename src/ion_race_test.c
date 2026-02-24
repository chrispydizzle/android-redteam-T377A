#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>

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

#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP     _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT  _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)

/* Safe heaps: 0 (System), 1 (System Contig), 4 (Safe?) - avoiding heap 2 */
#define ION_HEAP_SYSTEM_MASK (1 << 0)
#define ION_HEAP_SYSTEM_CONTIG_MASK (1 << 1)
#define ION_HEAP_TYPE_4_MASK (1 << 4)
#define TARGET_HEAPS (ION_HEAP_SYSTEM_MASK | ION_HEAP_SYSTEM_CONTIG_MASK | ION_HEAP_TYPE_4_MASK)

#define POOL_SIZE 64
#define NUM_THREADS 8

/* Shared state */
int ion_fd;
atomic_int handle_pool[POOL_SIZE];
volatile int g_stop = 0;

void *worker_thread(void *arg) {
    unsigned int seed = time(NULL) ^ (unsigned long)pthread_self();
    struct ion_allocation_data alloc_data;
    struct ion_handle_data handle_data;
    struct ion_fd_data fd_data;
    int op, idx, ret;
    ion_user_handle_t h;

    while (!g_stop) {
        /* Tight loop, random operations */
        op = rand_r(&seed) % 5;
        idx = rand_r(&seed) % POOL_SIZE;
        
        h = atomic_load(&handle_pool[idx]);

        switch (op) {
            case 0: /* ALLOC */
                if (h != 0) continue; /* Slot occupied (maybe) */
                
                memset(&alloc_data, 0, sizeof(alloc_data));
                alloc_data.len = 4096;
                alloc_data.align = 4096;
                alloc_data.heap_id_mask = TARGET_HEAPS;
                alloc_data.flags = 0;
                
                ret = ioctl(ion_fd, ION_IOC_ALLOC, &alloc_data);
                if (ret == 0) {
                    /* Store only if slot is still empty-ish. */
                    ion_user_handle_t expected = 0;
                    if (!atomic_compare_exchange_strong(&handle_pool[idx], &expected, alloc_data.handle)) {
                        /* Slot taken in meantime, free our new handle immediately */
                        handle_data.handle = alloc_data.handle;
                        ioctl(ion_fd, ION_IOC_FREE, &handle_data);
                    }
                }
                break;

            case 1: /* FREE */
                if (h == 0) continue;
                
                if ((rand_r(&seed) % 2) == 0) {
                     /* Just Free (Double free possible, Use-after-free possible) */
                     handle_data.handle = h;
                     ioctl(ion_fd, ION_IOC_FREE, &handle_data);
                } else {
                     /* Claim and Free */
                     h = atomic_exchange(&handle_pool[idx], 0);
                     if (h != 0) {
                         handle_data.handle = h;
                         ioctl(ion_fd, ION_IOC_FREE, &handle_data);
                     }
                }
                break;

            case 2: /* SHARE */
                if (h == 0) continue;
                fd_data.handle = h;
                ret = ioctl(ion_fd, ION_IOC_SHARE, &fd_data);
                if (ret == 0 && fd_data.fd >= 0) close(fd_data.fd);
                break;

            case 3: /* MAP */
                if (h == 0) continue;
                fd_data.handle = h;
                ret = ioctl(ion_fd, ION_IOC_MAP, &fd_data);
                if (ret == 0 && fd_data.fd >= 0) close(fd_data.fd);
                break;

            case 4: /* IMPORT */
                if (h == 0) continue;
                
                fd_data.handle = h;
                ret = ioctl(ion_fd, ION_IOC_SHARE, &fd_data);
                if (ret == 0 && fd_data.fd >= 0) {
                    int shared_fd = fd_data.fd;
                    
                    struct ion_fd_data import_data;
                    import_data.fd = shared_fd;
                    import_data.handle = 0;
                    
                    ret = ioctl(ion_fd, ION_IOC_IMPORT, &import_data);
                    if (ret == 0) {
                        /* We got a new handle. Put it in a random slot? */
                        int target = rand_r(&seed) % POOL_SIZE;
                        ion_user_handle_t old = atomic_exchange(&handle_pool[target], import_data.handle);
                        if (old != 0) {
                            /* If we evicted a handle, free it */
                            handle_data.handle = old;
                            ioctl(ion_fd, ION_IOC_FREE, &handle_data);
                        }
                    }
                    close(shared_fd);
                }
                break;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    pthread_t threads[NUM_THREADS];
    int i;

    ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) {
        perror("open /dev/ion");
        return 1;
    }

    printf("[+] ION Chaos Mode (8 threads, safe heaps, pool=%d)...\n", POOL_SIZE);

    /* Initialize pool */
    for (i = 0; i < POOL_SIZE; i++) atomic_init(&handle_pool[i], 0);

    for (i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }

    /* Run for 30 seconds */
    for (i = 0; i < 30; i++) {
        sleep(1);
        printf(".");
        fflush(stdout);
    }
    printf("\n");

    g_stop = 1;
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("[+] Done.\n");
    close(ion_fd);
    return 0;
}
