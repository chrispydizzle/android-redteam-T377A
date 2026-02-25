/*
 * ion_slab_probe.c — Determine which kmalloc cache ion_handle uses
 * Since there's no ion_handle_cache, handles must be in generic kmalloc-*
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int ion_user_handle_t;
struct ion_allocation_data { size_t len; size_t align; unsigned int heap_id_mask; unsigned int flags; ion_user_handle_t handle; };
struct ion_fd_data { ion_user_handle_t handle; int fd; };
struct ion_handle_data { ion_user_handle_t handle; };
#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

struct slab_entry { char name[64]; long active; long total; long objsize; };

static int read_slabinfo(struct slab_entry *entries, int max) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return 0;
    char line[512];
    (void)fgets(line, sizeof(line), f);
    (void)fgets(line, sizeof(line), f);
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < max) {
        sscanf(line, "%63s %ld %ld %ld",
               entries[count].name, &entries[count].active,
               &entries[count].total, &entries[count].objsize);
        count++;
    }
    fclose(f);
    return count;
}

int main(void) {
    printf("=== ION Slab Cache Identification ===\n\n");

    int ion_fd = open("/dev/ion", O_RDONLY);
    if (ion_fd < 0) { perror("ion open"); return 1; }

    struct slab_entry before[200], after[200], after_free[200];
    int nb = read_slabinfo(before, 200);

    /* Allocate 200 ION handles */
    ion_user_handle_t handles[200];
    int count = 0;
    for (int i = 0; i < 200; i++) {
        struct ion_allocation_data alloc = {
            .len = 4096, .align = 4096,
            .heap_id_mask = 1, .flags = 0
        };
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) == 0) {
            handles[count++] = alloc.handle;
        } else break;
    }
    printf("Allocated %d ION handles\n", count);

    int na = read_slabinfo(after, 200);

    printf("\nSlab changes after %d ION allocs:\n", count);
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < na; j++) {
            if (strcmp(before[i].name, after[j].name) == 0) {
                long diff = after[j].active - before[i].active;
                if (diff >= 10) {
                    printf("  %-40s: %+ld (objsz=%ld)\n",
                           before[i].name, diff, before[i].objsize);
                }
                break;
            }
        }
    }

    /* Free all handles */
    for (int i = 0; i < count; i++) {
        struct ion_handle_data hd = { .handle = handles[i] };
        ioctl(ion_fd, ION_IOC_FREE, &hd);
    }

    int nf = read_slabinfo(after_free, 200);

    printf("\nSlab changes after ION free:\n");
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < nf; j++) {
            if (strcmp(before[i].name, after_free[j].name) == 0) {
                long diff = after_free[j].active - before[i].active;
                if (diff >= 10 || diff <= -10) {
                    printf("  %-40s: %+ld from baseline (objsz=%ld)\n",
                           before[i].name, diff, before[i].objsize);
                }
                break;
            }
        }
    }

    /* TEST 2: ION share creates dma_buf — check which slab */
    printf("\n--- dma_buf slab impact ---\n");
    nb = read_slabinfo(before, 200);

    int share_fds[100];
    ion_user_handle_t share_handles[100];
    int share_count = 0;
    for (int i = 0; i < 100; i++) {
        struct ion_allocation_data alloc = {
            .len = 4096, .align = 4096,
            .heap_id_mask = 1, .flags = 0
        };
        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) break;
        share_handles[i] = alloc.handle;

        struct ion_fd_data fd_data = { .handle = alloc.handle };
        if (ioctl(ion_fd, ION_IOC_SHARE, &fd_data) == 0) {
            share_fds[share_count] = fd_data.fd;
            share_count++;
        }
    }
    printf("Created %d shared dma_bufs\n", share_count);

    na = read_slabinfo(after, 200);

    printf("\nSlab changes after %d ION share:\n", share_count);
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < na; j++) {
            if (strcmp(before[i].name, after[j].name) == 0) {
                long diff = after[j].active - before[i].active;
                if (diff >= 10) {
                    printf("  %-40s: %+ld (objsz=%ld)\n",
                           before[i].name, diff, before[i].objsize);
                }
                break;
            }
        }
    }

    /* Close shared fds and free handles */
    for (int i = 0; i < share_count; i++)
        close(share_fds[i]);
    for (int i = 0; i < share_count; i++) {
        struct ion_handle_data hd = { .handle = share_handles[i] };
        ioctl(ion_fd, ION_IOC_FREE, &hd);
    }

    nf = read_slabinfo(after_free, 200);
    printf("\nAfter cleanup:\n");
    for (int i = 0; i < nb; i++) {
        for (int j = 0; j < nf; j++) {
            if (strcmp(before[i].name, after_free[j].name) == 0) {
                long diff = after_free[j].active - before[i].active;
                if (diff >= 10 || diff <= -10) {
                    printf("  %-40s: %+ld from baseline (objsz=%ld)\n",
                           before[i].name, diff, before[i].objsize);
                }
                break;
            }
        }
    }

    close(ion_fd);
    printf("\n=== Done ===\n");
    return 0;
}
