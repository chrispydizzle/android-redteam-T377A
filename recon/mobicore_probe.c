#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>

// MobiCore ioctl definitions (from mc_linux.h)
#define MC_IOC_MAGIC 'M'

// Standard MobiCore ioctls
#define MC_IO_INIT         _IOWR(MC_IOC_MAGIC, 0, int)
#define MC_IO_INFO         _IOWR(MC_IOC_MAGIC, 1, int)
#define MC_IO_VERSION      _IOR(MC_IOC_MAGIC, 2, unsigned int)
#define MC_IO_MAP          _IOWR(MC_IOC_MAGIC, 5, int)
#define MC_IO_UNMAP        _IOW(MC_IOC_MAGIC, 6, int)
#define MC_IO_ERR          _IOWR(MC_IOC_MAGIC, 7, int)
#define MC_IO_OPEN_SESSION _IOWR(MC_IOC_MAGIC, 10, int)
#define MC_IO_CLOSE_SESSION _IOW(MC_IOC_MAGIC, 11, int)
#define MC_IO_NOTIFY       _IOW(MC_IOC_MAGIC, 12, int)
#define MC_IO_WAIT         _IOW(MC_IOC_MAGIC, 13, int)
#define MC_IO_GP_INIT_SESSION _IOWR(MC_IOC_MAGIC, 14, int)

static void alarm_handler(int sig) { printf("[TIMEOUT]\n"); _exit(1); }

int main() {
    int fd, ret;
    unsigned int version = 0;

    signal(SIGALRM, alarm_handler);
    alarm(10);

    printf("=== MobiCore TEE Probe ===\n");

    // Try opening
    fd = open("/dev/mobicore-user", O_RDWR);
    if (fd < 0) {
        printf("OPEN FAILED: %s (errno=%d)\n", strerror(errno), errno);
        // Try mobicore without -user
        fd = open("/dev/mobicore", O_RDWR);
        if (fd < 0) {
            printf("OPEN /dev/mobicore also FAILED: %s\n", strerror(errno));
            return 1;
        }
        printf("Opened /dev/mobicore instead (fd=%d)\n", fd);
    } else {
        printf("OPEN SUCCESS: fd=%d\n", fd);
    }

    // Try version ioctl
    ret = ioctl(fd, MC_IO_VERSION, &version);
    printf("VERSION ioctl: ret=%d, version=0x%08x, errno=%d (%s)\n",
           ret, version, errno, strerror(errno));

    // Try info ioctl
    int info[16] = {0};
    ret = ioctl(fd, MC_IO_INFO, info);
    printf("INFO ioctl: ret=%d, errno=%d (%s)\n", ret, errno, strerror(errno));
    if (ret == 0) {
        printf("  info[0]=0x%x info[1]=0x%x info[2]=0x%x info[3]=0x%x\n",
               info[0], info[1], info[2], info[3]);
    }

    // Try init ioctl
    int init_arg = 0;
    ret = ioctl(fd, MC_IO_INIT, &init_arg);
    printf("INIT ioctl: ret=%d, errno=%d (%s)\n", ret, errno, strerror(errno));

    // Brute-force ioctl numbers 0-20
    printf("\n=== Brute-force ioctl scan ===\n");
    for (int i = 0; i <= 20; i++) {
        int arg[32] = {0};
        unsigned long cmd;

        // Try _IO (no data)
        cmd = _IO(MC_IOC_MAGIC, i);
        errno = 0;
        ret = ioctl(fd, cmd, arg);
        if (ret == 0 || (ret < 0 && errno != ENOTTY && errno != EINVAL)) {
            printf("  _IO('M', %d): ret=%d errno=%d (%s)\n", i, ret, errno, strerror(errno));
        }

        // Try _IOR (read)
        cmd = _IOR(MC_IOC_MAGIC, i, int[8]);
        errno = 0;
        ret = ioctl(fd, cmd, arg);
        if (ret == 0 || (ret < 0 && errno != ENOTTY && errno != EINVAL)) {
            printf("  _IOR('M', %d, 32): ret=%d errno=%d (%s)\n", i, ret, errno, strerror(errno));
        }

        // Try _IOW (write)
        cmd = _IOW(MC_IOC_MAGIC, i, int[8]);
        errno = 0;
        ret = ioctl(fd, cmd, arg);
        if (ret == 0 || (ret < 0 && errno != ENOTTY && errno != EINVAL)) {
            printf("  _IOW('M', %d, 32): ret=%d errno=%d (%s)\n", i, ret, errno, strerror(errno));
        }

        // Try _IOWR (read/write)
        cmd = _IOWR(MC_IOC_MAGIC, i, int[8]);
        errno = 0;
        ret = ioctl(fd, cmd, arg);
        if (ret == 0 || (ret < 0 && errno != ENOTTY && errno != EINVAL)) {
            printf("  _IOWR('M', %d, 32): ret=%d errno=%d (%s)\n", i, ret, errno, strerror(errno));
        }
    }

    // Try reading
    char buf[256] = {0};
    ret = read(fd, buf, sizeof(buf));
    printf("\nREAD: ret=%d, errno=%d (%s)\n", ret, errno, strerror(errno));

    // Try mmap
    void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    printf("MMAP: %s\n", p == MAP_FAILED ? "FAILED" : "SUCCESS");
    if (p != MAP_FAILED) {
        printf("  First 16 bytes: ");
        for (int i = 0; i < 16; i++) printf("%02x ", ((unsigned char*)p)[i]);
        printf("\n");
        munmap(p, 4096);
    }

    close(fd);
    printf("\nDone.\n");
    return 0;
}
