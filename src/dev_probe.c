#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

int main(void) {
    const char *devs[] = {
        "/dev/ion",
        "/dev/mobicore-user",
        "/dev/mobicore",
        "/dev/binder",
        "/dev/ashmem",
        "/dev/mali0",
        "/dev/s5p-smem",
        "/dev/knox_kap",
        "/dev/alarm",
        "/dev/dek_req",
        "/dev/sdp_dlp",
        "/dev/sdp_mm",
        "/dev/tun",
        "/dev/uhid",
        "/dev/uinput",
        "/dev/xt_qtaguid",
        "/dev/random",
        "/dev/urandom",
        NULL
    };

    printf("PID=%d UID=%d\n\n", getpid(), getuid());
    for (int i = 0; devs[i]; i++) {
        int fd = open(devs[i], O_RDWR);
        if (fd >= 0) {
            printf("[+] %-25s OPEN (fd=%d)\n", devs[i], fd);
            close(fd);
        } else {
            int e = errno;
            /* Try read-only too */
            fd = open(devs[i], O_RDONLY);
            if (fd >= 0) {
                printf("[~] %-25s RDONLY (fd=%d, rdwr errno=%d: %s)\n", devs[i], fd, e, strerror(e));
                close(fd);
            } else {
                printf("[-] %-25s FAIL (rdwr=%d:%s, rdonly=%d:%s)\n",
                       devs[i], e, strerror(e), errno, strerror(errno));
            }
        }
    }
    return 0;
}
