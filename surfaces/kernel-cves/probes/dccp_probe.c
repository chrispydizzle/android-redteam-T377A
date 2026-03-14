#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <linux/netlink.h>

#define IPPROTO_DCCP 33
#define SOCK_DCCP 6

int main() {
    int fd;
    char buf[256];
    
    /* Show our SELinux context */
    int ctx_fd = open("/proc/self/attr/current", O_RDONLY);
    if (ctx_fd >= 0) {
        int n = read(ctx_fd, buf, sizeof(buf)-1);
        if (n > 0) { buf[n] = 0; printf("SELinux: %s\n", buf); }
        close(ctx_fd);
    }
    
    printf("UID=%d PID=%d\n", getuid(), getpid());
    
    /* Test 1: DCCP IPv4 */
    fd = socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP);
    printf("DCCP IPv4: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) {
        printf("*** DCCP SOCKET CREATED! CVE-2017-8890 VIABLE! ***\n");
        close(fd);
    }
    
    /* Test 2: DCCP IPv6 */
    errno = 0;
    fd = socket(AF_INET6, SOCK_DCCP, IPPROTO_DCCP);
    printf("DCCP IPv6: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) {
        printf("*** DCCP6 SOCKET CREATED! ***\n");
        close(fd);
    }
    
    /* Test 3: Raw socket (for comparison) */
    errno = 0;
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_DCCP);
    printf("RAW DCCP: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) close(fd);
    
    /* Test 4: MobiCore access */
    errno = 0;
    fd = open("/dev/mobicore-user", O_RDWR);
    printf("MobiCore: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) {
        printf("*** MOBICORE ACCESS! TIMA BYPASS POSSIBLE! ***\n");
        close(fd);
    }
    
    /* Test 5: property_service socket */
    errno = 0;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, "/dev/socket/property_service");
        int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
        printf("property_service: connect=%d errno=%d (%s)\n", rc, errno, rc<0?strerror(errno):"OK");
        close(fd);
    }
    
    /* Test 6: NETLINK_KOBJECT_UEVENT */
    errno = 0;
    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    printf("NETLINK_UEVENT: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) close(fd);
    
    /* Test 7: Can we read /data/system files? */
    errno = 0;
    fd = open("/data/system/packages.xml", O_RDONLY);
    printf("packages.xml: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) {
        int n = read(fd, buf, 100);
        printf("  read %d bytes\n", n);
        close(fd);
    }
    
    /* Test 8: /efs/FactoryApp access */
    errno = 0;
    fd = open("/efs/FactoryApp/serial_no", O_RDONLY);
    printf("/efs/serial_no: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) {
        int n = read(fd, buf, sizeof(buf)-1);
        if (n > 0) { buf[n] = 0; printf("  content: %s\n", buf); }
        close(fd);
    }

    /* Test 9: /dev/block/param access */
    errno = 0;
    fd = open("/dev/block/param", O_RDONLY);
    printf("PARAM block: fd=%d errno=%d (%s)\n", fd, errno, fd<0?strerror(errno):"OK");
    if (fd >= 0) {
        int n = read(fd, buf, 64);
        printf("  read %d bytes, first 4: %02x %02x %02x %02x\n", n,
               (unsigned char)buf[0], (unsigned char)buf[1],
               (unsigned char)buf[2], (unsigned char)buf[3]);
        close(fd);
    }

    return 0;
}
