#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

int test_stream(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -errno;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    int e = errno;
    close(fd);
    return rc == 0 ? 1 : -e;
}

int main() {
    char buf[256];
    int ctx_fd = open("/proc/self/attr/current", O_RDONLY);
    if (ctx_fd >= 0) {
        int n = read(ctx_fd, buf, sizeof(buf)-1);
        if (n > 0) { buf[n] = 0; printf("SELinux: %s\n", buf); }
        close(ctx_fd);
    }
    printf("UID=%d PID=%d\n\n", getuid(), getpid());

    const char *socks[] = {
        "/dev/socket/dnsproxyd",
        "/dev/socket/fwmarkd",
        "/dev/socket/netd",
        "/dev/socket/installd",
        "/dev/socket/vold",
        "/dev/socket/zygote",
        "/dev/socket/cryptd",
        "/dev/socket/lmkd",
        "/dev/socket/ppm",
        "/dev/socket/epm",
        "/dev/socket/frigate",
        "/dev/socket/rild",
        "/dev/socket/rild-debug",
        "/dev/socket/rild-cas",
        "/dev/socket/imsd",
        "/dev/socket/sdp",
        "/dev/socket/adbd",
        "/dev/socket/property_service",
        "/dev/socket/dir_enc_report",
        "/dev/socket/mdns",
        "/dev/socket/sme_socket",
        "/data/.socket_stream",
        "/data/.diagsocket_stream",
        "/data/.consocket_stream",
        NULL
    };

    for (int i = 0; socks[i]; i++) {
        int r = test_stream(socks[i]);
        const char *s;
        if (r > 0) s = "*** CONNECTED ***";
        else if (r == -13) s = "EPERM";
        else if (r == -111) s = "CONNREFUSED";
        else if (r == -2) s = "ENOENT";
        else s = strerror(-r);
        printf("%-40s %s\n", socks[i], s);
    }
    return 0;
}
