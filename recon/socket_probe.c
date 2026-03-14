#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>

int try_connect(const char *name) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    
    // Abstract socket - first byte is \0
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name, sizeof(addr.sun_path) - 2);
    
    int len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name);
    int ret = connect(fd, (struct sockaddr*)&addr, len);
    if (ret < 0) {
        printf("  connect(%s): FAILED (errno=%d: %s)\n", name, errno, strerror(errno));
        close(fd);
        return -1;
    }
    printf("  connect(%s): SUCCESS! fd=%d\n", name, fd);
    
    // Try to read a greeting
    char buf[256];
    fd_set rfds;
    struct timeval tv = {1, 0};
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    if (select(fd+1, &rfds, NULL, NULL, &tv) > 0) {
        int n = read(fd, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("  read %d bytes: ", n);
            for (int i = 0; i < n && i < 64; i++) printf("%02x ", (unsigned char)buf[i]);
            printf("\n");
        }
    }
    return fd;
}

int main() {
    printf("=== Abstract Socket Probe ===\n");
    
    const char *sockets[] = {
        "ATDMultiClient",
        "FactoryClientSend",
        "FactoryClientRecv",
        "diag_mycmc_app2cp",
        NULL
    };
    
    for (int i = 0; sockets[i]; i++) {
        int fd = try_connect(sockets[i]);
        if (fd >= 0) {
            // Try sending a simple AT command to ATDMultiClient
            if (strcmp(sockets[i], "ATDMultiClient") == 0) {
                const char *cmd = "AT\r\n";
                write(fd, cmd, strlen(cmd));
                printf("  sent AT command\n");
                usleep(500000);
                char buf[256];
                int n = read(fd, buf, sizeof(buf)-1);
                if (n > 0) {
                    buf[n] = '\0';
                    printf("  response: ");
                    for (int j = 0; j < n && j < 64; j++) printf("%02x ", (unsigned char)buf[j]);
                    printf("\n  ascii: %s\n", buf);
                }
            }
            close(fd);
        }
    }
    
    // Also try filesystem sockets
    printf("\n=== Filesystem Socket Probe ===\n");
    const char *fsocks[] = {
        "/data/.diag_stream",
        "/data/.diagsocket_stream",
        "/dev/socket/rild-debug",
        NULL
    };
    for (int i = 0; fsocks[i]; i++) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, fsocks[i], sizeof(addr.sun_path)-1);
        int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
        printf("  connect(%s): %s (errno=%d)\n", fsocks[i], ret==0?"SUCCESS":"FAILED", errno);
        close(fd);
    }
    
    return 0;
}
