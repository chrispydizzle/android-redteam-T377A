#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#define SOCK_PATH "/dev/socket/dnsproxyd"
#define BUF_SIZE 4096

static int connect_dnsproxyd(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket: %s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("connect: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int send_recv(int fd, const char *cmd, char *resp, int resp_len) {
    int n = write(fd, cmd, strlen(cmd));
    if (n < 0) {
        printf("  write: %s\n", strerror(errno));
        return -1;
    }
    // Set recv timeout
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    n = read(fd, resp, resp_len - 1);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("  timeout (no response)\n");
        } else {
            printf("  read: %s\n", strerror(errno));
        }
        return -1;
    }
    resp[n] = '\0';
    return n;
}

static void test_basic(void) {
    printf("=== TEST 1: Basic getaddrinfo ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char resp[BUF_SIZE];
    // Format: getaddrinfo host service family socktype proto flags netid mark
    const char *cmd = "getaddrinfo localhost ^  10 2 0 0 0 0\0";
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes: ", n);
        for (int i = 0; i < n && i < 64; i++) {
            if (resp[i] >= 32 && resp[i] < 127) printf("%c", resp[i]);
            else printf("\\x%02x", (unsigned char)resp[i]);
        }
        printf("\n");
    }
    close(fd);
}

static void test_gethostbyname(void) {
    printf("\n=== TEST 2: gethostbyname ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char resp[BUF_SIZE];
    const char *cmd = "gethostbyname localhost 10\0";
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes: ", n);
        for (int i = 0; i < n && i < 64; i++) {
            if (resp[i] >= 32 && resp[i] < 127) printf("%c", resp[i]);
            else printf("\\x%02x", (unsigned char)resp[i]);
        }
        printf("\n");
    }
    close(fd);
}

static void test_long_hostname(void) {
    printf("\n=== TEST 3: Long hostname (512 bytes) ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char cmd[1024];
    char host[513];
    memset(host, 'A', 512);
    host[512] = '\0';
    snprintf(cmd, sizeof(cmd), "getaddrinfo %s ^ 10 2 0 0 0 0", host);
    
    char resp[BUF_SIZE];
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes\n", n);
    }
    close(fd);
}

static void test_very_long_hostname(void) {
    printf("\n=== TEST 4: Very long hostname (4096 bytes) ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char *cmd = malloc(8192);
    char *host = malloc(4097);
    memset(host, 'B', 4096);
    host[4096] = '\0';
    snprintf(cmd, 8192, "getaddrinfo %s ^ 10 2 0 0 0 0", host);
    
    char resp[BUF_SIZE];
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes\n", n);
    }
    free(cmd);
    free(host);
    close(fd);
}

static void test_format_strings(void) {
    printf("\n=== TEST 5: Format string in hostname ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char resp[BUF_SIZE];
    const char *cmd = "getaddrinfo %x.%x.%x.%x ^ 10 2 0 0 0 0\0";
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes: ", n);
        for (int i = 0; i < n && i < 128; i++) {
            if (resp[i] >= 32 && resp[i] < 127) printf("%c", resp[i]);
            else printf("\\x%02x", (unsigned char)resp[i]);
        }
        printf("\n");
    }
    close(fd);
}

static void test_negative_values(void) {
    printf("\n=== TEST 6: Negative/large values ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char resp[BUF_SIZE];
    const char *cmd = "getaddrinfo localhost ^ -1 -1 -1 -1 -1 -1\0";
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes\n", n);
    }
    close(fd);
}

static void test_gethostbyaddr(void) {
    printf("\n=== TEST 7: gethostbyaddr ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char resp[BUF_SIZE];
    const char *cmd = "gethostbyaddr 127.0.0.1 2\0";
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes: ", n);
        for (int i = 0; i < n && i < 64; i++) {
            if (resp[i] >= 32 && resp[i] < 127) printf("%c", resp[i]);
            else printf("\\x%02x", (unsigned char)resp[i]);
        }
        printf("\n");
    }
    close(fd);
}

static void test_invalid_command(void) {
    printf("\n=== TEST 8: Invalid command ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char resp[BUF_SIZE];
    const char *cmd = "INVALIDCOMMAND test 1 2 3\0";
    int n = send_recv(fd, cmd, resp, sizeof(resp));
    if (n > 0) {
        printf("  Recv %d bytes: %s\n", n, resp);
    }
    close(fd);
}

static void test_null_bytes(void) {
    printf("\n=== TEST 9: Embedded null bytes ===\n");
    int fd = connect_dnsproxyd();
    if (fd < 0) return;
    
    char cmd[64];
    memcpy(cmd, "getaddrinfo ", 12);
    cmd[12] = 'A';
    cmd[13] = '\0';
    cmd[14] = 'B';
    cmd[15] = '\0';
    // Write extra after null
    int n = write(fd, cmd, 20);
    printf("  Wrote %d bytes (with null at offset 13)\n", n);
    
    char resp[BUF_SIZE];
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    n = read(fd, resp, sizeof(resp)-1);
    if (n > 0) {
        resp[n] = '\0';
        printf("  Recv %d bytes\n", n);
    } else {
        printf("  No response\n");
    }
    close(fd);
}

int main(void) {
    printf("dnsproxyd Socket Probe — SM-T377A\n");
    printf("Target: /dev/socket/dnsproxyd (netd=root)\n\n");
    
    // Check if netd is alive first
    if (access(SOCK_PATH, F_OK) != 0) {
        printf("ERROR: %s not found\n", SOCK_PATH);
        return 1;
    }
    
    test_basic();
    test_gethostbyname();
    test_long_hostname();
    test_very_long_hostname();
    test_format_strings();
    test_negative_values();
    test_gethostbyaddr();
    test_invalid_command();
    test_null_bytes();
    
    // Verify netd is still alive
    printf("\n=== HEALTH CHECK ===\n");
    int fd = connect_dnsproxyd();
    if (fd >= 0) {
        printf("netd still alive (connection succeeded)\n");
        close(fd);
    } else {
        printf("*** netd may have crashed! ***\n");
    }
    
    return 0;
}
