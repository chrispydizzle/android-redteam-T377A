#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/time.h>

#define SOCK_PATH "/dev/socket/dnsproxyd"
#define BUF_SIZE 4096

static int connect_dnsproxyd(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void send_and_recv(const char *label, const char *cmd) {
    printf("%s\n", label);
    int fd = connect_dnsproxyd();
    if (fd < 0) { printf("  connect failed: %s\n", strerror(errno)); return; }
    
    // Commands must end with \0 for FrameworkListener
    int cmdlen = strlen(cmd);
    char *buf = malloc(cmdlen + 2);
    memcpy(buf, cmd, cmdlen);
    buf[cmdlen] = '\0';
    
    int n = write(fd, buf, cmdlen + 1);
    printf("  Sent %d bytes\n", n);
    free(buf);
    
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    char resp[BUF_SIZE];
    n = read(fd, resp, sizeof(resp) - 1);
    if (n > 0) {
        resp[n] = '\0';
        printf("  Recv %d bytes: ", n);
        for (int i = 0; i < n && i < 128; i++) {
            if (resp[i] >= 32 && resp[i] < 127) printf("%c", resp[i]);
            else printf("\\x%02x", (unsigned char)resp[i]);
        }
        printf("\n");
    } else if (n == 0) {
        printf("  Connection closed by peer\n");
    } else {
        printf("  read error: %s\n", strerror(errno));
    }
    close(fd);
}

int main(void) {
    printf("dnsproxyd Protocol Probe v2\n");
    printf("Target: %s (netd=root)\n\n", SOCK_PATH);
    
    // FrameworkListener expects: seqno command args\0
    // seqno is just an integer that gets echoed back
    
    send_and_recv("TEST 1: getaddrinfo with seqno",
        "1 getaddrinfo localhost ^ 10 2 0 0 0 0");
    
    send_and_recv("TEST 2: gethostbyname with seqno",
        "2 gethostbyname localhost 10");
    
    send_and_recv("TEST 3: gethostbyaddr with seqno",
        "3 gethostbyaddr 127.0.0.1 2");
    
    send_and_recv("TEST 4: invalid command",
        "4 INVALID test");
    
    send_and_recv("TEST 5: empty command",
        "5");
    
    send_and_recv("TEST 6: getaddrinfo long host (200 chars)",
        "6 getaddrinfo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ^ 10 2 0 0 0 0");
    
    // Test with no arguments
    send_and_recv("TEST 7: getaddrinfo no args",
        "7 getaddrinfo");
    
    // Format string
    send_and_recv("TEST 8: format string",
        "8 getaddrinfo %x.%x.%x.%x ^ 10 2 0 0 0 0");
    
    // Negative values  
    send_and_recv("TEST 9: negative family",
        "9 getaddrinfo localhost ^ -1 -1 -1 -1 0 0");
    
    // Very large int
    send_and_recv("TEST 10: large netid",
        "10 getaddrinfo localhost ^ 10 2 0 0 999999999 0");
    
    // Integer overflow attempt
    send_and_recv("TEST 11: INT_MAX values",
        "11 getaddrinfo localhost ^ 2147483647 2147483647 0 0 0 0");
    
    // Extra args
    send_and_recv("TEST 12: extra args",
        "12 getaddrinfo localhost ^ 10 2 0 0 0 0 EXTRA1 EXTRA2 EXTRA3");
    
    // Newline in host
    send_and_recv("TEST 13: newline in args",
        "13 getaddrinfo local\nhost ^ 10 2 0 0 0 0");
    
    printf("\n=== HEALTH CHECK ===\n");
    int fd = connect_dnsproxyd();
    if (fd >= 0) {
        printf("netd alive\n");
        close(fd);
    } else {
        printf("*** netd may be dead! ***\n");
    }
    
    return 0;
}
