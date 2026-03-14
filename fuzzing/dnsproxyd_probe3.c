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
    int fd = connect_sock();
    if (fd < 0) { printf("  connect failed\n"); return; }
    
    int n = write(fd, cmd, len);
    printf("  Sent %d bytes\n", n);
    
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    char resp[BUF_SIZE];
    n = read(fd, resp, sizeof(resp)-1);
    if (n > 0) {
        resp[n] = '\0';
        printf("  Recv %d bytes: ", n);
        for (int i = 0; i < n && i < 200; i++) {
            if (resp[i] >= 32 && resp[i] < 127) printf("%c", resp[i]);
            else printf("\\x%02x", (unsigned char)resp[i]);
        }
        printf("\n");
    } else if (n == 0) {
        printf("  Closed\n");
    } else {
        printf("  %s\n", strerror(errno));
    }
    close(fd);
}

#define PROBE(lbl, cmd) probe(lbl, cmd, sizeof(cmd))

int main(void) {
    printf("dnsproxyd Probe v3 — no seqno\n\n");
    
    // No sequence numbers — raw commands with null terminator
    PROBE("T1: getaddrinfo localhost",
          "getaddrinfo localhost ^ 10 2 0 0 0 0");
    
    PROBE("T2: gethostbyname",
          "gethostbyname localhost 10");
    
    PROBE("T3: gethostbyaddr",
          "gethostbyaddr 127.0.0.1 2");
    
    PROBE("T4: getdnsnetid",
          "getdnsnetid 0");
    
    PROBE("T5: no args getaddrinfo",
          "getaddrinfo");
    
    PROBE("T6: empty",
          "");
    
    PROBE("T7: format string host",
          "getaddrinfo %p.%p.%p ^ 2 1 0 0 0 0");
    
    PROBE("T8: negative family",
          "getaddrinfo localhost ^ -1 -1 -1 -1 0 0");
    
    // Samsung-specific commands?
    PROBE("T9: res_init",
          "res_init");
    PROBE("T10: setnetworkforuid",
          "setnetworkforuid 0 10139");
    PROBE("T11: setdefaultnetwork",
          "setdefaultnetwork 0");
    PROBE("T12: resolver",
          "resolver");
    PROBE("T13: setdnsfornet",
          "setdnsfornet 0 8.8.8.8");
    PROBE("T14: dnsproxylistener",
          "dnsproxylistener");
    
    printf("\n=== HEALTH ===\n");
    int fd = connect_sock();
    if (fd >= 0) { printf("netd alive\n"); close(fd); }
    else printf("*** DEAD ***\n");
    return 0;
}
