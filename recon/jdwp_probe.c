/*
 * jdwp_probe.c - Probe @jdwp-control abstract UNIX socket
 * Lists JDWP-debuggable PIDs from the Android debug daemon.
 * 
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o jdwp_probe jdwp_probe.c
 * Run:   adb push jdwp_probe /data/local/tmp/ && adb shell /data/local/tmp/jdwp_probe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

static void alarm_handler(int sig) {
    (void)sig;
    printf("[TIMEOUT]\n");
    _exit(1);
}

int main(void) {
    int fd;
    struct sockaddr_un addr;
    char buf[4096];
    int ret;
    int pid_count = 0;

    signal(SIGALRM, alarm_handler);
    alarm(10);

    printf("=== JDWP Control Socket Probe ===\n\n");

    /* Check if we can see the socket in /proc/net/unix */
    printf("[*] Checking /proc/net/unix for jdwp sockets...\n");
    FILE *fp = fopen("/proc/net/unix", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "jdwp")) {
                printf("    Found: %s", line);
            }
        }
        fclose(fp);
    }
    printf("\n");

    /* Try connecting to @jdwp-control */
    printf("[*] Connecting to @jdwp-control...\n");

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("[-] socket() failed: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* Abstract namespace: first byte is \0 */
    addr.sun_path[0] = '\0';
    strcpy(addr.sun_path + 1, "jdwp-control");

    ret = connect(fd, (struct sockaddr *)&addr,
                  sizeof(sa_family_t) + 1 + strlen("jdwp-control"));
    if (ret < 0) {
        printf("[-] CONNECT FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("    This is expected if SELinux blocks shell->adbd socket access.\n");
        close(fd);

        /* Check SELinux context */
        printf("\n[*] Our SELinux context:\n");
        fp = fopen("/proc/self/attr/current", "r");
        if (fp) {
            if (fgets(buf, sizeof(buf), fp))
                printf("    %s\n", buf);
            fclose(fp);
        }

        /* Check adbd's context */
        printf("[*] Checking adbd SELinux context...\n");
        system("cat /proc/$(pidof adbd)/attr/current 2>/dev/null");
        printf("\n");

        return 1;
    }

    printf("[+] CONNECTED to @jdwp-control!\n\n");

    /* Read PIDs (text, newline-separated) */
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("[*] Reading debuggable PIDs...\n");
    while ((ret = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[ret] = '\0';
        /* Count and display PIDs */
        char *line = strtok(buf, "\n");
        while (line) {
            int pid = atoi(line);
            if (pid > 0) {
                pid_count++;
                printf("    PID %d", pid);
                /* Try to read process name */
                char cmdline_path[64];
                char cmdline[256];
                snprintf(cmdline_path, sizeof(cmdline_path),
                         "/proc/%d/cmdline", pid);
                FILE *cf = fopen(cmdline_path, "r");
                if (cf) {
                    if (fgets(cmdline, sizeof(cmdline), cf))
                        printf(" -> %s", cmdline);
                    fclose(cf);
                }
                /* Try to read UID */
                char status_path[64];
                char status_line[256];
                snprintf(status_path, sizeof(status_path),
                         "/proc/%d/status", pid);
                FILE *sf = fopen(status_path, "r");
                if (sf) {
                    while (fgets(status_line, sizeof(status_line), sf)) {
                        if (strncmp(status_line, "Uid:", 4) == 0) {
                            int uid = atoi(status_line + 5);
                            printf(" [uid=%d", uid);
                            if (uid == 0) printf(" ROOT!");
                            else if (uid == 1000) printf(" SYSTEM!");
                            else if (uid == 1001) printf(" RADIO!");
                            printf("]");
                            break;
                        }
                    }
                    fclose(sf);
                }
                printf("\n");
            }
            line = strtok(NULL, "\n");
        }
    }

    printf("\n[*] Read ended: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
    printf("[*] Total debuggable PIDs found: %d\n", pid_count);

    if (pid_count == 0) {
        printf("\n[!] No debuggable PIDs found.\n");
        printf("    ro.debuggable=0 means only apps with android:debuggable=true appear.\n");
        printf("    System apps on production builds are NOT debuggable.\n");
    }

    close(fd);

    /* Summary of what JDWP access means */
    printf("\n=== JDWP Security Assessment ===\n");
    printf("[*] JDWP allows arbitrary code execution in debuggable app contexts.\n");
    printf("[*] On this device (ro.debuggable=0):\n");
    printf("    - Only explicitly debuggable apps are exposed\n");
    printf("    - System apps (UID 1000) are NOT debuggable\n");
    printf("    - Cannot escalate to system via JDWP alone\n");
    printf("[*] JDWP would be high-impact if ro.debuggable=1 (eng/userdebug build)\n");

    return 0;
}
