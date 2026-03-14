/*
 * usb_restore_adb.c - Try to restore ADB via USB service or property service
 *
 * The device fell back to persist.sys.usb.config=acm,dm (no ADB).
 * This tool attempts to restore ADB by:
 * 1. Setting sys.usb.config property to include adb
 * 2. Calling USB service to change configuration
 * 3. Writing to property_service socket
 *
 * Build: arm-linux-gnueabi-gcc -static -pie -fPIE -o usb_restore_adb usb_restore_adb.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
/* Property service protocol */
#define PROP_SERVICE_NAME "property_service"
#define PROP_MSG_SETPROP 1
#define PROP_SUCCESS 0

struct prop_msg {
    unsigned cmd;
    char name[32];
    char value[92];
};

static int set_property_via_socket(const char *name, const char *value) {
    int s;
    struct sockaddr_un addr;
    struct prop_msg msg;
    int result = -1;
    
    s = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/dev/socket/%s", PROP_SERVICE_NAME);
    
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect property_service");
        close(s);
        return -1;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.cmd = PROP_MSG_SETPROP;
    strncpy(msg.name, name, sizeof(msg.name) - 1);
    strncpy(msg.value, value, sizeof(msg.value) - 1);
    
    if (send(s, &msg, sizeof(msg), 0) != sizeof(msg)) {
        perror("send");
        close(s);
        return -1;
    }
    
    /* Read response */
    int n = recv(s, &result, sizeof(result), 0);
    if (n == sizeof(result)) {
        printf("  Property set result: %d (%s)\n", result, result == 0 ? "SUCCESS" : "FAILED");
    } else {
        printf("  No response from property_service (n=%d)\n", n);
    }
    
    close(s);
    return result;
}

int main() {
    printf("=== USB ADB Restore Tool ===\n");
    printf("UID=%d PID=%d\n\n", getuid(), getpid());
    
    /* Try __system_property_get — not available in static build, use getprop */
    printf("Current USB properties:\n");
    system("getprop sys.usb.config");
    system("getprop sys.usb.state");
    system("getprop persist.sys.usb.config");
    system("getprop persist.sys.usb.q_config");
    system("getprop init.svc.adbd");
    
    /* Attempt 1: Set sys.usb.config via property service socket */
    printf("\n--- Attempt 1: Set sys.usb.config via property_service ---\n");
    int ret = set_property_via_socket("sys.usb.config", "rndis,acm,dm,adb");
    printf("  Result: %d\n", ret);
    
    sleep(2);
    
    /* Check if it changed */
    printf("  sys.usb.config now:\n");
    system("getprop sys.usb.config");
    
    /* Attempt 2: Set persist.sys.usb.config */
    printf("\n--- Attempt 2: Set persist.sys.usb.config ---\n");
    ret = set_property_via_socket("persist.sys.usb.config", "rndis,acm,dm,adb");
    printf("  Result: %d\n", ret);
    
    /* Attempt 3: Try setprop command */
    printf("\n--- Attempt 3: Try setprop via system() ---\n");
    system("setprop sys.usb.config rndis,acm,dm,adb 2>&1");
    sleep(1);
    printf("  sys.usb.config now:\n");
    system("getprop sys.usb.config");
    
    /* Attempt 4: Try writing to USB gadget sysfs directly */
    printf("\n--- Attempt 4: Check USB gadget sysfs ---\n");
    const char *gadget_paths[] = {
        "/sys/class/android_usb/android0/functions",
        "/sys/class/android_usb/android0/enable",
        "/sys/class/android_usb/android0/idProduct",
        "/sys/devices/virtual/android_usb/android0/functions",
        NULL
    };
    
    for (int i = 0; gadget_paths[i]; i++) {
        int gfd = open(gadget_paths[i], O_RDONLY);
        if (gfd >= 0) {
            char buf[256] = {0};
            int n = read(gfd, buf, sizeof(buf)-1);
            close(gfd);
            if (n > 0) {
                buf[n] = 0;
                printf("  %s = %s", gadget_paths[i], buf);
            }
        }
        
        /* Try writing */
        gfd = open(gadget_paths[i], O_WRONLY);
        if (gfd >= 0) {
            printf("  %s is WRITABLE!\n", gadget_paths[i]);
            close(gfd);
        }
    }
    
    /* Attempt 5: ctl.restart adbd */
    printf("\n--- Attempt 5: Try ctl.restart adbd ---\n");
    ret = set_property_via_socket("ctl.restart", "adbd");
    printf("  Result: %d\n", ret);
    
    /* Attempt 6: ctl.start adbd */  
    printf("\n--- Attempt 6: Try ctl.start adbd ---\n");
    ret = set_property_via_socket("ctl.start", "adbd");
    printf("  Result: %d\n", ret);
    
    printf("\n--- Final state ---\n");
    system("getprop sys.usb.config");
    system("getprop sys.usb.state");
    system("getprop init.svc.adbd");
    
    printf("\n=== Done ===\n");
    return 0;
}
