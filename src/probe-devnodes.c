#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

/*
 * probe-devnodes.c — Enumerate and probe world-writable /dev nodes
 * Runs in the QEMU ARM kernel fuzzing VM.
 * This just opens device nodes and prints info; does not fuzz.
 */

struct dev_info {
    const char *path;
    const char *desc;
};

static struct dev_info targets[] = {
    { "/dev/binder",   "Android Binder IPC" },
    { "/dev/ashmem",   "Android shared memory" },
    { "/dev/ion",      "ION memory allocator" },
    { "/dev/mali0",    "ARM Mali GPU" },
    { "/dev/random",   "Kernel RNG" },
    { NULL, NULL }
};

int main(void) {
    struct utsname u;
    int fd, i;

    printf("=== Device Node Probe ===\n");
    if (uname(&u) == 0)
        printf("Kernel: %s %s (%s)\n", u.sysname, u.release, u.machine);
    printf("UID: %d  PID: %d\n\n", getuid(), getpid());

    /* Read slabinfo header */
    fd = open("/proc/slabinfo", O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        int n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("/proc/slabinfo readable (%d bytes)\n", n);
        }
        close(fd);
    } else {
        printf("/proc/slabinfo: not readable\n");
    }

    /* Read kallsyms sample */
    fd = open("/proc/kallsyms", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        int n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("/proc/kallsyms first line: %.60s...\n", buf);
        }
        close(fd);
    }

    printf("\n--- Device nodes ---\n");
    for (i = 0; targets[i].path; i++) {
        fd = open(targets[i].path, O_RDWR);
        if (fd >= 0) {
            printf("[+] %-20s  OPEN OK  (fd=%d)  %s\n",
                   targets[i].path, fd, targets[i].desc);
            close(fd);
        } else {
            fd = open(targets[i].path, O_RDONLY);
            if (fd >= 0) {
                printf("[~] %-20s  READ OK  (fd=%d)  %s\n",
                       targets[i].path, fd, targets[i].desc);
                close(fd);
            } else {
                printf("[-] %-20s  FAILED   %s\n",
                       targets[i].path, targets[i].desc);
            }
        }
    }

    printf("\nDone.\n");
    return 0;
}
