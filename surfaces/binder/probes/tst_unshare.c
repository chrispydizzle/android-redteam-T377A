#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    int r = syscall(__NR_unshare, 0x400); /* CLONE_FILES = 0x400 */
    printf("unshare(CLONE_FILES) = %d errno=%d\n", r, errno);
    return 0;
}
