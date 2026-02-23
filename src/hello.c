#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>

int main(void) {
    struct utsname u;
    printf("hello from ARM! uid=%d\n", getuid());
    if (uname(&u) == 0)
        printf("kernel: %s %s %s\n", u.sysname, u.release, u.machine);
    return 0;
}
