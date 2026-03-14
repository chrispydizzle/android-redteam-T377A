/* alarm_fuzz.c — /dev/alarm ioctl fuzzer
 * Tests alarm timer interfaces for edge cases and crashes.
 * Cross-compile: arm-linux-gnueabi-gcc -std=gnu99 -static -pie -Wall -o alarm_fuzz alarm_fuzz.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>

/* Android alarm driver ioctl definitions from kernel source */
#define ANDROID_ALARM_BASE_CMD(cmd)    (cmd & ~(_IOC(0, 0, 0xf0, 0)))
#define ANDROID_ALARM_IOCTL_NR(alarm)  ((alarm) >> 4)

/* Alarm types */
#define ANDROID_ALARM_RTC_WAKEUP       0
#define ANDROID_ALARM_RTC              1
#define ANDROID_ALARM_ELAPSED_REALTIME_WAKEUP 2
#define ANDROID_ALARM_ELAPSED_REALTIME 3
#define ANDROID_ALARM_SYSTEMTIME       4
#define ANDROID_ALARM_TYPE_COUNT       5

/* ioctl commands */
#define ALARM_IOW(c, type, size) _IOW('a', (c) | ((type) << 4), size)
#define ALARM_IOR(c, type, size) _IOR('a', (c) | ((type) << 4), size)
#define ALARM_IO(c, type)        _IO('a', (c) | ((type) << 4))

#define ANDROID_ALARM_GET_TIME(type)   ALARM_IOR(4, type, struct timespec)
#define ANDROID_ALARM_SET(type)        ALARM_IOW(2, type, struct timespec)
#define ANDROID_ALARM_CLEAR(type)      ALARM_IO(3, type)
#define ANDROID_ALARM_SET_RTC          ALARM_IOW(5, 0, struct timespec)
#define ANDROID_ALARM_WAIT             _IO('a', 1)

static uint32_t seed;
static uint32_t rnd32(void) {
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

static unsigned long total_ops = 0;

int main(int argc, char *argv[]) {
    int iters = 2000;
    if (argc > 1) iters = atoi(argv[1]);

    seed = (uint32_t)time(NULL) ^ getpid();
    printf("=== /dev/alarm Fuzzer ===\n");
    printf("uid=%d, iterations=%d\n", getuid(), iters);

    int fd = open("/dev/alarm", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/alarm");
        return 1;
    }
    printf("[+] /dev/alarm fd=%d\n", fd);

    int crashes = 0;
    for (int i = 0; i < iters; i++) {
        if (i % 500 == 0)
            printf("  [%d] ops=%lu\n", i, total_ops);

        uint32_t op = rnd32() % 10;

        if (op < 3) {
            /* GET_TIME with valid and invalid types */
            struct timespec ts = {0};
            int type = rnd32() % 8; /* 0-4 valid, 5-7 invalid */
            unsigned long cmd = ANDROID_ALARM_GET_TIME(type);
            int ret = ioctl(fd, cmd, &ts);
            total_ops++;
            if (ret == 0 && type >= ANDROID_ALARM_TYPE_COUNT) {
                printf("  [!] GET_TIME type=%d succeeded (unexpected)\n", type);
            }
        } else if (op < 5) {
            /* SET with various timespec values (expect EPERM) */
            struct timespec ts;
            ts.tv_sec = (long)(rnd32() % 0x7FFFFFFF);
            ts.tv_nsec = (long)(rnd32() % 2000000000); /* include invalid >1e9 */
            int type = rnd32() % 8;
            unsigned long cmd = ANDROID_ALARM_SET(type);
            ioctl(fd, cmd, &ts);
            total_ops++;
        } else if (op < 7) {
            /* CLEAR with various types (expect EPERM) */
            int type = rnd32() % 8;
            unsigned long cmd = ANDROID_ALARM_CLEAR(type);
            ioctl(fd, cmd, 0);
            total_ops++;
        } else if (op == 7) {
            /* SET_RTC with garbage timespec */
            struct timespec ts;
            ts.tv_sec = (long)(rnd32());
            ts.tv_nsec = (long)(rnd32());
            ioctl(fd, ANDROID_ALARM_SET_RTC, &ts);
            total_ops++;
        } else if (op == 8) {
            /* Completely random ioctl number */
            unsigned long cmd = rnd32();
            char buf[256];
            memset(buf, rnd32() & 0xFF, sizeof(buf));
            ioctl(fd, cmd, buf);
            total_ops++;
        } else {
            /* WAIT with timeout (non-blocking via O_NONBLOCK reopen) */
            int fd2 = open("/dev/alarm", O_RDONLY | O_NONBLOCK);
            if (fd2 >= 0) {
                ioctl(fd2, ANDROID_ALARM_WAIT, 0);
                close(fd2);
            }
            total_ops++;
        }
    }

    close(fd);
    printf("\n=== Done: %lu total ops, %d anomalies ===\n", total_ops, crashes);
    return 0;
}
