/* alarm_rtc_probe.c — Test if ANDROID_ALARM_SET_RTC works from shell
 * If this succeeds, CVE-2017-10661 (timerfd race) becomes viable!
 * 
 * /dev/alarm is crw-rw-r-- system radio — shell can open RO.
 * But SET_RTC ioctl needs write access. Test both paths.
 */
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>

#define ALARM_IOW(c, type, size) _IOW('a', (c) | ((type) << 4), size)
#define ALARM_IOR(c, type, size) _IOR('a', (c) | ((type) << 4), size)
#define ANDROID_ALARM_SET_RTC    ALARM_IOW(5, 0, struct timespec)
#define ANDROID_ALARM_GET_TIME(t) ALARM_IOR(4, t, struct timespec)

int main(void) {
    printf("=== /dev/alarm RTC probe ===\n");
    
    /* Try RW first, then RO */
    int fd = open("/dev/alarm", O_RDWR);
    if (fd >= 0) {
        printf("Opened RW: fd=%d\n", fd);
    } else {
        printf("RW failed: errno=%d\n", errno);
        fd = open("/dev/alarm", O_RDONLY);
        if (fd >= 0) {
            printf("Opened RO: fd=%d\n", fd);
        } else {
            printf("RO failed: errno=%d\n", errno);
            return 1;
        }
    }

    /* Read current RTC time */
    struct timespec ts = {0};
    int ret = ioctl(fd, ANDROID_ALARM_GET_TIME(1), &ts);
    printf("GET_TIME(RTC): ret=%d errno=%d time=%ld.%09ld\n", ret, errno, ts.tv_sec, ts.tv_nsec);
    
    struct timespec ts2 = {0};
    ret = ioctl(fd, ANDROID_ALARM_GET_TIME(4), &ts2);
    printf("GET_TIME(SYS): ret=%d errno=%d time=%ld.%09ld\n", ret, errno, ts2.tv_sec, ts2.tv_nsec);

    /* Try SET_RTC — changes system clock if permitted */
    struct timespec new_ts = { .tv_sec = ts.tv_sec + 2, .tv_nsec = 0 };
    errno = 0;
    ret = ioctl(fd, ANDROID_ALARM_SET_RTC, &new_ts);
    printf("SET_RTC(+2s): ret=%d errno=%d\n", ret, errno);
    if (ret == 0) {
        printf("*** TIME CONTROL CONFIRMED — CVE-2017-10661 IS VIABLE ***\n");
        /* Set it back */
        new_ts.tv_sec = ts.tv_sec;
        ioctl(fd, ANDROID_ALARM_SET_RTC, &new_ts);
        printf("Time restored\n");
    } else if (errno == 13) {
        printf("EPERM — need CAP_SYS_TIME or different permissions\n");
    } else if (errno == 22) {
        printf("EINVAL — bad parameters\n");
    }

    close(fd);
    return 0;
}
