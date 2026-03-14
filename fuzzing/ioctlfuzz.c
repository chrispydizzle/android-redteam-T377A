#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define DEVICE_PATH "/dev/mali0"  // Change this to your target device node
#define ITERATIONS 10000            // Number of fuzz attempts
#define MAX_BUF_SIZE 512            // Max buffer size for ioctl arg
#define LOG_FILE "/data/local/tmp/ioctl_fuzz.log"

// Generate a random unsigned long
unsigned long rand_ulong() {
    return ((unsigned long)rand() << 32) | rand();
}

int main() {
    FILE *log = fopen(LOG_FILE, "w");
    if (!log) {
        perror("Failed to open log file");
        return 1;
    }

    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fprintf(log, "Failed to open %s: %s\n", DEVICE_PATH, strerror(errno));
        fclose(log);
        return 1;
    }

    srand(time(NULL));

    for (int i = 0; i < ITERATIONS; i++) {
        unsigned long cmd = rand_ulong();
        size_t buf_size = rand() % MAX_BUF_SIZE + 1;
        char *buffer = malloc(buf_size);
        if (!buffer) {
            fprintf(log, "Memory allocation failed\n");
            break;
        }

        for (size_t j = 0; j < buf_size; j++) {
            buffer[j] = rand() % 256;
        }

        int ret = ioctl(fd, cmd, buffer);
        if (ret < 0) {
            // Ignore common benign errors
            if (errno != ENOTTY && errno != EINVAL) {
                fprintf(log, "[%d] ioctl cmd=0x%lx size=%zu errno=%d (%s)\n",
                        i, cmd, buf_size, errno, strerror(errno));
            }
        } else {
            fprintf(log, "[%d] ioctl cmd=0x%lx size=%zu SUCCESS\n", i, cmd, buf_size);
        }

        free(buffer);
    }

    close(fd);
    fclose(log);
    return 0;
}
