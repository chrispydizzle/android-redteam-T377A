#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/input.h>

// Helper to get random number in range
long rand_range(long min, long max) {
    return min + (rand() % (max - min + 1));
}

void fuzz_device(const char *path, int iterations) {
    printf("[*] Opening input device: %s\n", path);
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open device");
        return;
    }

    printf("[+] Device opened. Fuzzing for %d iterations...\n", iterations);
    srand(time(NULL));

    struct input_event ev;
    int success_count = 0;
    int fail_count = 0;

    for (int i = 0; i < iterations; i++) {
        memset(&ev, 0, sizeof(ev));
        
        // 80% chance of random event, 20% chance of semi-valid event types
        if (rand() % 100 < 80) {
            ev.type = rand() % 0xFFFF;
            ev.code = rand() % 0xFFFF;
            ev.value = rand();
        } else {
            // Try to hit common types
            int type_pick = rand() % 5;
            switch(type_pick) {
                case 0: ev.type = EV_SYN; break;
                case 1: ev.type = EV_KEY; break;
                case 2: ev.type = EV_REL; break;
                case 3: ev.type = EV_ABS; break;
                case 4: ev.type = EV_MSC; break;
            }
            ev.code = rand() % 512;
            ev.value = rand();
        }

        // Randomize timestamp? usually kernel ignores write timestamp and sets its own
        // but let's leave it 0 or random
        ev.time.tv_sec = rand();
        ev.time.tv_usec = rand();

        ssize_t ret = write(fd, &ev, sizeof(ev));
        if (ret < 0) {
            // Expected to fail often with EINVAL
            if (errno != EINVAL) {
                // printf("Write failed: %s\n", strerror(errno));
            }
            fail_count++;
        } else {
            success_count++;
            if (i % 1000 == 0) {
                printf("[.] Iteration %d: Wrote event type=%x code=%x value=%x\n", i, ev.type, ev.code, ev.value);
            }
        }
        
        // Occasionally sync
        if (i % 100 == 0) {
            fsync(fd);
        }
    }

    printf("[+] Fuzzing complete. Success: %d, Fail: %d\n", success_count, fail_count);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <device_path> <iterations>\n", argv[0]);
        return 1;
    }

    fuzz_device(argv[1], atoi(argv[2]));
    return 0;
}
