#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/input.h>

#define EVIOCGVERSION		_IOR('E', 0x01, int)			/* get driver version */
#define EVIOCGID		_IOR('E', 0x02, struct input_id)	/* get device ID */
#define EVIOCGREP		_IOR('E', 0x03, unsigned int[2])	/* get repeat settings */
#define EVIOCSREP		_IOW('E', 0x03, unsigned int[2])	/* set repeat settings */

#define EVIOCGKEYCODE		_IOR('E', 0x04, unsigned int[2])        /* get keycode */
#define EVIOCGKEYCODE_V2	_IOR('E', 0x04, struct input_keymap_entry)
#define EVIOCSKEYCODE		_IOW('E', 0x04, unsigned int[2])        /* set keycode */
#define EVIOCSKEYCODE_V2	_IOW('E', 0x04, struct input_keymap_entry)

#define EVIOCGNAME(len)		_IOC(_IOC_READ, 'E', 0x06, len)		/* get device name */
#define EVIOCGPHYS(len)		_IOC(_IOC_READ, 'E', 0x07, len)		/* get physical location */
#define EVIOCGUNIQ(len)		_IOC(_IOC_READ, 'E', 0x08, len)		/* get unique identifier */
#define EVIOCGPROP(len)		_IOC(_IOC_READ, 'E', 0x09, len)		/* get device properties */

/**
 * EVIOCGMTSLOTS(len) - get MT slot values
 * @len: size of the data buffer in bytes
 *
 * The ioctl buffer argument should be binary equivalent to
 * struct input_mt_request_layout:
 * - the original code
 * - the set of slots to read
 * - the array of results
 */
#define EVIOCGMTSLOTS(len)	_IOC(_IOC_READ, 'E', 0x0a, len)

#define EVIOCGKEY(len)		_IOC(_IOC_READ, 'E', 0x18, len)		/* get global key state */
#define EVIOCGLED(len)		_IOC(_IOC_READ, 'E', 0x19, len)		/* get all LEDs */
#define EVIOCGSND(len)		_IOC(_IOC_READ, 'E', 0x1a, len)		/* get all sounds status */
#define EVIOCGSW(len)		_IOC(_IOC_READ, 'E', 0x1b, len)		/* get all switch states */

#define EVIOCGBIT(ev,len)	_IOC(_IOC_READ, 'E', 0x20 + (ev), len)	/* get event bits */
#define EVIOCGABS(abs)		_IOR('E', 0x40 + (abs), struct input_absinfo)	/* get abs value/limits */
#define EVIOCSABS(abs)		_IOW('E', 0xc0 + (abs), struct input_absinfo)	/* set abs value/limits */

#define EVIOCSFF		_IOC(_IOC_WRITE, 'E', 0x80, sizeof(struct ff_effect))	/* send a force effect to a force feedback device */
#define EVIOCRMFF		_IOW('E', 0x81, int)			/* Erase a force effect */
#define EVIOCGEFFECTS		_IOR('E', 0x84, int)			/* Report number of effects playable at the same time */

#define EVIOCGRAB		_IOW('E', 0x90, int)			/* Grab/Release device */
#define EVIOCREVOKE		_IOW('E', 0x91, int)			/* Revoke device access */

#define EVIOCSCLOCKID		_IOW('E', 0xa0, int)			/* Set clockid to be used for timestamps */

static volatile sig_atomic_t g_stop = 0;

static __thread uint64_t rng_state = 0;

static void seed_rng(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rng_state = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec ^ (uint64_t)syscall(SYS_gettid);
}

static uint32_t rnd32(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return (uint32_t)x;
}

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

void *worker_thread(void *arg) {
    const char *dev_path = (const char *)arg;
    seed_rng();
    
    int fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        printf("[-] Failed to open %s\n", dev_path);
        return NULL;
    }

    uint8_t buffer[4096];
    
    while (!g_stop) {
        int op = rnd32() % 100;
        unsigned long cmd;
        void *arg_ptr = buffer;
        int size = 0;
        
        // Randomize buffer content
        for (int i=0; i<sizeof(buffer)/4; i++) ((uint32_t*)buffer)[i] = rnd32();

        if (op < 10) {
             // EVIOCSFF - Force Feedback
             cmd = EVIOCSFF;
             size = sizeof(struct ff_effect);
        } else if (op < 20) {
             // EVIOCSABS
             int abs = rnd32() % ABS_MAX;
             cmd = EVIOCSABS(abs);
             size = sizeof(struct input_absinfo);
        } else if (op < 30) {
             // EVIOCSKEYCODE
             cmd = EVIOCSKEYCODE;
             size = sizeof(unsigned int) * 2;
        } else if (op < 40) {
             // EVIOCSKEYCODE_V2
             cmd = EVIOCSKEYCODE_V2;
             size = sizeof(struct input_keymap_entry);
        } else if (op < 50) {
             // EVIOCSREP
             cmd = EVIOCSREP;
             size = sizeof(unsigned int) * 2;
        } else if (op < 60) {
             // EVIOCSSUSPENDBLOCK (if available) or EVIOCSCLOCKID
             cmd = EVIOCSCLOCKID;
             size = sizeof(int);
             *(int*)arg_ptr = rnd32() % 4; // CLOCK_REALTIME, MONOTONIC, etc.
        } else if (op < 70) {
             // EVIOCGRAB (dangerous, might lock input)
             // Only grab if we ungrab quickly
             // cmd = EVIOCGRAB;
             // *(int*)arg_ptr = (rnd32() % 2);
             // Let's skip grab to avoid locking ourselves out unless we are careful
             continue;
        } else {
             // Random IOCTL code
             // Try to construct random valid-looking ioctls
             cmd = _IOC(_IOC_WRITE, 'E', (rnd32() % 0xFF), (rnd32() % 128));
             size = (rnd32() % 128);
        }

        ioctl(fd, cmd, arg_ptr);
        
        // Yield occasionally
        if ((rnd32() % 1000) == 0) usleep(1000);
    }
    
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <device_path> [duration] [threads]\n", argv[0]);
        return 1;
    }
    
    char *dev_path = argv[1];
    int duration = 30;
    int num_threads = 4;
    
    if (argc >= 3) duration = atoi(argv[2]);
    if (argc >= 4) num_threads = atoi(argv[3]);

    signal(SIGINT, on_sigint);
    printf("[*] Starting Input IOCTL Fuzzer on %s (%d threads, %ds)...\n", dev_path, num_threads, duration);

    pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
    for (int i=0; i<num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, dev_path);
    }

    sleep(duration);
    g_stop = 1;

    for (int i=0; i<num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("[*] Done.\n");
    return 0;
}
