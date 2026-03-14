/*
 * physmap_test.c — Test reading /proc/self/pagemap to get physical addresses
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

int main(void) {
    printf("=== Pagemap Test ===\n");
    
    /* Allocate and lock a page */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(page, 'A', 4096);  /* Touch to fault in */
    
    printf("[*] User page: %p\n", page);
    
    /* Open pagemap */
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        printf("[-] open pagemap: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }
    printf("[+] Opened /proc/self/pagemap (fd=%d)\n", fd);
    
    /* Calculate page index */
    unsigned long vpage = (unsigned long)page / 4096;
    off_t offset = vpage * 8;
    printf("[*] Page index: %lu, seek offset: %ld\n", vpage, (long)offset);
    
    /* Seek to the entry */
    off_t pos = lseek(fd, offset, SEEK_SET);
    if (pos == (off_t)-1) {
        printf("[-] lseek: %s (errno=%d)\n", strerror(errno), errno);
        /* Try reading sequentially instead */
        close(fd);
        fd = open("/proc/self/pagemap", O_RDONLY);
        
        /* Read in chunks */
        unsigned long long dummy;
        for (unsigned long i = 0; i < vpage; i++) {
            if (read(fd, &dummy, 8) != 8) {
                printf("[-] Sequential read failed at %lu\n", i);
                break;
            }
        }
    } else {
        printf("[+] Seeked to offset %ld\n", (long)pos);
    }
    
    /* Read the entry */
    unsigned long long entry = 0;
    int r = read(fd, &entry, 8);
    printf("[*] read returned %d bytes\n", r);
    printf("[*] raw entry: 0x%016llx\n", entry);
    
    if (r == 8) {
        int present = (entry >> 63) & 1;
        int swapped = (entry >> 62) & 1;
        unsigned long long pfn = entry & ((1ULL << 55) - 1);
        
        printf("[*] present=%d, swapped=%d, pfn=0x%llx\n", present, swapped, pfn);
        
        if (present) {
            unsigned long phys = pfn * 4096 + ((unsigned long)page & 0xFFF);
            unsigned long kaddr = phys + 0xA0000000; /* PAGE_OFFSET - PHYS_OFFSET */
            printf("[+] Physical address: 0x%08lx\n", phys);
            printf("[+] Kernel linear map: 0x%08lx\n", kaddr);
        } else if (pfn == 0) {
            printf("[-] PFN is 0 — pagemap may be restricted (CONFIG_STRICT_DEVMEM)\n");
        }
    }
    
    close(fd);
    
    /* Also test with the stack */
    printf("\n[*] Testing stack page:\n");
    unsigned long sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    unsigned long stack_page = sp & ~0xFFF;
    printf("[*] Stack page: 0x%08lx\n", stack_page);
    
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd >= 0) {
        vpage = stack_page / 4096;
        offset = vpage * 8;
        if (lseek(fd, offset, SEEK_SET) != (off_t)-1) {
            r = read(fd, &entry, 8);
            if (r == 8) {
                int present = (entry >> 63) & 1;
                unsigned long long pfn = entry & ((1ULL << 55) - 1);
                printf("[*] Entry: 0x%016llx, present=%d, pfn=0x%llx\n", 
                       entry, present, pfn);
                if (present && pfn) {
                    unsigned long phys = pfn * 4096;
                    printf("[+] Stack physical: 0x%08lx, kernel: 0x%08lx\n",
                           phys, phys + 0xA0000000);
                }
            }
        }
        close(fd);
    }
    
    munmap(page, 4096);
    return 0;
}
