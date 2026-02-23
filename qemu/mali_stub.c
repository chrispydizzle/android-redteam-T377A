/*
 * mali_stub.c — Stub Mali kbase driver for QEMU kernel fuzzing
 *
 * Registers /dev/mali0 with the same ioctl interface as the real
 * ARM Mali Midgard r7p0 (T72x) driver from the Samsung SM-T377A.
 *
 * The ioctl dispatch mirrors the real driver: it uses a single ioctl
 * number with a variable-size payload whose first 8 bytes carry a
 * uk_header identifying the sub-function.  This lets us exercise the
 * copy_from_user / dispatch / copy_to_user path that real attackers
 * target.
 *
 * No actual GPU hardware is required — this is purely for ioctl
 * interface fuzzing in a QEMU VM.
 *
 * Build: as an out-of-tree module against the 3.10 kernel
 * Load:  insmod /lib/modules/mali_stub.ko
 *
 * (C) Educational use — derived from GPL-licensed Samsung/ARM headers
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QEMU Fuzzing Lab");
MODULE_DESCRIPTION("Stub Mali kbase driver for ioctl fuzzing");

/* === UK header (from mali_uk.h) === */
union uk_header {
    u32 id;
    u32 ret;
    u64 sizer;  /* alignment */
};

/* === Function IDs (from mali_kbase_uku.h) === */
#define UK_FUNC_ID                  512

#define UKP_FUNC_ID_CHECK_VERSION   0

#define KBASE_FUNC_MEM_ALLOC        (UK_FUNC_ID + 0)
#define KBASE_FUNC_MEM_IMPORT       (UK_FUNC_ID + 1)
#define KBASE_FUNC_MEM_COMMIT       (UK_FUNC_ID + 2)
#define KBASE_FUNC_MEM_QUERY        (UK_FUNC_ID + 3)
#define KBASE_FUNC_MEM_FREE         (UK_FUNC_ID + 4)
#define KBASE_FUNC_MEM_FLAGS_CHANGE (UK_FUNC_ID + 5)
#define KBASE_FUNC_MEM_ALIAS        (UK_FUNC_ID + 6)
#define KBASE_FUNC_JOB_SUBMIT_UK6   (UK_FUNC_ID + 7)
#define KBASE_FUNC_SYNC             (UK_FUNC_ID + 8)
#define KBASE_FUNC_POST_TERM        (UK_FUNC_ID + 9)
#define KBASE_FUNC_HWCNT_SETUP      (UK_FUNC_ID + 10)
#define KBASE_FUNC_HWCNT_DUMP       (UK_FUNC_ID + 11)
#define KBASE_FUNC_HWCNT_CLEAR      (UK_FUNC_ID + 12)
#define KBASE_FUNC_GPU_PROPS_REG_DUMP (UK_FUNC_ID + 14)
#define KBASE_FUNC_FIND_CPU_OFFSET  (UK_FUNC_ID + 15)
#define KBASE_FUNC_GET_VERSION      (UK_FUNC_ID + 16)
#define KBASE_FUNC_EXT_BUFFER_LOCK  (UK_FUNC_ID + 17)
#define KBASE_FUNC_SET_FLAGS        (UK_FUNC_ID + 18)
#define KBASE_FUNC_SET_TEST_DATA    (UK_FUNC_ID + 19)
#define KBASE_FUNC_INJECT_ERROR     (UK_FUNC_ID + 20)
#define KBASE_FUNC_MODEL_CONTROL    (UK_FUNC_ID + 21)
#define KBASE_FUNC_KEEP_GPU_POWERED (UK_FUNC_ID + 22)
#define KBASE_FUNC_FENCE_VALIDATE   (UK_FUNC_ID + 23)
#define KBASE_FUNC_STREAM_CREATE    (UK_FUNC_ID + 24)
#define KBASE_FUNC_GET_PROFILING_CONTROLS  (UK_FUNC_ID + 25)
#define KBASE_FUNC_SET_PROFILING_CONTROLS  (UK_FUNC_ID + 26)
#define KBASE_FUNC_DEBUGFS_MEM_PROFILE_ADD (UK_FUNC_ID + 27)
#define KBASE_FUNC_JOB_SUBMIT       (UK_FUNC_ID + 28)
#define KBASE_FUNC_DISJOINT_QUERY   (UK_FUNC_ID + 29)
#define KBASE_FUNC_GET_CONTEXT_ID   (UK_FUNC_ID + 31)
#define KBASE_FUNC_TLSTREAM_ACQUIRE (UK_FUNC_ID + 32)
#define KBASE_FUNC_TLSTREAM_TEST    (UK_FUNC_ID + 33)
#define KBASE_FUNC_TLSTREAM_STATS   (UK_FUNC_ID + 34)
#define KBASE_FUNC_TLSTREAM_FLUSH   (UK_FUNC_ID + 35)
#define KBASE_FUNC_HWCNT_READER_SETUP (UK_FUNC_ID + 36)
#define KBASE_FUNC_MAX              (UK_FUNC_ID + 57)

/* Maximum ioctl payload size (matches real driver) */
#define CALL_MAX_SIZE  536

/* Error codes matching real driver */
#define MALI_ERROR_NONE             0
#define MALI_ERROR_FUNCTION_FAILED  -1

/* Per-fd context (analogous to kbase_context) */
struct mali_stub_ctx {
    struct mutex lock;
    u32 api_version;
    int setup_complete;
    u32 context_id;
    /* Simulated GPU memory tracking */
    u64 alloc_count;
    u64 free_count;
    u64 total_pages;
};

static atomic_t next_ctx_id = ATOMIC_INIT(1);

/* === Function name table for logging === */
static const char *func_name(u32 id)
{
    switch (id) {
    case UKP_FUNC_ID_CHECK_VERSION:   return "CHECK_VERSION";
    case KBASE_FUNC_MEM_ALLOC:        return "MEM_ALLOC";
    case KBASE_FUNC_MEM_IMPORT:       return "MEM_IMPORT";
    case KBASE_FUNC_MEM_COMMIT:       return "MEM_COMMIT";
    case KBASE_FUNC_MEM_QUERY:        return "MEM_QUERY";
    case KBASE_FUNC_MEM_FREE:         return "MEM_FREE";
    case KBASE_FUNC_MEM_FLAGS_CHANGE: return "MEM_FLAGS_CHANGE";
    case KBASE_FUNC_MEM_ALIAS:        return "MEM_ALIAS";
    case KBASE_FUNC_JOB_SUBMIT_UK6:   return "JOB_SUBMIT_UK6";
    case KBASE_FUNC_JOB_SUBMIT:       return "JOB_SUBMIT";
    case KBASE_FUNC_SYNC:             return "SYNC";
    case KBASE_FUNC_POST_TERM:        return "POST_TERM";
    case KBASE_FUNC_HWCNT_SETUP:      return "HWCNT_SETUP";
    case KBASE_FUNC_HWCNT_DUMP:       return "HWCNT_DUMP";
    case KBASE_FUNC_HWCNT_CLEAR:      return "HWCNT_CLEAR";
    case KBASE_FUNC_GPU_PROPS_REG_DUMP: return "GPU_PROPS_REG_DUMP";
    case KBASE_FUNC_FIND_CPU_OFFSET:  return "FIND_CPU_OFFSET";
    case KBASE_FUNC_GET_VERSION:      return "GET_VERSION";
    case KBASE_FUNC_SET_FLAGS:        return "SET_FLAGS";
    case KBASE_FUNC_GET_CONTEXT_ID:   return "GET_CONTEXT_ID";
    case KBASE_FUNC_FENCE_VALIDATE:   return "FENCE_VALIDATE";
    case KBASE_FUNC_STREAM_CREATE:    return "STREAM_CREATE";
    case KBASE_FUNC_DISJOINT_QUERY:   return "DISJOINT_QUERY";
    case KBASE_FUNC_TLSTREAM_ACQUIRE: return "TLSTREAM_ACQUIRE";
    case KBASE_FUNC_TLSTREAM_FLUSH:   return "TLSTREAM_FLUSH";
    default:                          return "UNKNOWN";
    }
}

/* === Dispatch — mirrors real driver logic === */
static int mali_stub_dispatch(struct mali_stub_ctx *ctx, void *args, u32 size)
{
    union uk_header *ukh = args;
    u32 id = ukh->id;

    ukh->ret = MALI_ERROR_NONE;

    pr_info("mali_stub: dispatch func=%u (%s) size=%u\n",
            id, func_name(id), size);

    /* Version handshake — must come first, like real driver */
    if (id == UKP_FUNC_ID_CHECK_VERSION) {
        struct {
            union uk_header header;
            u16 major;
            u16 minor;
            u8 padding[4];
        } *ver = args;

        if (size < sizeof(*ver)) {
            ukh->ret = MALI_ERROR_FUNCTION_FAILED;
            return 0;
        }

        pr_info("mali_stub: version check major=%u minor=%u\n",
                ver->major, ver->minor);

        /* Echo back version 10.0 (matching real r7p0 device) */
        ctx->api_version = (ver->major << 16) | ver->minor;
        ver->major = 10;
        ver->minor = 0;
        return 0;
    }

    /* Block calls before version handshake */
    if (ctx->api_version == 0) {
        pr_warn("mali_stub: call before version handshake, rejecting\n");
        return -EINVAL;
    }

    /* SET_FLAGS must come before any other call */
    if (!ctx->setup_complete) {
        if (id != KBASE_FUNC_SET_FLAGS)
            return -EINVAL;
        ctx->setup_complete = 1;
        pr_info("mali_stub: setup complete (SET_FLAGS)\n");
        return 0;
    }

    /* Main dispatch */
    switch (id) {
    case KBASE_FUNC_MEM_ALLOC: {
        /*
         * Real driver: allocates GPU VA region
         * We simulate: track allocation count, return fake GPU addr
         */
        struct {
            union uk_header header;
            u64 va_pages;
            u64 commit_pages;
            u64 extent;
            u64 flags;
            u64 gpu_va;
            u16 va_alignment;
        } *mem = args;

        if (size < 48) goto bad_size;

        ctx->alloc_count++;
        ctx->total_pages += mem->va_pages;
        /* Return a fake GPU VA */
        mem->gpu_va = 0x10000000ULL + (ctx->alloc_count << 20);
        pr_info("mali_stub: MEM_ALLOC va_pages=%llu -> gpu_va=0x%llx\n",
                mem->va_pages, mem->gpu_va);
        break;
    }

    case KBASE_FUNC_MEM_FREE: {
        struct {
            union uk_header header;
            u64 gpu_addr;
        } *mem = args;

        if (size < 16) goto bad_size;

        ctx->free_count++;
        pr_info("mali_stub: MEM_FREE gpu_addr=0x%llx\n", mem->gpu_addr);
        break;
    }

    case KBASE_FUNC_MEM_QUERY: {
        struct {
            union uk_header header;
            u64 gpu_addr;
            u64 query;
            u64 value;
        } *q = args;

        if (size < 32) goto bad_size;

        /* Return fake values */
        q->value = 256;
        pr_info("mali_stub: MEM_QUERY gpu_addr=0x%llx query=%llu\n",
                q->gpu_addr, q->query);
        break;
    }

    case KBASE_FUNC_MEM_COMMIT: {
        struct {
            union uk_header header;
            u64 gpu_addr;
            u64 pages;
            u32 result_subcode;
        } *c = args;

        if (size < 24) goto bad_size;
        pr_info("mali_stub: MEM_COMMIT gpu_addr=0x%llx pages=%llu\n",
                c->gpu_addr, c->pages);
        break;
    }

    case KBASE_FUNC_MEM_FLAGS_CHANGE: {
        struct {
            union uk_header header;
            u64 gpu_va;
            u64 flags;
            u64 mask;
        } *f = args;

        if (size < 32) goto bad_size;
        pr_info("mali_stub: MEM_FLAGS_CHANGE gpu_va=0x%llx flags=0x%llx mask=0x%llx\n",
                f->gpu_va, f->flags, f->mask);
        break;
    }

    case KBASE_FUNC_MEM_IMPORT:
    case KBASE_FUNC_MEM_ALIAS:
        pr_info("mali_stub: %s (stub)\n", func_name(id));
        break;

    case KBASE_FUNC_JOB_SUBMIT:
    case KBASE_FUNC_JOB_SUBMIT_UK6:
        pr_info("mali_stub: %s (no-op, no GPU)\n", func_name(id));
        ukh->ret = MALI_ERROR_FUNCTION_FAILED;
        break;

    case KBASE_FUNC_SYNC:
        pr_info("mali_stub: SYNC (no-op)\n");
        break;

    case KBASE_FUNC_HWCNT_SETUP:
    case KBASE_FUNC_HWCNT_DUMP:
    case KBASE_FUNC_HWCNT_CLEAR:
    case KBASE_FUNC_HWCNT_READER_SETUP:
        pr_info("mali_stub: %s (no HW counters)\n", func_name(id));
        ukh->ret = MALI_ERROR_FUNCTION_FAILED;
        break;

    case KBASE_FUNC_GPU_PROPS_REG_DUMP: {
        /*
         * Real driver: dumps GPU property registers
         * We return fake props matching T720 r7p0
         */
        pr_info("mali_stub: GPU_PROPS_REG_DUMP (fake T720 props)\n");
        /* Leave buffer mostly zeroed — caller gets "empty" props */
        break;
    }

    case KBASE_FUNC_GET_VERSION: {
        struct {
            union uk_header header;
            u16 major;
            u16 minor;
        } *ver = args;

        if (size >= sizeof(*ver)) {
            ver->major = 10;
            ver->minor = 0;
        }
        pr_info("mali_stub: GET_VERSION -> 10.0\n");
        break;
    }

    case KBASE_FUNC_GET_CONTEXT_ID: {
        struct {
            union uk_header header;
            s64 id;
        } *cid = args;

        if (size >= 16)
            cid->id = ctx->context_id;
        pr_info("mali_stub: GET_CONTEXT_ID -> %u\n", ctx->context_id);
        break;
    }

    case KBASE_FUNC_DISJOINT_QUERY: {
        struct {
            union uk_header header;
            u32 counter;
        } *dq = args;

        if (size >= 12)
            dq->counter = 0;
        pr_info("mali_stub: DISJOINT_QUERY -> 0\n");
        break;
    }

    case KBASE_FUNC_FIND_CPU_OFFSET: {
        struct {
            union uk_header header;
            u64 gpu_addr;
            u64 cpu_addr;
            u64 size;
            u64 offset;
        } *find = args;

        if (size < 40) goto bad_size;
        find->offset = 0;
        pr_info("mali_stub: FIND_CPU_OFFSET gpu=0x%llx cpu=0x%llx\n",
                find->gpu_addr, find->cpu_addr);
        break;
    }

    case KBASE_FUNC_FENCE_VALIDATE:
    case KBASE_FUNC_STREAM_CREATE:
    case KBASE_FUNC_EXT_BUFFER_LOCK:
        pr_info("mali_stub: %s (stub)\n", func_name(id));
        break;

    case KBASE_FUNC_POST_TERM:
        pr_info("mali_stub: POST_TERM\n");
        break;

    case KBASE_FUNC_SET_TEST_DATA:
    case KBASE_FUNC_INJECT_ERROR:
    case KBASE_FUNC_MODEL_CONTROL:
        pr_info("mali_stub: %s (debug, no-op)\n", func_name(id));
        break;

    case KBASE_FUNC_KEEP_GPU_POWERED:
        pr_info("mali_stub: KEEP_GPU_POWERED (deprecated, no-op)\n");
        break;

    case KBASE_FUNC_GET_PROFILING_CONTROLS:
    case KBASE_FUNC_SET_PROFILING_CONTROLS:
    case KBASE_FUNC_DEBUGFS_MEM_PROFILE_ADD:
        pr_info("mali_stub: %s (profiling, no-op)\n", func_name(id));
        break;

    case KBASE_FUNC_TLSTREAM_ACQUIRE:
    case KBASE_FUNC_TLSTREAM_TEST:
    case KBASE_FUNC_TLSTREAM_STATS:
    case KBASE_FUNC_TLSTREAM_FLUSH:
        pr_info("mali_stub: %s (timeline, no-op)\n", func_name(id));
        break;

    default:
        if (id >= UK_FUNC_ID && id < KBASE_FUNC_MAX) {
            pr_info("mali_stub: unhandled func %u (%s)\n",
                    id, func_name(id));
        } else {
            pr_warn("mali_stub: UNKNOWN func %u (out of range)\n", id);
            ukh->ret = MALI_ERROR_FUNCTION_FAILED;
        }
        break;
    }

    return 0;

bad_size:
    pr_warn("mali_stub: bad size for func %u: got %u\n", id, size);
    ukh->ret = MALI_ERROR_FUNCTION_FAILED;
    return 0;
}

/* === ioctl — mirrors real kbase_ioctl exactly === */
static long mali_stub_ioctl(struct file *filp, unsigned int cmd,
                            unsigned long arg)
{
    u64 msg[(CALL_MAX_SIZE + 7) >> 3];
    u32 size = _IOC_SIZE(cmd);
    struct mali_stub_ctx *ctx = filp->private_data;
    int ret;

    memset(msg, 0, sizeof(msg));

    if (size > CALL_MAX_SIZE)
        return -ENOTTY;

    if (copy_from_user(&msg, (void __user *)arg, size)) {
        pr_err("mali_stub: copy_from_user failed (size=%u)\n", size);
        return -EFAULT;
    }

    mutex_lock(&ctx->lock);
    ret = mali_stub_dispatch(ctx, &msg, size);
    mutex_unlock(&ctx->lock);

    if (ret)
        return ret;

    if (copy_to_user((void __user *)arg, &msg, size)) {
        pr_err("mali_stub: copy_to_user failed\n");
        return -EFAULT;
    }

    return 0;
}

static int mali_stub_open(struct inode *inode, struct file *filp)
{
    struct mali_stub_ctx *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    mutex_init(&ctx->lock);
    ctx->context_id = atomic_inc_return(&next_ctx_id);

    filp->private_data = ctx;
    pr_info("mali_stub: opened (ctx_id=%u, pid=%d)\n",
            ctx->context_id, current->pid);
    return 0;
}

static int mali_stub_release(struct inode *inode, struct file *filp)
{
    struct mali_stub_ctx *ctx = filp->private_data;

    pr_info("mali_stub: closed (ctx_id=%u, allocs=%llu, frees=%llu)\n",
            ctx->context_id, ctx->alloc_count, ctx->free_count);

    kfree(ctx);
    return 0;
}

static const struct file_operations mali_stub_fops = {
    .owner          = THIS_MODULE,
    .open           = mali_stub_open,
    .release        = mali_stub_release,
    .unlocked_ioctl = mali_stub_ioctl,
    .compat_ioctl   = mali_stub_ioctl,
};

static struct miscdevice mali_stub_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "mali0",
    .fops  = &mali_stub_fops,
    .mode  = 0666,
};

static int __init mali_stub_init(void)
{
    int ret = misc_register(&mali_stub_dev);
    if (ret) {
        pr_err("mali_stub: failed to register misc device: %d\n", ret);
        return ret;
    }
    pr_info("mali_stub: /dev/mali0 registered (r7p0 stub, %u functions)\n",
            KBASE_FUNC_MAX - UK_FUNC_ID);
    return 0;
}

static void __exit mali_stub_exit(void)
{
    misc_deregister(&mali_stub_dev);
    pr_info("mali_stub: /dev/mali0 unregistered\n");
}

module_init(mali_stub_init);
module_exit(mali_stub_exit);
