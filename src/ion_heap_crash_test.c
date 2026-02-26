/*
 * ion_heap_crash_test.c — Test which ION heap_id_mask values crash
 *
 * Theory: The previous crashes were from ION_IOC_ALLOC with heap_id_mask=0x1000
 * (bit 12) caused by a wrong struct layout (uint64_t instead of uint32_t fields).
 *
 * This tests each heap bit individually to find which ones crash.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

/* ARM32 correct struct: all 32-bit fields, total 20 bytes */
struct ion_alloc_data {
    uint32_t len;
    uint32_t align;
    uint32_t heap_id_mask;
    uint32_t flags;
    uint32_t handle;
};

/* ION_IOC_ALLOC = _IOWR('I', 0, 20) = 0xC0144900 */
#define ION_IOC_ALLOC 0xC0144900

static int test_heap(uint32_t heap_mask) {
    int pipefd[2];
    pipe(pipefd);

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        alarm(5);

        int ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
        if (ion < 0) {
            int r = -1;
            write(pipefd[1], &r, sizeof(r));
            close(pipefd[1]);
            _exit(1);
        }

        struct ion_alloc_data d = {
            .len = 4096,
            .align = 4096,
            .heap_id_mask = heap_mask,
            .flags = 0,
            .handle = 0
        };

        int r = ioctl(ion, ION_IOC_ALLOC, &d);
        int e = errno;
        int result[3] = { r, e, d.handle };
        write(pipefd[1], result, sizeof(result));
        close(ion);
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);
    int status;
    waitpid(pid, &status, 0);

    int result[3] = {0};
    read(pipefd[0], result, sizeof(result));
    close(pipefd[0]);

    if (WIFSIGNALED(status)) {
        printf("  heap=0x%08x: SIG%d (KILLED!)\n", heap_mask, WTERMSIG(status));
        return -1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 14) {
        printf("  heap=0x%08x: TIMEOUT (ALARM!)\n", heap_mask);
        return -2;
    }

    printf("  heap=0x%08x: ioctl=%d errno=%d handle=0x%x\n",
           heap_mask, result[0], result[1], result[2]);
    return result[0];
}

int main(int argc, char **argv) {
    printf("=== ION Heap Crash Test ===\n");
    printf("Testing ION_IOC_ALLOC with various heap_id_mask values\n\n");

    /* Test individual bits */
    printf("--- Individual heap bits ---\n");
    for (int bit = 0; bit < 16; bit++) {
        test_heap(1U << bit);
    }

    /* Test the specific problematic value from the old struct */
    printf("\n--- Specific values ---\n");
    test_heap(0x1000);  /* The old struct's effective heap_id_mask */
    test_heap(0x0004);  /* Known crash from repo memory: heap bit 2 */
    test_heap(0);       /* Zero mask */
    test_heap(0xFFFFFFFF); /* All bits */

    printf("\n=== Done ===\n");
    return 0;
}
