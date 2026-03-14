#!/usr/bin/env python3
"""Test BNEP connection after pairing - requires bluetoothd running."""
import socket, struct, time, sys

TARGET = '02:00:00:00:00:21'
PSM_BNEP = 15  # 0x000F

print(f'[*] Connecting L2CAP STREAM to {TARGET} PSM={PSM_BNEP} (BNEP)...')
s = socket.socket(31, 1, 3)  # AF_BLUETOOTH, SOCK_STREAM, BTPROTO_L2CAP
s.settimeout(15)

try:
    s.connect((TARGET, PSM_BNEP))
    print('[+] *** BNEP L2CAP CONNECTED! ***')

    # Send BNEP Setup Connection Request
    # BNEP control type=0x01, subtype=0x01 (setup conn req)
    # UUID size=2, src=0x1115 (PANU), dst=0x1116 (NAP)
    bnep_setup = bytes([0x01, 0x01, 0x02, 0x11, 0x15, 0x11, 0x16])
    s.send(bnep_setup)
    print(f'[+] Sent BNEP Setup Request: {bnep_setup.hex()}')

    time.sleep(1)
    try:
        resp = s.recv(256)
        print(f'[+] Response: {len(resp)} bytes: {resp.hex()}')
        # Parse BNEP Setup Response: type=0x01, subtype=0x02, response_code(2)
        if len(resp) >= 4 and resp[0] == 0x01 and resp[1] == 0x02:
            code = struct.unpack('>H', resp[2:4])[0]
            codes = {0: 'SUCCESS', 1: 'NOT_ALLOWED', 2: 'INVALID_DST', 
                     3: 'INVALID_SRC', 4: 'INVALID_SIZE', 5: 'NOT_ALLOWED'}
            print(f'[+] BNEP Setup Response: {codes.get(code, f"unknown({code})")}')
            if code == 0:
                print('[+] *** BNEP SETUP SUCCESSFUL! CHANNEL FULLY OPEN! ***')
    except socket.timeout:
        print('[*] No response (timeout) - BNEP may still be processing')

    # Now we can send malformed BNEP packets to trigger CVE-2017-0782!
    print('[*] BNEP channel ready for exploitation')
    s.close()

except socket.error as e:
    print(f'[-] Connection failed: {e}')
    if e.errno == 111:
        print('    Connection refused - PSM not accepting')
    elif e.errno == 13:
        print('    Permission denied - not paired or auth failed')
    elif e.errno == 94:
        print('    Socket type not supported - try SOCK_SEQPACKET(5)')
    sys.exit(1)
