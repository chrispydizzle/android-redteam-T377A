#!/usr/bin/env python3
"""
DM/HDLC protocol probe for Samsung diagexe on SM-T377A.
Connects to COM18 (DIAGSERD device) and sends DM commands.

diagexe binary analysis shows:
  - DM_MSG_START_FLAG(0x7F) / DM_MSG_END_FLAG(0x7E)
  - Handles file operations (DoFileOperation thread)
  - Bridges to modem via /dev/umts_dm0 + /dev/ttyGS1

Standard DM HDLC framing:
  [0x7E] [cmd_code] [payload...] [CRC16_lo] [CRC16_hi] [0x7E]
  Escape: 0x7D followed by (byte XOR 0x20) for 0x7D and 0x7E in payload

Samsung variant uses 0x7F as start flag per diagexe strings.
"""

import serial
import struct
import time
import sys
import argparse

# CRC16 lookup table (CCITT polynomial 0x1021, reversed 0x8408)
CRC16_TABLE = []
for i in range(256):
    crc = i
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0x8408
        else:
            crc >>= 1
    CRC16_TABLE.append(crc)

def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFF

def hdlc_encode(payload: bytes, start_flag: int = 0x7E) -> bytes:
    """Encode a DM payload with HDLC framing and CRC."""
    crc = crc16(payload)
    crc_bytes = struct.pack('<H', crc)
    raw = payload + crc_bytes

    # Escape 0x7D and 0x7E in payload
    escaped = bytearray()
    for b in raw:
        if b == 0x7E or b == 0x7D:
            escaped.append(0x7D)
            escaped.append(b ^ 0x20)
        else:
            escaped.append(b)

    frame = bytes([start_flag]) + bytes(escaped) + bytes([0x7E])
    return frame

def hdlc_decode(frame: bytes) -> bytes:
    """Decode HDLC frame, strip flags and unescape."""
    if len(frame) < 4:
        return b''
    inner = frame
    if inner[0] in (0x7E, 0x7F):
        inner = inner[1:]
    if inner and inner[-1] == 0x7E:
        inner = inner[:-1]

    # Unescape
    payload = bytearray()
    i = 0
    while i < len(inner):
        if inner[i] == 0x7D:
            i += 1
            if i < len(inner):
                payload.append(inner[i] ^ 0x20)
        else:
            payload.append(inner[i])
        i += 1

    # Strip CRC (last 2 bytes)
    if len(payload) >= 2:
        return bytes(payload[:-2])
    return bytes(payload)

def recv_frame(ser: serial.Serial, timeout: float = 2.0) -> bytes:
    """Read until a complete 0x7E-terminated frame is received."""
    deadline = time.time() + timeout
    buf = bytearray()
    in_frame = False
    while time.time() < deadline:
        b = ser.read(1)
        if not b:
            continue
        val = b[0]
        if val == 0x7E or val == 0x7F:
            if in_frame and len(buf) > 0:
                buf.append(val)
                return bytes(buf)
            buf = bytearray([val])
            in_frame = True
        elif in_frame:
            buf.append(val)
    return bytes(buf) if buf else b''

# DM command codes
CMD_VERSION_INFO      = 0x00  # Version info
CMD_ESN               = 0x01  # ESN request (CDMA)
CMD_MEMORY_PEEK_BYTE  = 0x02  # Read 1 byte from address
CMD_MEMORY_PEEK_WORD  = 0x03  # Read 2 bytes
CMD_MEMORY_PEEK_DWORD = 0x04  # Read 4 bytes
CMD_NV_READ           = 0x26  # NV item read
CMD_NV_WRITE          = 0x27  # NV item write
CMD_DIAG_SUBSYS       = 0x4B  # Subsystem dispatch (command 75)
CMD_STATUS            = 0x0C  # Status request

def send_cmd(ser, payload: bytes, start_flag: int = 0x7E, timeout: float = 2.0):
    """Send a DM command and receive the response."""
    frame = hdlc_encode(payload, start_flag)
    print(f"  TX ({len(frame)} bytes): {frame.hex()}")
    ser.write(frame)
    ser.flush()

    resp = recv_frame(ser, timeout)
    if resp:
        decoded = hdlc_decode(resp)
        print(f"  RX ({len(resp)} bytes raw): {resp.hex()}")
        print(f"  RX decoded ({len(decoded)} bytes): {decoded.hex()}")
        if decoded:
            try:
                text = decoded.decode('ascii', errors='replace')
                print(f"  RX text: {text!r}")
            except Exception:
                pass
        return decoded
    else:
        print(f"  RX: timeout/empty")
        return b''

def main():
    parser = argparse.ArgumentParser(description='DM/HDLC probe for Samsung diagexe')
    parser.add_argument('--port', default='COM18', help='COM port (default: COM18)')
    parser.add_argument('--baud', type=int, default=115200, help='Baud rate (default: 115200)')
    parser.add_argument('--start-flag', type=lambda x: int(x, 0), default=0x7E,
                        help='Start flag byte (default: 0x7E, try 0x7F per diagexe strings)')
    args = parser.parse_args()

    print(f"[*] Opening {args.port} at {args.baud} baud")
    try:
        ser = serial.Serial(args.port, args.baud, timeout=0.1,
                           bytesize=8, parity='N', stopbits=1)
    except serial.SerialException as e:
        print(f"[!] Failed to open {args.port}: {e}")
        sys.exit(1)

    print(f"[*] Port opened. Start flag: 0x{args.start_flag:02X}")

    # Flush any pending data
    ser.reset_input_buffer()
    time.sleep(0.2)

    # Test 1: CMD_VERSION_INFO (0x00) - basic version request, standard start flag
    print("\n[1] CMD_VERSION_INFO (0x00) with 0x7E start")
    send_cmd(ser, bytes([CMD_VERSION_INFO]), 0x7E)
    time.sleep(0.2)

    # Test 2: Same with 0x7F start flag (Samsung diagexe DM_MSG_START_FLAG variant)
    print("\n[2] CMD_VERSION_INFO with 0x7F start flag")
    send_cmd(ser, bytes([CMD_VERSION_INFO]), 0x7F)
    time.sleep(0.2)

    # Test 3: Raw 0x7E wake-up bytes and listen
    print("\n[3] Raw 0x7E wake-up")
    ser.write(b'\x7e\x7e\x7e')
    time.sleep(0.5)
    data = ser.read(512)
    if data:
        print(f"  RX after wake: {data.hex()}")
    else:
        print("  RX: empty")

    # Test 4: CMD_STATUS (0x0C)
    print("\n[4] CMD_STATUS (0x0C)")
    send_cmd(ser, bytes([CMD_STATUS]), 0x7E)
    time.sleep(0.2)

    # Test 5: CMD_DIAG_SUBSYS with various subsystem IDs
    print("\n[5] CMD_DIAG_SUBSYS (0x4B) subsystem sweep")
    for subsys in [0x00, 0x01, 0x04, 0x0B, 0x12, 0x14, 0x3C, 0xFF]:
        payload = struct.pack('<BHH', CMD_DIAG_SUBSYS, subsys, 0x0000)
        print(f"  Subsys 0x{subsys:02X}:")
        resp = send_cmd(ser, payload, 0x7E, timeout=1.0)
        time.sleep(0.1)

    # Test 6: NV read probe (NV item 0 = ESN)
    print("\n[6] CMD_NV_READ (0x26) NV item 0 (ESN)")
    payload = struct.pack('<BH', CMD_NV_READ, 0x0000) + b'\x00' * 128
    send_cmd(ser, payload, 0x7E)

    # Test 7: Memory peek at address 0
    print("\n[7] CMD_MEMORY_PEEK_DWORD (0x04) at addr 0x00000000")
    payload = struct.pack('<BIB', CMD_MEMORY_PEEK_DWORD, 0x00000000, 4)
    send_cmd(ser, payload, 0x7E)

    # Test 8: Large payload to probe buffer handling
    print("\n[8] Oversized CMD_VERSION_INFO payload (2048 bytes)")
    big_payload = bytes([CMD_VERSION_INFO]) + b'\x41' * 2047
    send_cmd(ser, big_payload, 0x7E, timeout=3.0)

    ser.close()
    print("\n[*] Done")

if __name__ == '__main__':
    main()
