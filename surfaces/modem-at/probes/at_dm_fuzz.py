#!/usr/bin/env python3
"""Probe VERSNAME AT command and test DM protocol fuzzing potential."""
import serial
import time

def send_at(ser, cmd, timeout=2):
    try:
        ser.reset_input_buffer()
        ser.write(f"{cmd}\r\n".encode())
        time.sleep(timeout)
        resp = b""
        while ser.in_waiting > 0:
            resp += ser.read(ser.in_waiting)
            time.sleep(0.1)
        return resp.decode('ascii', errors='replace').strip()
    except Exception as e:
        return f"ERROR: {e}"

ser = serial.Serial("COM11", 115200, timeout=2)
send_at(ser, "AT+CMEE=2")

print("=== VERSNAME Probe ===")
for i in range(1, 11):
    resp = send_at(ser, f"AT+VERSNAME={i}", timeout=1)
    clean = resp.replace(f"AT+VERSNAME={i}", "").strip()
    if clean and "ERROR" not in clean:
        print(f"  VERSNAME {i}: {clean}")

print("\n=== DM Protocol Test ===")
# Test sending DM protocol frames through AT port
# diagexe expects 0x7F start, 0x7E end
dm_frames = [
    bytes([0x7F, 0x01, 0x00, 0x7E]),  # Basic DM command
    bytes([0x7F, 0x0C, 0x00, 0x7E]),  # Version query
    bytes([0x7F, 0x1A, 0x00, 0x7E]),  # Feature query
    b"AT+DEVCONINFO\r\n",             # AT mixed mode
]

for i, frame in enumerate(dm_frames):
    ser.reset_input_buffer()
    ser.write(frame)
    time.sleep(1)
    resp = b""
    while ser.in_waiting > 0:
        resp += ser.read(ser.in_waiting)
        time.sleep(0.1)
    if resp:
        print(f"  Frame {i}: sent {frame.hex()}, got {resp.hex()} ({resp[:50]})")
    else:
        print(f"  Frame {i}: sent {frame.hex()}, no response")

print("\n=== Long String Test (buffer overflow check) ===")
# Test if AT commands with long arguments cause issues
test_strings = [
    "A" * 100,
    "A" * 256,
    "A" * 512,
    "A" * 1024,
]
for s in test_strings:
    resp = send_at(ser, f"AT+VERSNAME={s}", timeout=1)
    clean = resp.strip()
    if "ERROR" in clean:
        print(f"  VERSNAME len={len(s)}: ERROR (normal)")
    elif not clean:
        print(f"  VERSNAME len={len(s)}: NO RESPONSE (possible crash!)")
    else:
        print(f"  VERSNAME len={len(s)}: {clean[:80]}")

# Test long DEVCONINFO
for s in test_strings:
    resp = send_at(ser, f"AT+DEVCONINFO={s}", timeout=1)
    clean = resp.strip()
    if "ERROR" in clean:
        print(f"  DEVCONINFO len={len(s)}: ERROR")
    elif not clean:
        print(f"  DEVCONINFO len={len(s)}: NO RESPONSE!")
    else:
        print(f"  DEVCONINFO len={len(s)}: {clean[:80]}")

ser.close()
print("\nDone")
