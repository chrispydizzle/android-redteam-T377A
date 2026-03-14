#!/usr/bin/env python3
"""
Refined DM buffer boundary probe around the 512-byte edge.
Tests exact sizes around the boundary with proper serial state management.
"""
import serial
import time
import subprocess
import datetime

COM_PORT = "COM11"
BAUD_RATE = 115200

DM_START = 0x7F
DM_END = 0x7E

def check_diagexe():
    r = subprocess.run(["adb", "shell", "ps | grep diagexe"], capture_output=True, text=True, timeout=5)
    lines = [l for l in r.stdout.strip().split('\n') if 'diagexe' in l and 'grep' not in l]
    if lines:
        pid = lines[0].split()[1]
        return int(pid)
    return None

def send_recv(ser, data, wait=0.5):
    ser.reset_input_buffer()
    ser.write(data)
    ser.flush()
    time.sleep(wait)
    resp = b""
    while ser.in_waiting:
        resp += ser.read(ser.in_waiting)
        time.sleep(0.05)
    return resp

def make_frame(payload):
    return bytes([DM_START]) + payload + bytes([DM_END])

def main():
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] DM Buffer Boundary Probe")
    
    pid = check_diagexe()
    print(f"Initial diagexe PID: {pid}")
    
    ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1.0)
    
    # Reset modem state: send AT\r\n to get clean state
    print("\n--- Resetting serial state ---")
    ser.write(b"AT\r\n")
    time.sleep(1.0)
    resp = ser.read(ser.in_waiting) if ser.in_waiting else b""
    print(f"AT reset: {resp}")
    
    # Quick baseline: verify responses work
    print("\n--- Baseline ---")
    frame = make_frame(b"\x41" * 10)  # 10 bytes of 'A'
    resp = send_recv(ser, frame, 0.5)
    print(f"payload=10: resp={len(resp)}b -> {resp[:20].hex() if resp else 'NONE'}")
    
    # Precise boundary search: every byte from 500 to 530
    print("\n--- Precise boundary search (500-530) ---")
    prev_had_resp = True
    for size in range(500, 531):
        payload = b"\x41" * size
        frame = make_frame(payload)
        resp = send_recv(ser, frame, 0.3)
        status = f"resp={len(resp):4d}b" if resp else "no_resp    "
        marker = " <<< BOUNDARY" if (size > 500 and not resp and prev_had_resp) or (resp and not prev_had_resp and size > 500) else ""
        prev_had_resp = bool(resp)
        print(f"  payload={size:4d} frame={len(frame):4d} -> {status}{marker}")
    
    # Anomaly investigation: what was the 190-byte response at 514?
    print("\n--- 514 retry (3 attempts) ---")
    for attempt in range(3):
        # Reset state between attempts
        ser.write(b"AT\r\n")
        time.sleep(0.5)
        ser.read(ser.in_waiting)
        
        payload = b"\x41" * 514
        frame = make_frame(payload)
        resp = send_recv(ser, frame, 0.5)
        if resp:
            print(f"  Attempt {attempt}: resp={len(resp)}b first_16={resp[:16].hex()} last_8={resp[-8:].hex()}")
        else:
            print(f"  Attempt {attempt}: no_resp")
    
    # Test: does the 200 anomaly reproduce?
    print("\n--- 200-byte anomaly check ---")
    for cmd_byte in [0x01, 0x41, 0x73, 0xFF]:
        payload = bytes([cmd_byte]) + b"\x41" * 199
        frame = make_frame(payload)
        resp = send_recv(ser, frame, 0.5)
        status = f"resp={len(resp)}b" if resp else "no_resp"
        print(f"  cmd=0x{cmd_byte:02x} payload=200: {status}")
    
    # Test: 512 with different fill bytes (not just 0x41)
    print("\n--- 512 with different fill bytes ---")
    for fill in [0x00, 0x01, 0x41, 0x7D, 0xFF]:
        payload = bytes([fill]) * 512
        frame = make_frame(payload)
        resp = send_recv(ser, frame, 0.5)
        status = f"resp={len(resp)}b" if resp else "no_resp"
        print(f"  fill=0x{fill:02x} payload=512: {status}")
    
    # Test: What happens at exact USB buffer boundary (512 frame = 510 payload + 2 delimiters)
    print("\n--- USB frame boundary test ---")
    for frame_size in [510, 511, 512, 513, 514, 515, 516]:
        payload_size = frame_size - 2  # minus start+end delimiters
        if payload_size < 0:
            continue
        payload = b"\x41" * payload_size
        frame = make_frame(payload)
        resp = send_recv(ser, frame, 0.3)
        status = f"resp={len(resp):4d}b" if resp else "no_resp    "
        print(f"  frame={frame_size:4d} payload={payload_size:4d} -> {status}")
    
    # Check diagexe after all tests
    new_pid = check_diagexe()
    print(f"\nFinal diagexe PID: {new_pid} {'(CHANGED!)' if new_pid != pid else '(same)'}")
    
    ser.close()
    print("Done.")

main()
