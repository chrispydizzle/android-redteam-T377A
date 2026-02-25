#!/usr/bin/env python3
"""Samsung DM/DIAG port probe for SM-T377A Shannon 308 modem"""
import serial
import time
import struct

PORT = 'COM9'
BAUD = 115200

def probe():
    s = serial.Serial(PORT, BAUD, timeout=2)
    print(f"Opened {PORT} at {BAUD} baud")
    
    # Samsung SIPC DIAG framing: 0x7E ... data ... CRC ... 0x7E
    # Try various DIAG command codes
    
    tests = [
        ("NULL cmd",        bytes([0x7e, 0x00, 0x00, 0x00, 0x7e])),
        ("Version",         bytes([0x7e, 0x0c, 0x00, 0x00, 0x7e])),
        ("Status",          bytes([0x7e, 0x01, 0x00, 0x00, 0x7e])),
        ("NV Read 0",       bytes([0x7e, 0x26, 0x00, 0x00, 0x00, 0x00, 0x7e])),
        ("Log config",      bytes([0x7e, 0x73, 0x00, 0x00, 0x7e])),
        ("Extended build",  bytes([0x7e, 0x7c, 0x00, 0x00, 0x7e])),
        ("Samsung IPC hello", bytes([0xfc, 0xeb, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])),
        ("Raw AT",          b'AT\r\n'),
        ("Raw ATI",         b'ATI\r\n'),
        ("Raw AT+CGMI",     b'AT+CGMI\r\n'),
    ]
    
    for name, cmd in tests:
        s.flushInput()
        s.write(cmd)
        time.sleep(0.5)
        resp = s.read(4096)
        if resp:
            print(f"[+] {name}: {len(resp)} bytes: {resp[:64].hex()}")
            # Try to decode as ASCII too
            try:
                ascii_part = resp.decode('ascii', errors='replace')
                if any(c.isalpha() for c in ascii_part):
                    print(f"    ASCII: {ascii_part[:80]}")
            except:
                pass
        else:
            print(f"[-] {name}: no response")
    
    # Try reading raw data (maybe the port streams something)
    print("\n[*] Listening for 3 seconds...")
    s.timeout = 3
    data = s.read(8192)
    if data:
        print(f"[+] Received {len(data)} bytes: {data[:100].hex()}")
    else:
        print("[-] No data received")
    
    s.close()
    print("Done")

if __name__ == '__main__':
    probe()
