#!/usr/bin/env python3
"""Deep probe of interesting AT commands on Samsung DM port."""
import serial
import time

def send_at(ser, cmd, timeout=2):
    ser.reset_input_buffer()
    ser.write(f"{cmd}\r\n".encode())
    time.sleep(timeout)
    resp = b""
    while ser.in_waiting > 0:
        resp += ser.read(ser.in_waiting)
        time.sleep(0.1)
    return resp.decode('ascii', errors='replace').strip()

ser = serial.Serial("COM11", 115200, timeout=2)
send_at(ser, "AT+CMEE=2")  # Enable verbose errors

print("=== Interesting AT Commands Deep Probe ===\n")

# Facility lock queries
print("--- AT+CLCK (Facility Locks) ---")
facilities = ["SC", "AO", "OI", "OX", "AI", "IR", "AB", "AG", "AC",
               "FD", "PN", "PU", "PP", "PC", "PS"]
for fac in facilities:
    resp = send_at(ser, f'AT+CLCK="{fac}",2', timeout=1)
    if "ERROR" not in resp or "CME ERROR" in resp:
        print(f"  {fac}: {resp}")

# SIM commands (even without SIM, check if command is accepted)
print("\n--- AT+CRSM (Restricted SIM) ---")
resp = send_at(ser, "AT+CRSM=176,28539,0,0,0")
print(f"  Read ICCID: {resp}")
resp = send_at(ser, "AT+CRSM=176,28423,0,0,9")
print(f"  Read IMSI: {resp}")

# Samsung specific
print("\n--- Samsung Specific ---")
cmds = [
    ("AT$ARMEE", "Army mode"),
    ("AT+DEVCONINFO", "Device config"),
    ("AT+CVMOD?", "Voice mode"),
    ("AT+CVMOD=?", "Voice mode options"),
    ("AT+CEMODE?", "CE mode"),
    ("AT+CEMODE=?", "CE mode options"),
    ("AT*CNTI=0", "Network type"),
    ("AT+PACSP?", "ACSP"),
    ("AT+ECNO?", "ECNO"),
    ("AT+RSCP?", "RSCP"),
    ("AT+RSRP?", "RSRP"),
    ("AT+RSRQ?", "RSRQ"),
    ("AT$CREG?", "Samsung CREG"),
    ("AT$CSQ", "Samsung CSQ"),
    ("AT+WS46?", "Wireless service"),
    ("AT+WS46=?", "Wireless options"),
]
for cmd, desc in cmds:
    resp = send_at(ser, cmd, timeout=1)
    if "ERROR" not in resp:
        print(f"  {cmd} ({desc}): {resp}")

# Keypad emulation
print("\n--- AT+CKPD (Keypad) ---")
resp = send_at(ser, "AT+CKPD=?", timeout=1)
print(f"  Supported: {resp}")
# Don't actually press keys yet

# Phone book access
print("\n--- AT+CPBS (Phonebook) ---")
resp = send_at(ser, 'AT+CPBS=?', timeout=1)
print(f"  Available: {resp}")
resp = send_at(ser, 'AT+CPBS?', timeout=1)
print(f"  Current: {resp}")

# SMS access
print("\n--- AT+CMGL (SMS List) ---")
send_at(ser, "AT+CMGF=1", timeout=1)  # Text mode
resp = send_at(ser, 'AT+CMGL="ALL"', timeout=2)
print(f"  Messages: {resp}")

# Try to read/write NV items (Samsung Shannon)
print("\n--- NV Access Attempts ---")
nv_cmds = [
    'AT+CRSM=178,12258,1,4,0',   # EF_DIR
    'AT+CGLA=0,"00A40804027FFF"',  # Select MF
    'AT+CUAD',                      # UICC application directory
]
for cmd in nv_cmds:
    resp = send_at(ser, cmd, timeout=1)
    if "ERROR" not in resp:
        print(f"  {cmd}: {resp}")

# Extended Samsung commands probing
print("\n--- Extended Samsung Probing ---")
samsung_ext = [
    "AT+CFUN=?",
    "AT+CGATT?",
    "AT+CGATT=?",
    "AT+CHSD",
    "AT+GCAP",
    "AT+CBC",
    "AT+CPAS",
    "ATV1",  # Verbose results
]
for cmd in samsung_ext:
    resp = send_at(ser, cmd, timeout=1)
    if "ERROR" not in resp:
        print(f"  {cmd}: {resp}")

# CRITICAL: Try CFUN=1 to enable radio (would be needed for network access)
print("\n--- Radio State ---")
resp = send_at(ser, "AT+CFUN?", timeout=1)
print(f"  Current: {resp}")
# NOT enabling radio without explicit permission
print("  Note: Radio is OFF (CFUN=0), NOT enabling without permission")

ser.close()
print("\nDone")
