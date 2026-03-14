#!/usr/bin/env python3
"""Safe probe of hidden Samsung AT commands. Avoids $ARMEE=1 and CFUN changes."""
import serial
import time
import sys

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
        return f"SERIAL_ERROR: {e}"

port = sys.argv[1] if len(sys.argv) > 1 else "COM11"
ser = serial.Serial(port, 115200, timeout=2)
send_at(ser, "AT+CMEE=2")
print(f"Port {port} opened\n")

print("=== ATI Variants ===")
for i in range(10):
    resp = send_at(ser, f"ATI{i}", timeout=1)
    clean = resp.replace(f"ATI{i}", "").strip()
    if clean and "ERROR" not in clean:
        print(f"  ATI{i}: {clean}")

print("\n=== S-Register Scan ===")
for i in range(30):
    resp = send_at(ser, f"ATS{i}?", timeout=0.5)
    clean = resp.replace(f"ATS{i}?", "").strip()
    if clean and "ERROR" not in clean:
        print(f"  S{i}: {clean}")

print("\n=== Hidden Samsung Read-Only Commands ===")
safe_read_cmds = [
    # Info queries only (? suffix = read, =? = test/range)
    "AT+IPR?", "AT+IPR=?",
    "AT+ICF?", "AT+ICF=?",
    "AT+IFC?", "AT+IFC=?",
    "AT+VERSNAME?", "AT+VERSNAME=?",
    "AT+CNUM",
    "AT+CEER",
    "AT+CSCS?", "AT+CSCS=?",
    "AT+CCLK?",
    "AT+CMUX=?",
    "AT+CPIN?",
    "AT+CDIS?", "AT+CDIS=?",
    "AT+CDU?", "AT+CDU=?",
    "AT+CHST?", "AT+CHST=?",
    "AT+CHSN?", "AT+CHSN=?",
    "AT+CLAE?", "AT+CLAE=?",
    "AT+CNMPSD?", "AT+CNMPSD=?",
    "AT+CSSN?", "AT+CSSN=?",
    "AT+CTZR?", "AT+CTZR=?",
    "AT+CVMOD?", "AT+CVMOD=?",
    "AT+FCLASS?", "AT+FCLASS=?",
    "AT+CGCLASS?", "AT+CGCLASS=?",
    "AT+CPLS?", "AT+CPLS=?",
    "AT+CSMS?", "AT+CSMS=?",
    "AT+CMGF?",
    "AT+CPMS?", "AT+CPMS=?",
    "AT+CNMI?", "AT+CNMI=?",
    "AT+CSCA?",
    "AT+CSMP?",
    "AT+CSDH?",
    "AT+CLCC",
    "AT+CMOD?", "AT+CMOD=?",
    "AT+CBST?", "AT+CBST=?",
    "AT+CRLP?", "AT+CRLP=?",
    "AT+CR?",
    "AT+CRC?",
    "AT+CMEC?", "AT+CMEC=?",
    "AT+CMER?", "AT+CMER=?",
    "AT+CACM?",
    "AT+CAMM?",
    "AT+CPUC?",
    "AT&V",
    # Samsung dollar commands
    "AT$ARMEE?",
    "AT$CREG?", "AT$CREG=?",
    "AT$CSQ",
    # Samsung star commands
    "AT*CNTI=0", "AT*CNTI=?",
    # Extended
    "AT+PACSP?", "AT+PACSP=?",
    "AT+ECNO?", "AT+ECNO=?",
    "AT+RSCP?", "AT+RSCP=?",
    "AT+RSRP?", "AT+RSRP=?",
    "AT+RSRQ?", "AT+RSRQ=?",
]

for cmd in safe_read_cmds:
    resp = send_at(ser, cmd, timeout=1)
    clean = resp.replace(cmd, "").strip()
    if clean and "ERROR" not in clean and len(clean) > 1:
        # Format multiline output
        print(f"  {cmd}: {clean[:200]}")

print("\n=== SIM APDU (AT+CSIM) ===")
# Try sending APDU even without SIM to see if modem processes them
apdus = [
    ("00A40000023F00", "SELECT MF"),
    ("00A40000027F20", "SELECT DF_GSM"),
    ("00B00000FF", "READ BINARY"),
    ("80CA006F00", "GET DATA"),
]
for apdu, desc in apdus:
    resp = send_at(ser, f'AT+CSIM={len(apdu)},"{apdu}"', timeout=1)
    clean = resp.replace(f'AT+CSIM={len(apdu)},"{apdu}"', "").strip()
    if "ERROR" not in clean:
        print(f"  {desc}: {clean}")

print("\n=== AT+CLCK Detailed (Facility Locks) ===")
# Re-verify lock states
locks = [
    ("SC", "SIM PIN"), ("FD", "Fixed Dial"), ("PN", "Network"),
    ("PU", "Network Subset"), ("PP", "Service Provider"),
    ("PC", "Corporate"), ("PS", "SIM"),
]
for fac, desc in locks:
    resp = send_at(ser, f'AT+CLCK="{fac}",2', timeout=1)
    clean = resp.replace(f'AT+CLCK="{fac}",2', "").strip()
    print(f"  {fac} ({desc}): {clean}")

print("\n=== SMS Storage ===")
send_at(ser, "AT+CMGF=1", timeout=0.5)
resp = send_at(ser, "AT+CPMS?", timeout=1)
print(f"  Storage: {resp}")
resp = send_at(ser, 'AT+CMGL="ALL"', timeout=2)
clean = resp.replace('AT+CMGL="ALL"', "").strip()
if clean and clean != "OK":
    print(f"  Messages: {clean[:500]}")
else:
    print("  Messages: (none)")

print("\n=== USSD ===")
# Try USSD codes via AT
resp = send_at(ser, 'AT+CUSD=1,"*#06#"', timeout=2)
clean = resp.replace('AT+CUSD=1,"*#06#"', "").strip()
print(f"  *#06#: {clean}")

ser.close()
print("\nDone")
