#!/usr/bin/env python3
"""Probe Samsung hidden AT commands and CFUN modes."""
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
send_at(ser, "AT+CMEE=2")

print("=== Samsung Hidden AT Command Probing ===\n")

# Try $ARMEE with different args
print("--- AT$ARMEE ---")
for arg in ["", "?", "=?", "=0", "=1", "=2"]:
    resp = send_at(ser, f"AT$ARMEE{arg}", timeout=1)
    clean = resp.replace(f"AT$ARMEE{arg}", "").strip()
    if clean:
        print(f"  AT$ARMEE{arg}: {clean}")

# CFUN modes - Samsung has proprietary modes 4-12
print("\n--- AT+CFUN Mode Details ---")
# Query current
resp = send_at(ser, "AT+CFUN?", timeout=1)
print(f"  Current: {resp}")
# DON'T change CFUN modes as some could reset device or enable radio

# Try Samsung hidden commands (not in CLAC but may exist)
print("\n--- Hidden Samsung Commands ---")
hidden_cmds = [
    # Samsung UART debug
    "AT+SYSINFO", "AT+SYSINFO?",
    "AT+SYSINFOEX", "AT+SYSINFOEX?",
    # Samsung download mode
    "AT+FUS?", "AT+FUSG?",
    # Samsung engineering
    "AT+DUMPCTRL", "AT+DUMPCTRL?", "AT+DUMPCTRL=?",
    "AT+DEBUG", "AT+DEBUG?", "AT+DEBUG=?",
    "AT+SYSLOG", "AT+SYSLOG?", "AT+SYSLOG=?",
    # Samsung RIL
    "AT+RILMGR", "AT+RILMGR?",
    # Samsung security
    "AT+IMEICHECK", "AT+IMEICHECK?",
    "AT+IMEICHECK=?",
    # Samsung service mode
    "AT+SVCMODE", "AT+SVCMODE?",
    "AT+SVCMODE=?",
    # Samsung CP crash
    "AT+CPCRASH", "AT+CPCRASH?",
    # Shannon specific
    "AT+XDBGMEM", "AT+XDBGMEM?",
    "AT+XSIMSTATE", "AT+XSIMSTATE?",
    "AT+XPOW", "AT+XPOW?",
    # Qualcomm-style (Samsung may support)  
    "AT$QCPWRDN", "AT$QCDMG", "AT$QCDMR",
    "AT$QCSYSMODE",
    # Samsung EFS
    "AT+EFSREAD", "AT+EFSCLEAR",
    # Samsung calibration
    "AT+CALDATA", "AT+CALDATA?",
    # Samsung command mode
    "AT+DIAG", "AT+DIAGMODE",
    # Generic but sometimes hidden
    "AT+IPR=?",
    "AT+ICF=?",
    "AT+IFC=?",
    "ATI0", "ATI1", "ATI2", "ATI3", "ATI4", "ATI5", "ATI6", "ATI7", "ATI8", "ATI9",
    # Samsung USSD
    "AT+CUSD=1,\"*#06#\"",
    # Samsung PSM
    "AT+CPSMS?", "AT+CPSMS=?",
    # Samsung Network
    "AT+COPS=?",  # Full network scan - might take long
    # Samsung CP version
    "AT+CPVER", "AT+CPVER?",
    "AT+VERSNAME?",
    "AT+VERSNAME=?",
]

for cmd in hidden_cmds:
    resp = send_at(ser, cmd, timeout=1.5)
    clean = resp.replace(cmd, "").strip()
    # Only print if we got something other than ERROR
    if clean and "ERROR" not in clean:
        print(f"  {cmd}: {clean}")

# Try to unlock PN lock with empty/default passwords
print("\n--- PN Lock Status ---")
resp = send_at(ser, 'AT+CLCK="PN",2', timeout=1)
print(f"  Status: {resp}")
# NOTE: Not attempting unlock as it has retry limits

# Check CEER for last error details
print("\n--- AT+CEER (Extended Error) ---")
resp = send_at(ser, "AT+CEER", timeout=1)
print(f"  {resp}")

# Check available character sets
print("\n--- AT+CSCS (Character Sets) ---")
resp = send_at(ser, "AT+CSCS=?", timeout=1)
print(f"  {resp}")

# Check current time
print("\n--- AT+CCLK (Clock) ---")
resp = send_at(ser, "AT+CCLK?", timeout=1)
print(f"  {resp}")

# Check multiplexing
print("\n--- AT+CMUX (Multiplexing) ---")
resp = send_at(ser, "AT+CMUX=?", timeout=1)
print(f"  {resp}")

ser.close()
print("\nDone")
