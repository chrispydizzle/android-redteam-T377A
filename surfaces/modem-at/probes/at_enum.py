#!/usr/bin/env python3
"""Deep AT command enumeration on Samsung DM port."""
import serial
import time

def send_at(ser, cmd, timeout=2):
    """Send AT command and return response."""
    ser.reset_input_buffer()
    ser.write(f"{cmd}\r\n".encode())
    time.sleep(timeout)
    resp = b""
    while ser.in_waiting > 0:
        resp += ser.read(ser.in_waiting)
        time.sleep(0.1)
    text = resp.decode('ascii', errors='replace').strip()
    # Remove echo
    lines = text.split('\n')
    if lines and lines[0].strip() == cmd:
        lines = lines[1:]
    return '\n'.join(lines).strip()

ser = serial.Serial("COM11", 115200, timeout=2)
print("COM11 opened")

# Basic info commands
info_cmds = [
    ("ATI", "Device info"),
    ("AT+CGMM", "Model"),
    ("AT+CGMR", "Firmware revision"),
    ("AT+CGSN", "IMEI"),
    ("AT+CIMI", "IMSI"),
    ("AT+CSQ", "Signal quality"),
    ("AT+COPS?", "Operator"),
    ("AT+CFUN?", "Phone functionality"),
    ("AT+CPIN?", "SIM status"),
    ("AT+CREG?", "Network registration"),
    ("AT+CGDCONT?", "PDP context"),
    ("AT+CMEE=2", "Enable verbose errors"),
]

print("\n=== Basic Info ===")
for cmd, desc in info_cmds:
    resp = send_at(ser, cmd)
    print(f"  {cmd} ({desc}): {resp}")

# List all available AT commands
print("\n=== Command List (AT+CLAC) ===")
resp = send_at(ser, "AT+CLAC", timeout=3)
if "OK" in resp:
    commands = [line.strip() for line in resp.split('\n') if line.strip() and line.strip() != 'OK']
    print(f"  Total commands: {len(commands)}")
    # Filter for interesting ones
    interesting = [c for c in commands if any(k in c.upper() for k in 
        ['SEC', 'SAM', 'LOCK', 'UNLOCK', 'ROOT', 'DEBUG', 'ENG', 'TEST', 
         'FACTORY', 'DIAG', 'NV', 'BOOT', 'FLASH', 'FUSE', 'KEY',
         'CERT', 'AUTH', 'ADMIN', 'POWER', 'RESET', 'WIPE', 'FORMAT',
         'DUMP', 'READ', 'WRITE', 'EXEC', 'SHELL', 'CMD', 'SYS',
         'KNOX', 'TIMA', 'DMR', 'OEM', 'CARRIER', 'SIM', 'PIN',
         'ADB', 'USB', 'MODEM', 'BASEBAND', 'IMEI', 'SERIAL'])]
    if interesting:
        print("  Interesting commands:")
        for cmd in interesting:
            print(f"    {cmd}")
    # Print all for reference
    print("\n  All commands:")
    for cmd in commands:
        print(f"    {cmd}")
else:
    print(f"  CLAC failed: {resp}")
    # Try Samsung-specific listing
    resp2 = send_at(ser, "AT$HELP", timeout=3)
    print(f"  AT$HELP: {resp2}")

# Samsung-specific commands
print("\n=== Samsung/Shannon Specific ===")
samsung_cmds = [
    "AT+VERSNAME",
    "AT+DEVCONINFO",
    "AT%SYSLOG",
    "AT%ITEST",
    "AT%KCNFG",
    "AT%NVREAD",
    "AT%KEYSTRING",
    "AT%SYSSLEEP",
    "AT+SSMCMD",
    "AT+XGENDATA",
    "AT+SECBOOT",
    "AT+UNLOCKSIM",
    "AT+SIMLOCKPIN",
    "AT+LOCKSTATE",
    "AT+SIMSLOT",
    "AT%DMROPEN",
    "AT%DMRCLOSE",
    "AT%FACTLOCK",
    "AT%CTZR",
]

for cmd in samsung_cmds:
    resp = send_at(ser, cmd, timeout=1)
    if "ERROR" not in resp or "CME ERROR" in resp:
        print(f"  {cmd}: {resp}")
    else:
        pass  # Skip simple errors

ser.close()
print("\nDone")
