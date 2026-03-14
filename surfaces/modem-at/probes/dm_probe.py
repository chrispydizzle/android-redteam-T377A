#!/usr/bin/env python3
"""Deep AT command enumeration on Samsung SM-T377A modem via COM11."""
import serial
import time
import sys

def send_at(ser, cmd, timeout=2):
    """Send AT command and return response."""
    ser.reset_input_buffer()
    ser.write((cmd + "\r").encode())
    time.sleep(timeout)
    resp = ser.read(ser.in_waiting or 1024)
    return resp.decode('ascii', errors='replace').strip()

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "COM11"
    print(f"=== Samsung AT Command Deep Probe on {port} ===\n")

    ser = serial.Serial(port, 115200, timeout=2)
    print(f"[+] Opened {port}")

    # Phase 1: Basic identification
    print("\n--- PHASE 1: Device Identification ---")
    id_cmds = [
        "ATI", "ATI0", "ATI1", "ATI2", "ATI3", "ATI4", "ATI9",
        "AT+CGMM", "AT+CGMI", "AT+CGMR", "AT+CGSN",
        "AT+GMI", "AT+GMM", "AT+GMR", "AT+GSN",
        "AT+CIMI",  # IMSI
        "AT+ICCID",  # SIM ICCID
    ]
    for cmd in id_cmds:
        r = send_at(ser, cmd, 1)
        lines = [l for l in r.split('\n') if l.strip() and l.strip() not in (cmd, 'OK')]
        if lines and 'ERROR' not in r:
            print(f"  {cmd}: {' | '.join(l.strip() for l in lines)}")

    # Phase 2: Samsung-specific AT commands ($ prefix)
    print("\n--- PHASE 2: Samsung Hidden AT Commands ---")
    samsung_cmds = [
        "AT$QCVERSIONS",
        "AT$SYSINFO",
        "AT$QCPRODTYPE",
        "AT$QCSYSMODE",
        "AT$BREW",
        "AT$QCMIPGETP",
        "AT$QCMRUE",
        "AT$QCDEFPROF",
        "AT$QCPKSP",
        "AT$QCAMS",
        "AT$ARMEE=?",     # Download mode toggle
        "AT$ARMEE?",      # Current value
        "AT$QCCLAC",      # List all AT commands
        "AT$QCSER",
        "AT$QCIMSI",
        "AT$QCCNMI",
        "AT$SECKEYSWAP",
        "AT$SECSETFACTORYMODE",
        "AT$SECGETFACTORYMODE",
        "AT$SECSIMLOCK",
        "AT$SECUNLOCK",
        "AT$SECLOCKINFO",
        "AT$SECDEVINFO",
        "AT$SECREADNV",
        "AT$SECWRITENV",
        "AT$SECFACTORYMODE",
        "AT$SECPRODCMD",
        "AT$SECDBG",
        "AT$SECEFSCMD",
        "AT$SECEFSCLEAR",
        "AT$SECLOG",
        "AT$SECAUTH",
        "AT$SECRILCMD",
        "AT$SECMODEMCMD",
        "AT$AUTOCAT=?",
        "AT$AUTOCAT?",
    ]
    for cmd in samsung_cmds:
        r = send_at(ser, cmd, 1)
        lines = [l for l in r.split('\n') if l.strip() and l.strip() != cmd]
        result = ' | '.join(l.strip() for l in lines if l.strip())
        if result and 'ERROR' not in result:
            print(f"  [OK] {cmd}: {result}")
        elif 'ERROR' in result and 'CME ERROR' in result:
            print(f"  [CME] {cmd}: {result}")

    # Phase 3: Standard 3GPP AT commands for network/config
    print("\n--- PHASE 3: Network & Config ---")
    net_cmds = [
        "AT+COPS?",       # Current operator
        "AT+CREG?",       # Registration status
        "AT+CSQ",         # Signal quality
        "AT+CFUN?",       # Functionality
        "AT+CLAC",        # List all AT commands (standard)
        "AT+CMEE=2",      # Enable verbose errors
        "AT+CPAS",        # Activity status
        "AT+CBC",         # Battery charge
        "AT+CPIN?",       # SIM status
        "AT+CUSD=1,\"*#06#\"",  # USSD query IMEI
    ]
    for cmd in net_cmds:
        r = send_at(ser, cmd, 1)
        lines = [l for l in r.split('\n') if l.strip() and l.strip() != cmd]
        result = ' | '.join(l.strip() for l in lines if l.strip())
        if result and 'ERROR' not in result:
            print(f"  {cmd}: {result}")

    # Phase 4: EFS/NV access commands (highest value for privesc)
    print("\n--- PHASE 4: EFS/NV Access Attempts ---")
    efs_cmds = [
        "AT+CEFS?",
        "AT+CEFS=0,\"/\"",
        'AT$QCNVR=0',     # Read NV item 0
        'AT$QCNVR=10',    # Read NV item 10 (NAM)
        'AT$QCNVR=85',    # SPC code
        "AT%EFSR=\"/\"",
        "AT%EFSR",
        "AT%EFSLS=\"/\"",
        "AT+CSCS?",
        "AT+CSCS=\"UCS2\"",
    ]
    for cmd in efs_cmds:
        r = send_at(ser, cmd, 1)
        lines = [l for l in r.split('\n') if l.strip() and l.strip() != cmd]
        result = ' | '.join(l.strip() for l in lines if l.strip())
        if result:
            tag = "[OK]" if 'ERROR' not in result else "[ERR]"
            print(f"  {tag} {cmd}: {result}")

    # Phase 5: Try to get full command list
    print("\n--- PHASE 5: Command List ---")
    r = send_at(ser, "AT+CLAC", 3)
    if 'ERROR' not in r:
        cmds = [l.strip() for l in r.split('\n') if l.strip().startswith('AT') or l.strip().startswith('+')]
        print(f"  Found {len(cmds)} commands")
        for c in cmds[:100]:
            print(f"    {c}")
        if len(cmds) > 100:
            print(f"    ... and {len(cmds)-100} more")
    else:
        # Try Samsung variant
        r = send_at(ser, "AT$QCCLAC", 3)
        if 'ERROR' not in r:
            cmds = [l.strip() for l in r.split('\n') if l.strip()]
            print(f"  $QCCLAC: Found {len(cmds)} entries")

    ser.close()
    print(f"\n[+] Done")

if __name__ == "__main__":
    main()
