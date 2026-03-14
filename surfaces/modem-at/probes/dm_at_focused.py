#!/usr/bin/env python3
"""
Focused AT command investigation:
1. Full AT+CLAC command list
2. AT+DUMPCTRL deep probing
3. AT+CFUN mode switching
4. All AT& commands
"""
import serial
import time
import subprocess
import datetime

COM_PORT = "COM11"
BAUD_RATE = 115200

def check_diagexe():
    r = subprocess.run(["adb", "shell", "ps | grep diagexe"], capture_output=True, text=True, timeout=5)
    lines = [l for l in r.stdout.strip().split('\n') if 'diagexe' in l and 'grep' not in l]
    if lines:
        return int(lines[0].split()[1])
    return None

def send_at_clean(ser, cmd, wait=1.0):
    """Send AT command with clean state and proper response collection."""
    # Flush any pending data
    time.sleep(0.2)
    if ser.in_waiting:
        ser.read(ser.in_waiting)
    
    ser.reset_input_buffer()
    time.sleep(0.1)
    
    full_cmd = (cmd + "\r\n").encode()
    ser.write(full_cmd)
    ser.flush()
    
    # Wait for response
    time.sleep(wait)
    
    resp = b""
    while True:
        chunk = ser.read(ser.in_waiting) if ser.in_waiting else b""
        if chunk:
            resp += chunk
            time.sleep(0.1)
        else:
            break
    
    try:
        text = resp.decode('ascii', errors='replace')
    except:
        text = resp.hex()
    return text

def main():
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] Focused AT Command Investigation")
    
    pid = check_diagexe()
    print(f"diagexe PID: {pid}")
    
    logfile = f"work/dm_fuzz_logs/at_focused_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log = open(logfile, "w")
    
    ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=2.0)
    
    def lp(msg):
        print(msg)
        log.write(msg + "\n")
        log.flush()
    
    # ===== 1. Full AT+CLAC command list =====
    lp("=== 1. AT+CLAC (Full Command List) ===")
    r = send_at_clean(ser, "AT+CLAC", 2.0)
    lines = [l.strip() for l in r.split('\n') if l.strip() and l.strip() not in ['AT+CLAC', 'OK']]
    lp(f"Total commands found: {len(lines)}")
    for line in lines:
        lp(f"  {line}")
    
    # ===== 2. AT+DEVCONINFO (full) =====
    lp("\n=== 2. AT+DEVCONINFO (Full Output) ===")
    r = send_at_clean(ser, "AT+DEVCONINFO", 1.0)
    lp(r.strip())
    
    # ===== 3. ATI4 (Full Factory Profile) =====
    lp("\n=== 3. ATI4 (Full Factory Profile) ===")
    r = send_at_clean(ser, "ATI4", 1.0)
    lp(r.strip())
    
    # ===== 4. AT+DUMPCTRL Deep Probe =====
    lp("\n=== 4. AT+DUMPCTRL Deep Probe ===")
    
    dumpctrl_tests = [
        "AT+DUMPCTRL",
        "AT+DUMPCTRL?",
        "AT+DUMPCTRL=?",
        "AT+DUMPCTRL=0",
        "AT+DUMPCTRL=1",
        "AT+DUMPCTRL=2",
        "AT+DUMPCTRL=0,0",
        "AT+DUMPCTRL=1,0",
        "AT+DUMPCTRL=1,1",
        "AT+DUMPCTRL=START",
        "AT+DUMPCTRL=STOP",
        "AT+DUMPCTRL=GET",
        "AT+DUMPCTRL=STATUS",
    ]
    
    for cmd in dumpctrl_tests:
        r = send_at_clean(ser, cmd, 0.8)
        clean = r.replace('\r', '').replace(cmd, '').strip()
        lp(f"  {cmd}: {clean[:200]}")
    
    # ===== 5. AT+CFUN Mode Investigation =====
    lp("\n=== 5. AT+CFUN Mode Investigation ===")
    
    # Current mode
    r = send_at_clean(ser, "AT+CFUN?", 0.5)
    lp(f"  Current: {r.strip()}")
    
    # Query available modes
    r = send_at_clean(ser, "AT+CFUN=?", 0.5)
    lp(f"  Available: {r.strip()}")
    
    # Try mode 1 (full functionality - enables radio)
    lp("  Trying AT+CFUN=1 (full radio on)...")
    r = send_at_clean(ser, "AT+CFUN=1", 2.0)
    lp(f"  AT+CFUN=1: {r.strip()}")
    
    # Check if mode changed
    r = send_at_clean(ser, "AT+CFUN?", 0.5)
    lp(f"  After CFUN=1: {r.strip()}")
    
    # If radio is on, try more commands
    r2 = send_at_clean(ser, "AT+COPS?", 0.5)
    lp(f"  AT+COPS? after radio on: {r2.strip()}")
    
    # ===== 6. AT& Commands =====
    lp("\n=== 6. AT& Commands ===")
    
    for suffix in ['D', 'F', 'G', 'J', 'K', 'L', 'M', 'P', 'Q', 'R', 'S', 'V', 'W']:
        for variant in ['', '?', '=?', '0', '1', '2']:
            cmd = f"AT&{suffix}{variant}"
            r = send_at_clean(ser, cmd, 0.5)
            clean = r.replace('\r', '').replace(cmd, '').strip()
            if 'OK' in clean or (clean and 'ERROR' not in clean):
                lp(f"  {cmd}: {clean[:120]}")
    
    # ===== 7. Extended Samsung commands =====
    lp("\n=== 7. Extended Samsung Commands ===")
    
    ext_cmds = [
        "AT+FMM", "AT+FMM?", "AT+FMM=?",
        "AT+CSC?", "AT+CSC",
        "AT+CPLOG", "AT+CPLOG?",
        "AT+CPLOGFLUSH",
        "AT+SILENTLOG", "AT+SILENTLOG?",
        "AT+SLOGCTRL", "AT+SLOGCTRL?",
        "AT+DIAGMODE", "AT+DIAGMODE?",
        "AT+DIAGTEST", "AT+DIAGTEST?",
        "AT+FACTORY", "AT+FACTORY?",
        "AT+LTEINFO", "AT+LTEINFO?",
        "AT+BANDSEL", "AT+BANDSEL?",
        "AT+IMEILOCK", "AT+IMEILOCK?",
        "AT+IMEIWRITE",
        "AT+IMEISV?",
        "AT+VERSNAME", "AT+VERSNAME?",
        "AT+HWVER", "AT+HWVER?",
        "AT+PRODID", "AT+PRODID?",
        "AT+PHONEST?",
        "AT+PHONEMD?",
        "AT+MSLCODE", "AT+MSLCODE?",
        "AT+OTKSL?",
        "AT+OMADM", "AT+OMADM?",
        "AT+LTEBC?",
        "AT+LTENBR?",
        "AT+LTECA?",
    ]
    
    for cmd in ext_cmds:
        r = send_at_clean(ser, cmd, 0.5)
        clean = r.replace('\r', '').replace(cmd, '').strip()
        if 'OK' in clean or ('+' in clean and 'ERROR' not in clean):
            lp(f"  {cmd}: {clean[:200]}")
    
    # ===== 8. Try to get SPC code =====
    lp("\n=== 8. SPC Probe ===")
    
    # Try common SPCs
    for spc in ["000000", "111111", "123456", "303030", "999999", "AAAAAA"]:
        cmd = f"AT+SPC={spc}"
        r = send_at_clean(ser, cmd, 0.5)
        clean = r.replace('\r', '').strip()
        lp(f"  AT+SPC={spc}: {clean[:120]}")
    
    # Try OTKSL
    for code in ["000000", "111111"]:
        cmd = f"AT+OTKSL={code}"
        r = send_at_clean(ser, cmd, 0.5)
        clean = r.replace('\r', '').strip()
        lp(f"  AT+OTKSL={code}: {clean[:120]}")
    
    # ===== 9. ADB check: did anything change on device? =====
    lp("\n=== 9. Device State Check ===")
    
    new_pid = check_diagexe()
    lp(f"diagexe PID: {new_pid} {'(CHANGED!)' if new_pid != pid else '(same)'}")
    
    # Check dmesg for any new messages
    r = subprocess.run(["adb", "shell", "dmesg | tail -20"], capture_output=True, text=True, timeout=5)
    lp(f"Recent dmesg:\n{r.stdout}")
    
    # Check logcat for diagexe activity
    r = subprocess.run(["adb", "shell", "logcat -d -t 50 | grep -i 'diag\\|dump\\|serial\\|modem'"], 
                       capture_output=True, text=True, timeout=5)
    if r.stdout.strip():
        lp(f"Relevant logcat:\n{r.stdout[:500]}")
    
    ser.close()
    log.close()
    print(f"\nLog saved to: {logfile}")

main()
