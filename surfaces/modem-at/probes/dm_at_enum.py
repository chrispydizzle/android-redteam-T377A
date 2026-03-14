#!/usr/bin/env python3
"""
Deep AT command enumeration on DM port.
Raw AT commands work on COM11 - enumerate ALL available commands.
Focus on Samsung-specific, debug, and potentially privileged commands.
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

def send_at(ser, cmd, wait=0.8):
    """Send raw AT command and read response."""
    ser.reset_input_buffer()
    full_cmd = cmd.encode() if isinstance(cmd, str) else cmd
    if not full_cmd.endswith(b"\r\n"):
        full_cmd += b"\r\n"
    ser.write(full_cmd)
    ser.flush()
    time.sleep(wait)
    resp = b""
    retries = 0
    while retries < 3:
        if ser.in_waiting:
            resp += ser.read(ser.in_waiting)
            time.sleep(0.05)
            retries = 0
        else:
            retries += 1
            time.sleep(0.05)
    # Decode response
    try:
        text = resp.decode('ascii', errors='replace').strip()
    except:
        text = resp.hex()
    return text

def main():
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] AT Command Deep Enumeration on COM11")
    
    pid = check_diagexe()
    print(f"diagexe PID: {pid}")
    
    logfile = f"work/dm_fuzz_logs/at_enum_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log = open(logfile, "w")
    
    ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1.0)
    
    def log_print(msg):
        print(msg)
        log.write(msg + "\n")
        log.flush()
    
    # Baseline
    r = send_at(ser, "AT")
    log_print(f"Baseline AT: {r}")
    
    # ===== Phase 1: Standard AT commands =====
    log_print("\n=== PHASE 1: Standard Information Commands ===")
    
    standard_cmds = [
        "ATI", "ATI0", "ATI1", "ATI2", "ATI3", "ATI4",
        "AT+CGMI", "AT+CGMM", "AT+CGMR", "AT+CGSN",
        "AT+CIMI",  # IMSI
        "AT+CCID",  # SIM ICCID
        "AT+CLAC",  # Command list
        "AT+CMEE=2",  # Extended error reporting
        "AT&V",     # View active config
        "AT+GCAP",  # Capabilities
        "AT+WS46?",  # Wireless data service
        "AT+CFUN?", "AT+CFUN=?",
        "AT+COPS?", "AT+COPS=?",
        "AT+CSQ",   # Signal quality
        "AT+CREG?", # Registration
        "AT+CGREG?", # GPRS registration
        "AT+CEREG?", # EPS registration
        "AT+CPAS",  # Phone activity status
        "AT+CPIN?", # SIM status
        "AT+CGDCONT?",  # PDP context
    ]
    
    for cmd in standard_cmds:
        r = send_at(ser, cmd, 0.5)
        lines = r.split('\n')
        # Only log non-trivial responses (not just echo+ERROR)
        if 'OK' in r or (len(lines) > 2):
            clean = r.replace('\r', '').strip()
            log_print(f"  {cmd}: {clean[:120]}")
        elif 'ERROR' not in r and r.strip():
            log_print(f"  {cmd}: {r[:120]}")
    
    # ===== Phase 2: Samsung-specific AT commands =====
    log_print("\n=== PHASE 2: Samsung-Specific AT Commands ===")
    
    samsung_cmds = [
        # Samsung standard
        "AT+VERSNAME", "AT+VERSNAME?",
        "AT+HWVER", "AT+HWVER?",
        "AT+SWVER", "AT+SWVER?",
        "AT+DEVCONINFO",
        "AT+FMM",  # Find My Mobile
        "AT+FMM?",
        "AT+CSC?",  # Country specific code
        "AT+SALESCODE",
        "AT+SERIALNO",
        "AT+SERIALNO?",
        "AT+IMEICHECK",
        "AT+IMSIREG?",
        # Samsung debug/engineering
        "AT+SEC?",
        "AT+SECPIN?",
        "AT+SECPUK?",
        "AT+SYSINFO",
        "AT+SYSINFO?",
        "AT+DEBUGLEVEL",
        "AT+DEBUGLEVEL?",
        "AT+TRACE?",
        "AT+DUMPCTRL",
        "AT+DUMPCTRL?",
        "AT+CPLOG",
        "AT+CPLOG?",
        "AT+CPLOGFLUSH",
        "AT+SYSDUMP",
        "AT+SYSDUMP?",
        "AT+MODEMRESET",
        "AT+NVCAL",
        "AT+NVCAL?",
        "AT+NVREAD",
        "AT+NVREAD?",
        "AT+NVWRITE",
        "AT+ODEN",
        "AT+ODEN?",
        "AT+FACTMODE",
        "AT+FACTMODE?",
        "AT+FACTSTART",
        "AT+TESTMODE",
        "AT+TESTMODE?",
        "AT+CALDATA",
        "AT+CALDATA?",
        # Samsung USB control
        "AT+USBMODE",
        "AT+USBMODE?",
        "AT+USBMODE=0",
        "AT+USBSWITCH",
        "AT+USBSWITCH?",
        "AT+ADBMODE",
        "AT+ADBMODE?",
        # Samsung security
        "AT+SVCIFPGM",
        "AT+SVCIFPGM?",
        "AT+LOCKMODE",
        "AT+LOCKMODE?",
        "AT+FBLOCK",
        "AT+FBLOCK?",
        "AT+CARRIERLOCK",
        "AT+CARRIERLOCK?",
        "AT+SIMLOCK",
        "AT+SIMLOCK?",
        "AT+OTKSL",
        "AT+OTKSL?",
        "AT+MSPL?",
        # Samsung download/ODIN
        "AT+DOWNLOAD",
        "AT+DOWNLOADEX",
        "AT+SWUP",
        "AT+SWUP?",
    ]
    
    for cmd in samsung_cmds:
        r = send_at(ser, cmd, 0.5)
        lines = r.split('\n')
        if 'OK' in r or (len(lines) > 2 and 'ERROR' not in r):
            clean = r.replace('\r', '').strip()
            log_print(f"  {cmd}: {clean[:200]}")
        elif 'ERROR' not in r and r.strip():
            log_print(f"  {cmd}: {r[:200]}")
    
    # ===== Phase 3: Qualcomm-style AT commands (Shannon may support some) =====
    log_print("\n=== PHASE 3: Qualcomm/Vendor AT Commands ===")
    
    qcom_cmds = [
        "AT$QCVERSN", "AT$QCVER",
        "AT$BREW", "AT$BREW?",
        "AT$QCDMG",  # DM mode
        "AT$QCDMQ",  # Query DM
        "AT$QCPDPP",
        "AT$QCDEFPROF",
        "AT$QCSYSMODE",
        "AT$QCMDR",
        "AT$QCPMS",
        "AT$QCNSP",
        "AT$QCMRUE",
        "AT^SYSCFG?",
        "AT^SYSINFO",
        "AT^GETPORTMODE",
        "AT^TMODE?",
        "AT^TMODE=?",
        "AT^VERSION?",
        "AT^CURC?",
        "AT^DIALMODE?",
        "AT^CARDLOCK?",
        "AT^U2DIAG?",
        "AT+XDBG?",
        "AT+XSYSTRACE?",
        "AT+XGENDATA",
        "AT+XLOG?",
        "AT+TRACE?",
    ]
    
    for cmd in qcom_cmds:
        r = send_at(ser, cmd, 0.5)
        if 'OK' in r or (len(r.split('\n')) > 2 and 'ERROR' not in r):
            clean = r.replace('\r', '').strip()
            log_print(f"  {cmd}: {clean[:200]}")
        elif 'ERROR' not in r and r.strip():
            log_print(f"  {cmd}: {r[:200]}")
    
    # ===== Phase 4: Shannon modem specific =====
    log_print("\n=== PHASE 4: Shannon Modem Specific ===")
    
    shannon_cmds = [
        "AT+XACT?",
        "AT+XBANDSEL?",
        "AT+XRAT?",
        "AT+XDRV?",
        "AT+XDRV=0,0",  # Driver control
        "AT+XDRV=4,0",
        "AT+XDRV=40,0",
        "AT+SHANNON?",
        "AT+SAMSUNGTEST",
        "AT+SAMSUNGTEST?",
        "AT+SAMSUNGMODE",
        "AT+SAMSUNGMODE?",
        "AT+SILENTLOG",
        "AT+SILENTLOG?",
        "AT+CPOSR?",
        "AT+AUTOTEST",
        "AT+AUTOTEST?",
        "AT+BATCHTEST",
        "AT+BATCHTEST?",
        "AT+EMMODE",
        "AT+EMMODE?",
        "AT+ENGMODE",
        "AT+ENGMODE?",
        "AT+DEBUGMODE",
        "AT+DEBUGMODE?",
        "AT%SYSINFO",
        "AT%CTZV?",
        "AT%EM?",
        "AT%DBGLOG?",
    ]
    
    for cmd in shannon_cmds:
        r = send_at(ser, cmd, 0.5)
        if 'OK' in r or (len(r.split('\n')) > 2 and 'ERROR' not in r):
            clean = r.replace('\r', '').strip()
            log_print(f"  {cmd}: {clean[:200]}")
    
    # ===== Phase 5: AT command brute force - letter prefixes =====
    log_print("\n=== PHASE 5: AT+ Command Brute Force (2-letter prefix) ===")
    
    # Systematic sweep of AT+XX for all 2-letter combos that aren't covered above
    # Focus on potentially privileged prefixes
    prefixes = [
        "SY", "SE", "FA", "DU", "NV", "CF", "MO", "US", "AD", "RO",
        "LO", "BL", "KN", "RD", "WR", "EX", "DB", "SH", "CP", "AP",
        "FS", "RF", "IM", "SI", "UN", "RE", "ST", "PR", "AC", "SP",
        "SS", "DS", "DI", "EN", "DE", "FW", "SW", "HW", "SV", "OD",
        "FL", "CA", "SA", "TB", "UP", "DO", "MD", "SD", "DR", "DM",
    ]
    
    found_cmds = []
    for prefix in prefixes:
        cmd = f"AT+{prefix}?"
        r = send_at(ser, cmd, 0.3)
        if 'OK' in r:
            clean = r.replace('\r', '').strip()
            log_print(f"  AT+{prefix}?: {clean[:120]}")
            found_cmds.append(prefix)
        # Also try without ?
        cmd = f"AT+{prefix}"
        r = send_at(ser, cmd, 0.3)
        if 'OK' in r:
            clean = r.replace('\r', '').strip()
            log_print(f"  AT+{prefix}: {clean[:120]}")
            if prefix not in found_cmds:
                found_cmds.append(prefix)
    
    if found_cmds:
        log_print(f"\n  Found prefixes: {', '.join(found_cmds)}")
    
    # ===== Phase 6: Samsung secret AT codes =====
    log_print("\n=== PHASE 6: Samsung Secret/Hidden AT Commands ===")
    
    secret_cmds = [
        # These are known Samsung engineering AT commands
        "AT+DATALOCK?",
        "AT+SPSERVICE?",
        "AT+SPPREFERENCE?",
        "AT+SPRESET",
        "AT+SPINCHECK",
        "AT+OMADM?",
        "AT+OMADM=0",
        "AT+VZWAPNE?",
        "AT+IUFAILCNT?",
        "AT+USBDEBUG",
        "AT+USBDEBUG?",
        "AT+ROOTSTATUS",
        "AT+ROOTSTATUS?",
        "AT+KNOXSTATUS",
        "AT+KNOXSTATUS?",
        "AT+WARRANTYVOID",
        "AT+WARRANTYVOID?",
        "AT+JTAGSTATUS",
        "AT+JTAGSTATUS?",
        "AT+SBOOT",
        "AT+SBOOT?",
        "AT+EFUSE",
        "AT+EFUSE?",
        "AT+TZPR",
        "AT+TZPR?",
        "AT+RRC?",
        "AT+SPC",
        "AT+SPC?",
        "AT+MSL",
        "AT+MSL?",
        "AT+CARRIERID",
        "AT+CARRIERID?",
        "AT+SUBSIDYLOCK",
        "AT+SUBSIDYLOCK?",
        "AT+NETLOCK",
        "AT+NETLOCK?",
    ]
    
    for cmd in secret_cmds:
        r = send_at(ser, cmd, 0.5)
        if 'OK' in r or ('+' in r and 'ERROR' not in r):
            clean = r.replace('\r', '').strip()
            log_print(f"  {cmd}: {clean[:200]}")
    
    # Final health check
    new_pid = check_diagexe()
    log_print(f"\nFinal diagexe PID: {new_pid} {'(CHANGED!)' if new_pid != pid else '(same)'}")
    
    ser.close()
    log.close()
    print(f"\nLog saved to: {logfile}")

main()
