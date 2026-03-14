"""
Full AT command map + fuzzing for Samsung SM-T377A Shannon 308 modem.
COM8 = ACM serial (AT commands), COM18 = DM binary (HDLC)
"""
import serial, time, sys, re

def open_port(port="COM8", baud=115200):
    ser = serial.Serial(port, baud, timeout=0.5)
    # Disable echo
    ser.write(b"ATE0\r\n")
    time.sleep(0.3)
    ser.reset_input_buffer()
    return ser

def at(ser, cmd, wait=0.5):
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    time.sleep(wait)
    data = bytearray()
    t = time.time()
    while time.time() - t < wait + 0.2:
        chunk = ser.read(4096)
        if chunk:
            data.extend(chunk)
            t = time.time()  # reset on data
    return data.decode("ascii", errors="replace").strip()

def get_cmd_list(ser):
    """Get complete AT command list via AT*."""
    ser.reset_input_buffer()
    ser.write(b"AT*\r\n")
    time.sleep(3.0)  # Large list takes time
    data = bytearray()
    deadline = time.time() + 5.0
    while time.time() < deadline:
        chunk = ser.read(8192)
        if chunk:
            data.extend(chunk)
    raw = data.decode("ascii", errors="replace")
    # Extract AT commands from the list
    cmds = re.findall(r'(AT[^\r\n]+)', raw)
    return cmds

def main():
    ser = open_port()
    print("[*] Port COM8 opened, echo disabled")
    
    # Get full command list
    print("[*] Fetching full AT command list...")
    cmds = get_cmd_list(ser)
    print(f"[*] Found {len(cmds)} commands:")
    for c in cmds:
        print(f"    {c}")
    
    print("\n" + "="*60)
    print("[*] Testing Samsung-specific commands...")
    
    # Test Samsung-specific AT commands
    samsung_cmds = [
        # File/storage operations
        "AT+CLVL=?",
        "AT+CSDH=?",
        "AT+CSMP=?",
        "AT+CSCA=?",
        "AT+CSCB=?",
        # Samsung proprietary
        "AT+STKC=?",
        "AT+STRH=?", 
        "AT+STRR=?",
        "AT+STRS=?",
        "AT+STRD=?",
        "AT+SFSD=?",    # Samsung file system?
        "AT+SFSR=?",
        "AT+SFSW=?",
        "AT+SFSL=?",
        # Samsung diag
        "AT+SDDD=?",
        "AT+SSRV=?",
        "AT+SCKS=?",
        "AT+SMUT=?",
        # Voice/call (might expose exec paths)
        "AT+VTS=?",
        "AT+VTD=?",
        # Engineering/hidden
        "AT+ENGSQ",
        "AT+ENGMODE",
        "AT*BAND",
        "AT*NUMSIM",
        "AT+CAOC=?",
        # GPS  
        "AT+CGPS=?",
        "AT+CGPSNMEA=?",
        # Data
        "AT+CGACT=?",
        "AT+CGDATA=?",
        "AT+CGREG=?",
        # Write/exec candidates
        "AT+CFGN=?",
        "AT+CNMA=?",
        "AT+CKPD=?",    # Keypad simulation
        "AT+CRSM=?",    # SIM access (could be interesting)
        "AT+CSIM=?",    # Generic SIM access
        "AT+CRLA=?",    # Restricted SIM access
    ]
    
    for cmd in samsung_cmds:
        resp = at(ser, cmd, 0.3)
        if resp and "ERROR" not in resp:
            r_short = repr(resp[:100])
            print("  %s: %s" % (cmd, r_short))
    
    print("\n" + "="*60)
    print("[*] Buffer overflow candidates (long args)...")
    
    # Test buffer overflow candidates
    overflow_tests = [
        # AT commands with string args that might overflow
        ("AT+CGDCONT=1,\"IP\",\"" + "A"*256 + "\"", "APN string overflow"),
        ("AT+CGSMS=" + "A"*512, "CGSMS overflow"),
        ("AT+CUSD=" + "A"*512, "USSD string overflow"),
        ("AT+COPS=" + "0,0,\"" + "A"*256 + "\"", "Operator name overflow"),
        ("AT+CLCK=\"SC\"," + "A"*256, "Facility lock overflow"),
        ("AT+CPWD=\"SC\",\"1234\",\"" + "A"*256 + "\"", "Password change overflow"),
        ("AT+CNUM=" + "A"*512, "Number overflow"),
        ("AT+CESQ=" + "A"*512, "CESQ overflow"),
        ("AT+CGLA=0," + str(len("A"*512) * 2) + ",\"" + "4141" * 128 + "\"", "CGLA SIM data overflow"),
    ]
    
    for cmd, desc in overflow_tests:
        resp = at(ser, cmd, 1.0)
        r_short = repr(resp[:80])
        print("  [%s]: %s" % (desc, r_short))
        # Check device still alive
        alive = at(ser, "AT", 0.3)
        if "OK" not in alive:
            print("  *** DEVICE MAY HAVE CRASHED! alive=%s" % repr(alive))
            break
    
    print("\n[*] Final health check:")
    print(f"  AT: {at(ser, 'AT')!r}")
    print(f"  ATI: {at(ser, 'ATI')!r}")
    
    ser.close()
    print("[*] Done")

if __name__ == "__main__":
    main()
