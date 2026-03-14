import serial, time

ser = serial.Serial("COM8", 115200, timeout=0.5)
ser.write(b"ATE0\r\n")
time.sleep(0.3)
ser.read(256)

def at(cmd, wait=0.3):
    ser.write((cmd + "\r\n").encode())
    time.sleep(wait)
    resp = ser.read(1024)
    return resp.decode("ascii", errors="replace").strip()

# Probe interesting AT commands
tests = [
    ("AT+CLAC", "List all available AT commands"),
    ("AT*", "Samsung star commands"),
    ("AT$", "Samsung dollar commands"),
    ("AT+CIMI", "IMSI"),
    ("AT+CCID", "SIM CCID"),
    ("AT+ICCID", "ICCID alternate"),
    ("AT+CSQ", "Signal quality"),
    ("AT+CREG?", "Network registration"),
    ("AT+CPIN?", "SIM PIN state"),
    ("AT+CFUN?", "Phone functionality"),
    ("AT+CMEE=1", "Enable verbose errors"),
    ("AT+CMEE?", "Error mode"),
    ("AT!ENTERCND=A710", "Shannon diag enter"),
    ("AT!DIAG", "Diag mode"),
    ("AT+XDIAG", "Extended diag"),
    ("AT%XDIAG", "Extended diag v2"),
    ("ATD*99***1#", "PDP context"),
    ("AT+CGDCONT?", "PDP context query"),
    ("AT+CSCS?", "Character set"),
    ("AT+CGSN", "IMEI/serial (may need CMEE)"),
    ("AT+CMGS=?", "SMS send capability"),
    ("ATZ", "Reset"),
    ("ATQ0V1", "Quiet/verbose mode"),
    ("AT+COPN=?", "Operator names"),
]

for cmd, desc in tests:
    resp = at(cmd, 0.5)
    r_short = repr(resp[:150])
    print("  %s [%s]: %s" % (cmd, desc, r_short))

ser.close()
