import serial, time, sys

s = serial.Serial('COM11', 115200, timeout=2)
print(f"COM11 open: {s.is_open}")

cmds = [
    'AT+FIRMVERS',
    'AT+KSTRINGB=1,0',
    'AT+KSTRINGB',
    'AT+CONTROLN',
    'AT+UARTSWIT',
    'AT+DEBUGLVC',
    'AT+FACTOLOG',
    'AT+VERSNAME',
    'AT+BATTTEST',
]

for cmd in cmds:
    s.reset_input_buffer()
    s.write((cmd + '\r').encode())
    time.sleep(1.5)
    resp = s.read(s.in_waiting or 500)
    print(f"CMD: {cmd}")
    print(f"  RAW: {repr(resp)[:300]}")
    # Decode for readability
    try:
        text = resp.decode('utf-8', errors='replace').strip()
        print(f"  TXT: {text[:200]}")
    except:
        pass
    print()

s.close()
print("Done")
