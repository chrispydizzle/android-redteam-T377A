import serial, time, sys

ser = serial.Serial("COM8", 115200, timeout=2)
ser.write(b"ATE0\r\n")
time.sleep(0.3)
ser.read(256)

def at(cmd, wait=1.0):
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    time.sleep(wait)
    data = bytearray()
    while True:
        chunk = ser.read(4096)
        if not chunk:
            break
        data.extend(chunk)
    return data.decode("ascii", errors="replace").strip()

# Get full command list
print("[*] Getting full AT command list (AT*)...")
resp = at("AT*", wait=2.0)
print(resp)
print("\n" + "="*60)

# Get Samsung-specific $ commands
print("\n[*] AT$ commands...")
resp2 = at("AT$", wait=2.0)
print(resp2)
print("\n" + "="*60)

# Try to bring modem to full function
print("\n[*] AT+CFUN=1 (full functionality)...")
print(at("AT+CFUN=1", wait=3.0))

# Now re-check status
print("[*] AT+CFUN?:", at("AT+CFUN?"))
print("[*] AT+CSQ:", at("AT+CSQ"))
print("[*] AT+CREG?:", at("AT+CREG?"))

ser.close()
