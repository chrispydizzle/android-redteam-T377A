"""Get the full AT* command list from Shannon modem on COM8."""
import serial, time

ser = serial.Serial("COM8", 115200, timeout=0.1)
ser.write(b"ATE0\r\n")
time.sleep(0.3)
ser.reset_input_buffer()

# AT* returns the full command list - read with rolling buffer
print("[*] Sending AT* ...")
ser.write(b"AT*\r\n")

# Collect for 5 seconds
buf = bytearray()
deadline = time.time() + 5.0
while time.time() < deadline:
    chunk = ser.read(4096)
    if chunk:
        buf.extend(chunk)

raw = buf.decode("ascii", errors="replace")
print("[*] Raw response (%d bytes):" % len(buf))
print(raw)
print("="*60)

# Parse out individual AT commands
import re
lines = [l.strip() for l in raw.split("\n") if l.strip()]
at_cmds = [l for l in lines if l.startswith("AT") or l.startswith("+")]
print("[*] Parsed %d command lines:" % len(at_cmds))
for c in at_cmds:
    print("  " + c)

ser.close()
