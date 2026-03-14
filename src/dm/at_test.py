import serial, time

try:
    ser = serial.Serial('COM18', 115200, timeout=1)
    print('Port opened')
    ser.reset_input_buffer()
    
    # Try AT first (we know this works per STATUS.md)
    ser.write(b'AT\r\n')
    time.sleep(0.5)
    resp = ser.read(256)
    print(f'AT response: {resp!r}')
    
    # Try ATE0 to disable echo
    ser.write(b'ATE0\r\n')
    time.sleep(0.3)
    resp = ser.read(256)
    print(f'ATE0 response: {resp!r}')
    
    # Try ATI for modem info
    ser.write(b'ATI\r\n')
    time.sleep(0.5)
    resp = ser.read(512)
    print(f'ATI response: {resp!r}')
    
    # Try raw DM start with 0x7F start flag (Samsung variant)
    # VERSION_INFO command (0x00)
    payload = b'\x00'
    crc = 0xFFFF
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = (c >> 1) ^ 0x8408
            else:
                c >>= 1
        table.append(c)
    for b in payload:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    crc ^= 0xFFFF
    import struct
    raw = payload + struct.pack('<H', crc)
    escaped = bytearray()
    for b in raw:
        if b in (0x7E, 0x7D):
            escaped.extend([0x7D, b ^ 0x20])
        else:
            escaped.append(b)
    
    # Try 0x7F start flag
    frame_7f = bytes([0x7F]) + bytes(escaped) + bytes([0x7E])
    print(f'TX DM 0x7F: {frame_7f.hex()}')
    ser.write(frame_7f)
    time.sleep(1.0)
    resp = ser.read(512)
    print(f'RX after DM: {resp!r}')
    
    ser.close()
except Exception as e:
    print(f'Error: {e}')
