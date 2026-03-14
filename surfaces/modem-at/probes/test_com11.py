"""Quick AT command connectivity test on COM11."""
import serial, sys

try:
    ser = serial.Serial('COM11', 115200, timeout=2)
    
    # Basic AT test
    ser.write(b'AT\r\n')
    resp = ser.read(256).decode('ascii', errors='replace').strip()
    print(f'AT -> [{resp}]')
    
    # Device info
    ser.write(b'ATI\r\n')
    resp = ser.read(512).decode('ascii', errors='replace').strip()
    print(f'ATI -> [{resp}]')
    
    # Current CFUN mode
    ser.write(b'AT+CFUN?\r\n')
    resp = ser.read(256).decode('ascii', errors='replace').strip()
    print(f'CFUN? -> [{resp}]')
    
    # CFUN range
    ser.write(b'AT+CFUN=?\r\n')
    resp = ser.read(256).decode('ascii', errors='replace').strip()
    print(f'CFUN=? -> [{resp}]')
    
    ser.close()
    print('\n=== COM11 CONNECTED AND RESPONSIVE ===')
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
