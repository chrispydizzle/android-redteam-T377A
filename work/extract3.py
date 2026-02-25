import struct
data = open('boot.img', 'rb').read()
kernel_size = struct.unpack('<I', data[8:12])[0]
page_size = struct.unpack('<I', data[36:40])[0]
kd = data[page_size:page_size+kernel_size]
print(f'First 32 kernel bytes: {kd[:32].hex()}')
# Find compression signatures
for i in range(min(len(kd), 0x100000)):
    b = kd[i:i+4]
    if b == b'\x1f\x8b\x08\x00': print(f'gzip at {i:#x}')
    elif b == b'\x89\x4c\x5a\x4f': print(f'LZO at {i:#x}')
    elif b == b'\x02\x21\x4c\x18': print(f'LZ4 at {i:#x}')
    elif b == b'\xfd\x37\x7a\x58': print(f'XZ at {i:#x}')
    elif b == b'\x42\x5a\x68': print(f'bzip2 at {i:#x}'); break
    elif b[:2] == b'\x1f\x8b' and i < 0x10000: print(f'gzip-like at {i:#x}: {kd[i:i+8].hex()}')
# Also search for ARM Linux banner
idx = kd.find(b'Linux version')
if idx >= 0:
    print(f'Linux version at {idx:#x}: {kd[idx:idx+80]}')
