import struct, gzip, io, sys
data = open('boot.img', 'rb').read()
kernel_size = struct.unpack('<I', data[8:12])[0]
page_size = struct.unpack('<I', data[36:40])[0]
kernel_data = data[page_size:page_size+kernel_size]
print(f'Kernel chunk: {len(kernel_data)} bytes', file=sys.stderr)
# Find gzip
for i in range(min(len(kernel_data)-2, 0x100000)):
    if kernel_data[i] == 0x1f and kernel_data[i+1] == 0x8b:
        try:
            gz = gzip.GzipFile(fileobj=io.BytesIO(kernel_data[i:]))
            d = gz.read()
            if len(d) > 1000000:
                print(f'Decompressed {len(d)} bytes from offset {i:#x}', file=sys.stderr)
                open('/tmp/vmlinux', 'wb').write(d)
                print(f'Saved to /tmp/vmlinux', file=sys.stderr)
                sys.exit(0)
        except:
            pass
print('No valid gzip found', file=sys.stderr)
