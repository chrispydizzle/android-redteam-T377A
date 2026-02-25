import struct, gzip, io, zlib
data = open('boot.img', 'rb').read()
page_size = struct.unpack('<I', data[36:40])[0]
kernel_size = struct.unpack('<I', data[8:12])[0]
kd = data[page_size:page_size+kernel_size]
offset = 0x6a48
print(f'gzip header bytes: {kd[offset:offset+10].hex()}')

# Try raw deflate
try:
    d = zlib.decompress(kd[offset+10:], -15)
    print(f'zlib decompress: {len(d)} bytes')
    open('/tmp/vmlinux', 'wb').write(d)
except Exception as e:
    print(f'zlib failed: {e}')

# Try gzip with all data from offset to end of kernel
try:
    gz_data = kd[offset:]
    d = gzip.decompress(gz_data)
    print(f'gzip decompress: {len(d)} bytes')
    open('/tmp/vmlinux', 'wb').write(d)
except Exception as e:
    print(f'gzip failed: {e}')
    # Maybe the gzip stream ends before kernel_data ends, try smaller chunks
    for end_off in range(len(kd), offset, -0x10000):
        try:
            d = gzip.decompress(kd[offset:end_off])
            print(f'gzip {end_off:#x}: {len(d)} bytes')
            open('/tmp/vmlinux', 'wb').write(d)
            break
        except:
            pass
    else:
        print('All gzip attempts failed')
