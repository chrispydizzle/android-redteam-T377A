import struct, gzip, io
data = open('boot.img', 'rb').read()
magic = data[:8]
kernel_size = struct.unpack('<I', data[8:12])[0]
page_size = struct.unpack('<I', data[36:40])[0]
print(f'Kernel: size={kernel_size}, page_size={page_size}')
kernel_data = data[page_size:page_size+kernel_size]
for i in range(len(kernel_data)-2):
    if kernel_data[i] == 0x1f and kernel_data[i+1] == 0x8b and kernel_data[i+2] == 0x08:
        print(f'gzip at kernel+{i:#x}')
        try:
            gz = gzip.GzipFile(fileobj=io.BytesIO(kernel_data[i:]))
            d = gz.read()
            print(f'Decompressed: {len(d)} bytes')
            for s in [b'binder_poll', b'wait_for_proc', b'%d:%d poll', b'binder: %d:%d', b'thread->wait']:
                idx = d.find(s)
                if idx >= 0: print(f'  {s.decode()}: at {idx:#x}')
                else: print(f'  {s.decode()}: NOT FOUND')
            open('/tmp/vmlinux', 'wb').write(d)
            break
        except Exception as e:
            pass
