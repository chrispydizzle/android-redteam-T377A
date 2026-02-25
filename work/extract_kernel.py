#!/usr/bin/env python3
import struct, zlib, io, gzip, sys

with open(r'C:\InfoSec\android-redteam\work\boot.img', 'rb') as f:
    data = f.read()

# Android boot.img header
magic = data[:8]
print('Magic:', magic)
kernel_size = struct.unpack_from('<I', data, 8)[0]
kernel_addr = struct.unpack_from('<I', data, 12)[0]
ramdisk_size = struct.unpack_from('<I', data, 16)[0]
page_size = struct.unpack_from('<I', data, 36)[0]
print(f'Kernel size: {kernel_size}')
print(f'Kernel load addr: 0x{kernel_addr:08x}')
print(f'Ramdisk size: {ramdisk_size}')
print(f'Page size: {page_size}')

# Kernel starts after 1 page header
kernel_off = page_size
kernel_data = data[kernel_off:kernel_off+kernel_size]
print(f'Kernel first 16 bytes: {kernel_data[:16].hex()}')

# Find gzip stream inside zImage
gzip_off = kernel_data.find(b'\x1f\x8b\x08')
print(f'Gzip stream at kernel+0x{gzip_off:x}')

if gzip_off >= 0:
    # Use raw zlib to avoid issues with concatenated streams
    # Skip gzip header (10 bytes minimum)
    raw = kernel_data[gzip_off:]
    # Find the end of the gzip header
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)  # auto-detect gzip
    vmlinux = decomp.decompress(raw)
    # Try to get any remaining data
    try:
        vmlinux += decomp.flush()
    except:
        pass
    print(f'Decompressed kernel: {len(vmlinux)} bytes')

    # Check kernel version string
    ver_off = vmlinux.find(b'Linux version')
    if ver_off >= 0:
        ver_str = vmlinux[ver_off:ver_off+150].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f'Version: {ver_str}')

    # Save it
    with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'wb') as out:
        out.write(vmlinux)
    print('Saved to work/vmlinux_aqgf')
