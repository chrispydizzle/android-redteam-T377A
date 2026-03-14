#!/usr/bin/env python3
"""Find kallsyms addresses table by searching for ascending address runs."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

print(f'Kernel size: {len(data)} bytes')

# Search for known addresses from recovery_kernel.log
known_addrs = {
    0xc000e498: 'ret_from_fork',
    0xc0012838: 'dump_backtrace',
    0xc00129c0: 'show_stack',
    0xc002a61c: 'warn_slowpath_common',
    0xc002a740: 'warn_slowpath_null',
    0xc0357890: 'pm_generic_runtime_idle',
    0xc07d4fa0: 'kernel_init',
    0xc07e0dac: 'dump_stack',
    0xc0a28b50: 'do_one_initcall',
}

for addr, name in known_addrs.items():
    packed = struct.pack('<I', addr)
    count = 0
    off = 0
    positions = []
    while True:
        off = data.find(packed, off)
        if off == -1:
            break
        if off % 4 == 0:
            positions.append(off)
        off += 1
        count += 1
    print(f'0x{addr:08x} ({name}): {len(positions)} aligned hits')
    if positions and len(positions) <= 10:
        for p in positions:
            print(f'  at file offset 0x{p:x}')

# Also search with different PAGE_OFFSET values
print('\nSearching with alternative base addresses...')
for base_shift in [0x00000000, 0x80000000, 0x40000000]:
    test_addr = 0xc000e498 - 0xc0000000 + base_shift
    packed = struct.pack('<I', test_addr)
    off = data.find(packed)
    if off >= 0 and off % 4 == 0:
        print(f'  ret_from_fork with base 0x{base_shift:08x}: found at 0x{off:x} (addr 0x{test_addr:08x})')

# Brute force: find ANY long run of ascending 32-bit values in typical kernel range
print('\nSearching for ascending address table...')
best_start = 0
best_len = 0
i = 0
while i < len(data) - 8:
    v = struct.unpack_from('<I', data, i)[0]
    if 0xc0000000 <= v <= 0xd0000000:
        run_start = i
        run_len = 1
        prev = v
        j = i + 4
        while j < len(data) - 4:
            nv = struct.unpack_from('<I', data, j)[0]
            if nv == 0:  # allow zero entries
                run_len += 1
                j += 4
                continue
            if 0xc0000000 <= nv <= 0xd0000000 and nv >= prev - 0x1000:
                run_len += 1
                prev = nv
                j += 4
            else:
                break
        if run_len > best_len:
            best_len = run_len
            best_start = run_start
            if run_len >= 100:
                first_val = struct.unpack_from('<I', data, run_start)[0]
                print(f'  Run at 0x{run_start:x}: {run_len} entries, first=0x{first_val:08x}')
        i = j
    else:
        i += 4

print(f'\nBest run: offset 0x{best_start:x}, {best_len} entries')
if best_len > 100:
    # Print first 10 entries
    for k in range(min(10, best_len)):
        v = struct.unpack_from('<I', data, best_start + k*4)[0]
        print(f'  [{k}] 0x{v:08x}')
    # Print entries around idx 1944
    for k in [1940, 1941, 1942, 1943, 1944, 1945, 1946, 1950, 1952, 1953]:
        off = best_start + k * 4
        if off + 4 <= len(data):
            v = struct.unpack_from('<I', data, off)[0]
            print(f'  [{k}] 0x{v:08x}')
