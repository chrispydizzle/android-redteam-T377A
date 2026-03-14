#!/usr/bin/env python3
"""Decode kallsyms from decompressed ARM kernel binary."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

print(f'Kernel size: {len(data)} bytes')

# Find kallsyms_addresses table - look for sequence of 0xc0XXXXXX addresses
# The table starts with _text address and has many sequential kernel addresses

def find_kallsyms_addresses(data):
    """Find the kallsyms_addresses table."""
    # Search for a run of at least 100 consecutive 32-bit values in 0xc0000000-0xc1000000
    for start in range(0, len(data) - 400, 4):
        vals = struct.unpack_from('<100I', data, start)
        # Check if all look like kernel text addresses
        if all(0xc0000000 <= v <= 0xc1200000 for v in vals):
            # Check they're mostly ascending
            ascending = sum(1 for i in range(99) if vals[i] <= vals[i+1])
            if ascending > 90:
                return start
    return None

# More efficient: search for known address ret_from_fork = 0xc000e498
known_addr = struct.pack('<I', 0xc000e498)
candidates = []
off = 0
while True:
    off = data.find(known_addr, off)
    if off == -1:
        break
    # Check alignment
    if off % 4 == 0:
        candidates.append(off)
    off += 1

print(f'Found {len(candidates)} aligned occurrences of 0xc000e498')

for cand in candidates:
    # Check if this is in a table of kernel addresses
    # Look at surrounding values
    idx_in_table = cand // 4  # rough
    # Check previous 140 entries (ret_from_fork should be around index 140)
    table_start = cand - 140 * 4
    if table_start < 0:
        continue
    
    vals = struct.unpack_from('<200I', data, table_start)
    kernel_count = sum(1 for v in vals if 0xc0000000 <= v <= 0xc1200000)
    if kernel_count > 180:
        print(f'\nPotential table at file offset 0x{table_start:x}')
        # Verify with another known address: dump_backtrace = 0xc0012838 at idx 252
        expected_db_off = table_start + 252 * 4
        if expected_db_off + 4 <= len(data):
            db_val = struct.unpack_from('<I', data, expected_db_off)[0]
            print(f'  Value at idx 252: 0x{db_val:08x} (expect dump_backtrace=0xc0012838)')
            if db_val == 0xc0012838:
                print('  *** EXACT MATCH for dump_backtrace! ***')
        
        # Check warn_slowpath_common at idx 890
        expected_ws_off = table_start + 890 * 4
        if expected_ws_off + 4 <= len(data):
            ws_val = struct.unpack_from('<I', data, expected_ws_off)[0]
            print(f'  Value at idx 890: 0x{ws_val:08x} (expect warn_slowpath_common=0xc002a61c)')
            if ws_val == 0xc002a61c:
                print('  *** EXACT MATCH for warn_slowpath_common! ***')

        # If we found it, extract commit_creds at idx 1944 (0-based)
        cc_off = table_start + 1944 * 4
        pkc_off = table_start + 1952 * 4
        if cc_off + 4 <= len(data) and pkc_off + 4 <= len(data):
            cc_val = struct.unpack_from('<I', data, cc_off)[0]
            pkc_val = struct.unpack_from('<I', data, pkc_off)[0]
            print(f'  Value at idx 1944 (commit_creds?): 0x{cc_val:08x}')
            print(f'  Value at idx 1952 (prepare_kernel_cred?): 0x{pkc_val:08x}')
        
        # Find total table size
        pos = table_start
        count = 0
        while pos + 4 <= len(data):
            v = struct.unpack_from('<I', data, pos)[0]
            if 0xc0000000 <= v <= 0xc1200000:
                count += 1
                pos += 4
            else:
                # Allow a few zero entries (weak symbols)
                if v == 0 and count < 50000:
                    count += 1
                    pos += 4
                else:
                    break
        print(f'  Table entries: {count}')
        
        # Read num_syms after table
        num_syms_off = table_start + count * 4
        if num_syms_off + 4 <= len(data):
            num_syms = struct.unpack_from('<I', data, num_syms_off)[0]
            print(f'  num_syms value after table: {num_syms}')
