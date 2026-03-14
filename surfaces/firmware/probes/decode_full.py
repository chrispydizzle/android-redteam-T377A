#!/usr/bin/env python3
"""Full kallsyms decoder for the matching kernel binary."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# Verified offsets
TOKEN_TABLE_OFF = 0x926000
MARKERS_OFF = 0x925D50
NUM_SYMS = 43664

# Parse token table: 256 null-terminated ASCII strings starting at TOKEN_TABLE_OFF
tokens = []
pos = TOKEN_TABLE_OFF
for i in range(256):
    end = data.index(b'\x00', pos)
    tokens.append(data[pos:end].decode('ascii', errors='replace'))
    pos = end + 1

# Token index follows token table (256 x uint16)
TOKEN_INDEX_OFF = pos
print(f"Token index at: 0x{TOKEN_INDEX_OFF:x}")

# Addresses table: look for the real start
# We know the table has NUM_SYMS entries ending before num_syms field
# num_syms should be at: table_start + NUM_SYMS * 4
# And the value at num_syms offset should be 43664

# Working backward: names start at some point after num_syms
# Let's find num_syms = 43664 = 0xAA80
search_val = struct.pack('<I', 43664)
off = 0x8A4F80
while off < 0x8A5000:
    if data[off:off+4] == search_val:
        table_start = off - NUM_SYMS * 4
        print(f"num_syms at 0x{off:x}, table_start would be 0x{table_start:x}")
        # Check what's at table_start
        first_val = struct.unpack_from('<I', data, table_start)[0]
        print(f"  First value: 0x{first_val:08x}")
    off += 4

# Use the most likely table start
# num_syms at 0x8A4F90 => table_start = 0x8A4F90 - 43664*4 = 0x8A4F90 - 0x2AA40 = 0x87A550
TABLE_START = 0x87A550
first_val = struct.unpack_from('<I', data, TABLE_START)[0]
print(f"\nAddresses table start: 0x{TABLE_START:x}")
print(f"First entry [0]: 0x{first_val:08x}")

# Verify with known symbols
# dump_backtrace should be at idx 252 (1-based) = 251 (0-based) per running kernel
# warn_slowpath_common at idx 891 (1-based) = 890 (0-based)
for idx, expected_addr, name in [
    (251, 0xc0012838, 'dump_backtrace'),
    (252, 0xc00129c0, 'show_stack'),
    (890, 0xc002a61c, 'warn_slowpath_common'),
    (894, 0xc002a740, 'warn_slowpath_null'),
]:
    actual = struct.unpack_from('<I', data, TABLE_START + idx * 4)[0]
    match = "MATCH" if actual == expected_addr else f"MISMATCH (got 0x{actual:08x})"
    print(f"  [{idx}] expect {name}=0x{expected_addr:08x}: {match}")

# Names table
NAMES_OFF = TABLE_START + NUM_SYMS * 4 + 4  # after addresses + num_syms
print(f"\nNames table at: 0x{NAMES_OFF:x}")

def decode_name(compressed_bytes):
    """Decode compressed kallsyms name."""
    result = ''
    for b in compressed_bytes:
        result += tokens[b]
    return result

# Decode ALL symbols, search for commit_creds and prepare_kernel_cred
pos = NAMES_OFF
found = {}
for i in range(NUM_SYMS):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    pos += 1 + entry_len
    
    if entry_len > 0:
        sym_type_char = decode_name(entry_data[0:1])
        sym_name = decode_name(entry_data[1:])
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        
        full_name = sym_name
        
        if 'commit_cred' in full_name or 'prepare_kernel_cred' in full_name:
            print(f"  *** [{i}] 0x{addr:08x} {sym_type_char} {full_name}")
            found[full_name] = (i, addr, sym_type_char)
        
        # Also check known functions for verification
        if full_name in ('dump_backtrace', 'show_stack', 'warn_slowpath_common', 
                         'warn_slowpath_null', 'kernel_init', 'dump_stack',
                         'ret_from_fork', 'do_one_initcall'):
            print(f"  Verified: [{i}] 0x{addr:08x} {sym_type_char} {full_name}")

print(f"\nDecoded {NUM_SYMS} symbols")
print(f"\nResults:")
for name, (idx, addr, stype) in sorted(found.items()):
    print(f"  {name}: index={idx}, address=0x{addr:08x}, type={stype}")
