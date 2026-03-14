#!/usr/bin/env python3
"""Verify if firmware kernel matches running kernel using nf_conntrack slabinfo leak."""
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

# Search ALL nf_conntrack symbols in firmware
print("All nf_conntrack symbols in firmware:")
pos = NAMES_OFF
nf_syms = []
for i in range(NUM_SYMS):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    pos += 1 + entry_len
    
    if entry_len > 0:
        sym_name = decode_name(entry_data[1:])
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        if 'nf_conntrack' in sym_name:
            sym_type = decode_name(entry_data[0:1])
            nf_syms.append((addr, sym_type, sym_name, i))

# Print nf_conntrack symbols sorted by address, focus on those near 0xc0afXXXX
for addr, stype, name, idx in sorted(nf_syms):
    if 0xc0af0000 <= addr <= 0xc0b10000:
        print(f"  [{idx}] 0x{addr:08x} {stype} {name}")

# Also look for the exact address 0xc0afeb00 as a data symbol
print(f"\nSearching for address 0xc0afeb00 in firmware addresses table:")
target = 0xc0afeb00
for i in range(NUM_SYMS):
    addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
    if addr == target:
        entry_off = NAMES_OFF
        for j in range(i):
            el = data[entry_off]
            entry_off += 1 + el
        el = data[entry_off]
        ed = data[entry_off+1:entry_off+1+el]
        if el > 0:
            sn = decode_name(ed[1:])
            st = decode_name(ed[0:1])
            print(f"  EXACT MATCH: [{i}] 0x{addr:08x} {st} {sn}")
    elif abs(addr - target) <= 64:
        entry_off = NAMES_OFF
        for j in range(i):
            el = data[entry_off]
            entry_off += 1 + el
        el = data[entry_off]
        ed = data[entry_off+1:entry_off+1+el]
        if el > 0:
            sn = decode_name(ed[1:])
            st = decode_name(ed[0:1])
            diff = addr - target
            print(f"  NEAR: [{i}] 0x{addr:08x} ({diff:+d}) {st} {sn}")

# Also check: dump first/last few symbols and verify against running kernel
print("\n\nFirst 5 firmware symbols:")
pos = NAMES_OFF
for i in range(5):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
    if entry_len > 0:
        stype = decode_name(entry_data[0:1])
        sname = decode_name(entry_data[1:])
        print(f"  [{i}] 0x{addr:08x} {stype} {sname}")
    else:
        print(f"  [{i}] 0x{addr:08x} (no name)")
    pos += 1 + entry_len

print("\nLast 5 firmware symbols:")
# We need to iterate to the end, skip ahead using markers
pos = NAMES_OFF
for i in range(NUM_SYMS):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    if i >= NUM_SYMS - 5:
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        if entry_len > 0:
            stype = decode_name(entry_data[0:1])
            sname = decode_name(entry_data[1:])
            print(f"  [{i}] 0x{addr:08x} {stype} {sname}")
        else:
            print(f"  [{i}] 0x{addr:08x} (no name)")
    pos += 1 + entry_len
