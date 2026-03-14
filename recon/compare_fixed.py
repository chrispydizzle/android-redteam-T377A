#!/usr/bin/env python3
"""Fixed comparison: handle blank lines and fix type/name splitting."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

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

def decode_symbol(compressed_bytes):
    """Decode compressed kallsyms entry. Returns (type_char, name)."""
    if len(compressed_bytes) == 0:
        return '?', ''
    full = ''.join(tokens[b] for b in compressed_bytes)
    # First character is the type
    return full[0], full[1:]

# Decode ALL firmware symbols
fw_entries = []  # (addr, type, name)
pos = NAMES_OFF
for i in range(NUM_SYMS):
    el = data[pos]
    ed = data[pos+1:pos+1+el]
    pos += 1 + el
    addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
    if el > 0:
        stype, sname = decode_symbol(ed)
        fw_entries.append((addr, stype, sname))
    else:
        fw_entries.append((addr, '?', ''))

# Read running kernel names (skip blank lines)
with open(r'C:\InfoSec\android-redteam\work\running_names.txt', 'r') as f:
    raw_lines = [line.strip() for line in f.readlines()]
running_entries = []
for line in raw_lines:
    if line:
        parts = line.split(' ', 1)
        if len(parts) == 2:
            running_entries.append((parts[0], parts[1]))
        elif len(parts) == 1:
            running_entries.append((parts[0], ''))

print(f"Firmware symbols: {len(fw_entries)}")
print(f"Running symbols (non-blank): {len(running_entries)}")

# Show first 20 from each
print("\nFirst 20 firmware:")
for i in range(20):
    a, t, n = fw_entries[i]
    print(f"  [{i}] 0x{a:08x} {t} {n}")

print("\nFirst 20 running:")
for i in range(20):
    t, n = running_entries[i]
    print(f"  [{i}] {t} {n}")

# Find offset: firmware names start 12 entries later
# Check if fw[12] == running[0]
print("\nAlignment check:")
for offset in range(0, 20):
    match_count = 0
    for i in range(min(100, len(running_entries))):
        fi = i + offset
        if fi >= len(fw_entries):
            break
        _, ft, fn = fw_entries[fi]
        rt, rn = running_entries[i]
        if ft == rt and fn == rn:
            match_count += 1
    print(f"  offset={offset}: {match_count}/100 matches")

# Once we find the offset, use it for commit_creds
print("\n--- commit_creds resolution ---")
# Find commit_creds in running entries
for i, (rt, rn) in enumerate(running_entries):
    if rn == 'commit_creds':
        print(f"Running commit_creds at index {i}: {rt} {rn}")
        # Try various offsets
        for offset in range(0, 20):
            fi = i + offset
            if fi < len(fw_entries):
                a, ft, fn = fw_entries[fi]
                if fn == 'commit_creds':
                    print(f"  MATCH with offset={offset}: firmware idx {fi}, addr=0x{a:08x}")
        break

for i, (rt, rn) in enumerate(running_entries):
    if rn == 'prepare_kernel_cred':
        print(f"Running prepare_kernel_cred at index {i}: {rt} {rn}")
        for offset in range(0, 20):
            fi = i + offset
            if fi < len(fw_entries):
                a, ft, fn = fw_entries[fi]
                if fn == 'prepare_kernel_cred':
                    print(f"  MATCH with offset={offset}: firmware idx {fi}, addr=0x{a:08x}")
        break

# Build name lookup and directly match
print("\n--- Direct name lookup ---")
fw_by_name = {}
for i, (a, t, n) in enumerate(fw_entries):
    key = f"{t} {n}"
    if key not in fw_by_name:
        fw_by_name[key] = (i, a)

for target in ['T commit_creds', 'T prepare_kernel_cred']:
    if target in fw_by_name:
        idx, addr = fw_by_name[target]
        print(f"  {target}: firmware idx={idx}, addr=0x{addr:08x}")
    else:
        print(f"  {target}: NOT FOUND in firmware")
