#!/usr/bin/env python3
"""Compare running kernel symbol names with firmware to validate address mapping."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# Parse tokens
TABLE_START = 0x87A550
NUM_SYMS = 43664
NAMES_OFF = 0x8A4F94
TOKEN_TABLE_OFF = 0x926000

tokens = []
pos = TOKEN_TABLE_OFF
for i in range(256):
    end = data.index(b'\x00', pos)
    tokens.append(data[pos:end].decode('ascii', errors='replace'))
    pos = end + 1

def decode_name(cb):
    return ''.join(tokens[b] for b in cb)

# Decode ALL firmware names
fw_names = []
pos = NAMES_OFF
for i in range(NUM_SYMS):
    el = data[pos]
    ed = data[pos+1:pos+1+el]
    pos += 1 + el
    if el > 0:
        stype = decode_name(ed[0:1])
        sname = decode_name(ed[1:])
        fw_names.append(f"{stype} {sname}")
    else:
        fw_names.append("? ")

# Save firmware names
with open(r'C:\InfoSec\android-redteam\work\fw_names.txt', 'w') as f:
    for name in fw_names:
        f.write(name + '\n')

# Read running kernel names
with open(r'C:\InfoSec\android-redteam\work\running_names.txt', 'r') as f:
    running_names = [line.strip() for line in f.readlines()]

print(f"Firmware symbols: {len(fw_names)}")
print(f"Running symbols: {len(running_names)}")

# Compare at same indices
matches = 0
mismatches = 0
empty_fw = 0
for i in range(min(len(fw_names), len(running_names))):
    if fw_names[i].startswith('? '):
        empty_fw += 1
        continue
    if fw_names[i] == running_names[i]:
        matches += 1
    else:
        mismatches += 1
        if mismatches <= 20:
            print(f"  MISMATCH [{i}]: running='{running_names[i]}' fw='{fw_names[i]}'")

print(f"\nMatches: {matches}")
print(f"Mismatches: {mismatches}")
print(f"Empty FW names: {empty_fw}")
print(f"Match rate: {matches/(matches+mismatches)*100:.1f}% (of non-empty)")

# Find commit_creds in running kernel by line
for i, name in enumerate(running_names):
    if 'commit_creds' in name and 'commit_creds' == name.split()[-1]:
        print(f"\nRunning kernel commit_creds: line {i} = '{name}'")
        # Check firmware at same index
        if i < len(fw_names):
            print(f"Firmware at same index: '{fw_names[i]}'")
            addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
            print(f"Firmware address at idx {i}: 0x{addr:08x}")
        # Also find in firmware by name
        for j, fn in enumerate(fw_names):
            if fn == name:
                faddr = struct.unpack_from('<I', data, TABLE_START + j * 4)[0]
                print(f"Firmware '{name}' at idx {j}: 0x{faddr:08x}")
                break

for i, name in enumerate(running_names):
    if 'prepare_kernel_cred' in name and 'prepare_kernel_cred' == name.split()[-1]:
        print(f"\nRunning kernel prepare_kernel_cred: line {i} = '{name}'")
        if i < len(fw_names):
            print(f"Firmware at same index: '{fw_names[i]}'")
            addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
            print(f"Firmware address at idx {i}: 0x{addr:08x}")
        for j, fn in enumerate(fw_names):
            if fn == name:
                faddr = struct.unpack_from('<I', data, TABLE_START + j * 4)[0]
                print(f"Firmware '{name}' at idx {j}: 0x{faddr:08x}")
                break
