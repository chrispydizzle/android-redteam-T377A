#!/usr/bin/env python3
"""Properly decode kallsyms from Samsung kernel to find l2cap_config_rsp."""
import struct

data = open('work/firmware/vmlinux_aqgf', 'rb').read()
BASE = 0xC0008000

# Known: addresses table at 0x87a554
TABLE_START = 0x87a554

# Scan to find num_syms: it's the first non-kernel-address after the table
pos = TABLE_START
count = 0
while pos + 4 <= len(data):
    v = struct.unpack_from('<I', data, pos)[0]
    if 0xc0000000 <= v <= 0xc1200000 or v == 0:
        count += 1
        pos += 4
    else:
        break

print(f"Address table: {count} entries, ends at 0x{pos:x}")

# num_syms should be right after
num_syms = struct.unpack_from('<I', data, pos)[0]
print(f"Value after table: {num_syms} (0x{num_syms:x})")

# If that doesn't match, try aligned offset
if num_syms != count:
    # Try next aligned position
    for try_off in range(pos, pos + 32, 4):
        v = struct.unpack_from('<I', data, try_off)[0]
        if v == count or abs(v - count) < 10:
            print(f"num_syms={v} found at 0x{try_off:x}")
            num_syms = v
            pos = try_off
            break

NUM_ENTRIES = count
names_off = pos + 4
print(f"Names start at 0x{names_off:x}")

# Read compressed name entries
name_positions = []
p = names_off
for i in range(min(NUM_ENTRIES, 50000)):
    if p >= len(data):
        break
    entry_len = data[p]
    if entry_len == 0:
        # Could be padding or end
        name_positions.append((p, 0, b''))
        p += 1
        continue
    entry_data = data[p+1:p+1+entry_len]
    name_positions.append((p, entry_len, entry_data))
    p += 1 + entry_len

names_end = p
print(f"Read {len(name_positions)} name entries, names end at 0x{names_end:x}")

# Align to 4 bytes
markers_off = (names_end + 3) & ~3

# Number of markers
num_markers = (NUM_ENTRIES + 255) // 256
markers_end = markers_off + num_markers * 4

# Token table follows
token_off = markers_end

# Parse 256 null-terminated token strings
tokens = []
tp = token_off
for i in range(256):
    if tp >= len(data):
        tokens.append('')
        continue
    end = data.index(b'\x00', tp)
    tok = data[tp:end]
    tokens.append(tok)
    tp = end + 1

print(f"Token table at 0x{token_off:x}, ends at 0x{tp:x}")
# Show some tokens
for i in [0, 1, 2, 3, 10, 20, 50, 100, 200, 255]:
    if i < len(tokens):
        print(f"  token[{i}]: {tokens[i]}")

# Decode a compressed name
def decode_name(entry_data):
    result = b''
    for byte in entry_data:
        result += tokens[byte]
    return result

# Try decoding first few names
print("\nFirst 10 symbols:")
for i in range(min(10, len(name_positions))):
    pos_n, elen, edata = name_positions[i]
    if elen == 0:
        print(f"  [{i}] (empty)")
        continue
    try:
        sym_type_tok = tokens[edata[0]]
        sym_name = decode_name(edata[1:])
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        print(f"  [{i}] 0x{addr:08x} {sym_type_tok} {sym_name}")
    except Exception as e:
        print(f"  [{i}] decode error: {e}")

# Now search for l2cap in ALL names
print("\nSearching for 'l2cap' in symbol names...")
l2cap_syms = []
for i in range(min(NUM_ENTRIES, len(name_positions))):
    pos_n, elen, edata = name_positions[i]
    if elen < 2:
        continue
    try:
        name = decode_name(edata[1:])
        if b'l2cap' in name:
            addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
            sym_type = decode_name(edata[0:1])
            l2cap_syms.append((i, addr, sym_type, name))
    except:
        pass

print(f"Found {len(l2cap_syms)} l2cap symbols")
for idx, addr, stype, name in l2cap_syms:
    try:
        print(f"  [{idx}] 0x{addr:08x} {stype.decode()} {name.decode()}")
    except:
        print(f"  [{idx}] 0x{addr:08x} {stype} {name}")

# Also verify commit_creds
print("\nVerifying known symbols...")
for i in range(min(NUM_ENTRIES, len(name_positions))):
    pos_n, elen, edata = name_positions[i]
    if elen < 2:
        continue
    try:
        name = decode_name(edata[1:])
        if b'commit_cred' in name or b'prepare_kernel' in name or b'selinux_enforc' in name:
            addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
            sym_type = decode_name(edata[0:1])
            print(f"  [{i}] 0x{addr:08x} {sym_type.decode()} {name.decode()}")
    except:
        pass
