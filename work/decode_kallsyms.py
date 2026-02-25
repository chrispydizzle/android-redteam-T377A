#!/usr/bin/env python3
"""Decode kallsyms names from the matching kernel binary."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# Known from previous analysis: addresses table at 0x87a554, 43663 entries
TABLE_START = 0x87a554
NUM_ENTRIES = 43663

# After addresses table: num_syms (4 bytes)
num_syms_off = TABLE_START + NUM_ENTRIES * 4
num_syms = struct.unpack_from('<I', data, num_syms_off)[0]
print(f'num_syms at 0x{num_syms_off:x}: {num_syms}')

# names table starts after num_syms
names_off = num_syms_off + 4
print(f'Names table starts at: 0x{names_off:x}')
print(f'First 32 bytes of names: {data[names_off:names_off+32].hex()}')

# Each name entry: [len] [type_token] [compressed_name_tokens...]
# len is the total number of bytes that follow (including type_token)
# Each byte in the compressed name is an index into the token table

# To find the token table, we need to skip past all names and markers
# Strategy: skip names by reading each entry's length, then find markers and tokens

# Read all name entries
pos = names_off
name_offsets = []  # offset of each name entry relative to names_off
for i in range(num_syms):
    name_offsets.append(pos - names_off)
    entry_len = data[pos]
    pos += 1 + entry_len
    if i < 5:
        entry_data = data[pos - entry_len:pos]
        print(f'  Name {i}: len={entry_len}, data={entry_data.hex()}')

names_end = pos
print(f'Names end at: 0x{names_end:x}')

# Align to 4 bytes
markers_off = (names_end + 3) & ~3
print(f'Markers at: 0x{markers_off:x}')

# markers: array of unsigned long, one per 256 symbols
num_markers = (num_syms + 255) // 256
print(f'Expected markers: {num_markers}')
markers = []
for i in range(num_markers):
    m = struct.unpack_from('<I', data, markers_off + i * 4)[0]
    markers.append(m)
    if i < 5:
        print(f'  marker[{i}]: {m}')

markers_end = markers_off + num_markers * 4
print(f'Markers end at: 0x{markers_end:x}')

# Token table follows markers
# It's 256 null-terminated strings concatenated
token_table_off = markers_end
print(f'Token table at: 0x{token_table_off:x}')
print(f'First 64 bytes: {data[token_table_off:token_table_off+64].hex()}')

# Parse token table: 256 null-terminated strings
tokens = []
pos = token_table_off
for i in range(256):
    end = data.index(b'\x00', pos)
    token = data[pos:end].decode('ascii', errors='replace')
    tokens.append(token)
    pos = end + 1

print(f'Parsed {len(tokens)} tokens')
print(f'Token table ends at: 0x{pos:x}')

# Show some tokens
for i in range(20):
    print(f'  token[{i}]: {repr(tokens[i])}')
print('  ...')
for i in range(240, 256):
    print(f'  token[{i}]: {repr(tokens[i])}')

# Token index follows token table (256 x uint16)
token_index_off = pos
print(f'\nToken index at: 0x{token_index_off:x}')

# Now decode names
def decode_name(name_data):
    """Decode a compressed kallsyms name."""
    result = ''
    for byte in name_data:
        result += tokens[byte]
    return result

# Decode first 20 names
print('\nFirst 20 decoded symbols:')
pos = names_off
for i in range(20):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    # First byte is type, rest is compressed name
    sym_type = tokens[entry_data[0]]
    sym_name = decode_name(entry_data[1:])
    addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
    print(f'  [{i}] 0x{addr:08x} {sym_type} {sym_name}')
    pos += 1 + entry_len

# Now search for commit_creds
print('\nSearching for commit_creds and prepare_kernel_cred...')
pos = names_off
for i in range(num_syms):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    sym_type = tokens[entry_data[0]]
    sym_name = decode_name(entry_data[1:])
    
    if 'commit_creds' in sym_name or 'prepare_kernel_cred' in sym_name:
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        print(f'  [{i}] 0x{addr:08x} {sym_type} {sym_name}')
    
    pos += 1 + entry_len

# Also dump symbols around index 1940-1960
print('\nSymbols at indices 1935-1960:')
pos = names_off
for i in range(num_syms):
    entry_len = data[pos]
    if 1935 <= i <= 1960:
        entry_data = data[pos+1:pos+1+entry_len]
        sym_type = tokens[entry_data[0]]
        sym_name = decode_name(entry_data[1:])
        addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
        print(f'  [{i}] 0x{addr:08x} {sym_type} {sym_name}')
    pos += 1 + entry_len
    if i > 1960:
        break
