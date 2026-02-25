#!/usr/bin/env python3
"""Find kallsyms token table by searching for characteristic patterns."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# The token table is 256 null-terminated ASCII strings
# Common tokens: '_', 't', 'e', 's', 'r', 'n', 'i', 'er', 'in', 'on', 'se', ...
# The token table usually starts near the end of the kernel .rodata section

# Search for a region that looks like 256 consecutive null-terminated ASCII strings
# Each string is 1-15 chars long, all printable ASCII + underscore + digits

def is_token_char(b):
    return (0x20 <= b <= 0x7e)  # printable ASCII

# Strategy: look for a sequence like: <short ASCII><NUL><short ASCII><NUL>...
# with at least 256 tokens

print("Searching for token table pattern...")
# Look after the addresses table (beyond 0x8A0000)
search_start = 0x8A0000

for off in range(search_start, len(data) - 1000):
    # Check if this looks like a token table start
    # First token should be 1-4 chars + NUL
    if not is_token_char(data[off]):
        continue
    
    # Try to parse 256 tokens from here
    pos = off
    tokens = []
    valid = True
    for t in range(256):
        # Read until NUL
        start = pos
        while pos < len(data) and data[pos] != 0:
            if not is_token_char(data[pos]):
                valid = False
                break
            pos += 1
        if not valid or pos >= len(data):
            valid = False
            break
        token = data[start:pos].decode('ascii')
        if len(token) == 0 or len(token) > 20:
            valid = False
            break
        tokens.append(token)
        pos += 1  # skip NUL
    
    if valid and len(tokens) == 256:
        # Check if tokens look reasonable (contain common substrings)
        all_tokens = ' '.join(tokens)
        has_underscore = '_' in all_tokens
        has_common = any(t in tokens for t in ['t', 'e', 's', '_'])
        total_len = pos - off
        
        if has_underscore and total_len < 5000:
            print(f"\nCandidate token table at 0x{off:x} (size: {total_len} bytes)")
            # Show first 30 tokens
            for i in range(30):
                print(f"  token[{i}]: {repr(tokens[i])}")
            print("  ...")
            for i in range(250, 256):
                print(f"  token[{i}]: {repr(tokens[i])}")
            
            # Check if we can find 'commit_creds' using these tokens
            # First verify: can these tokens produce common kernel symbol names?
            has_cred = any('cred' in t for t in tokens)
            has_commit = any('commit' in t or 'omm' in t for t in tokens)
            print(f"\n  Has 'cred' substring: {has_cred}")
            print(f"  Has 'commit/omm' substring: {has_commit}")
            
            # Now find what's BEFORE this token table - should be markers
            # markers: (num_syms+255)//256 uint32 values, last one before token table
            num_syms = 43664
            num_markers = (num_syms + 255) // 256  # 171
            markers_start = off - num_markers * 4
            print(f"\n  Expected markers at 0x{markers_start:x}")
            marker0 = struct.unpack_from('<I', data, markers_start)[0]
            marker1 = struct.unpack_from('<I', data, markers_start + 4)[0]
            marker_last = struct.unpack_from('<I', data, markers_start + (num_markers-1)*4)[0]
            print(f"  marker[0]: {marker0}")
            print(f"  marker[1]: {marker1}")
            print(f"  marker[{num_markers-1}]: {marker_last}")
            
            if marker0 == 0 and marker1 > 0 and marker1 < 100000:
                print("  *** MARKERS LOOK VALID! ***")
                
                # Names table starts right after num_syms and ends at markers
                names_start_calc = 0x8A4F90 + 4  # after num_syms
                names_len = markers_start - names_start_calc
                print(f"  Names table: 0x{names_start_calc:x} to 0x{markers_start:x} ({names_len} bytes)")
                
                # Save token table info for the decoder
                print(f"\n  TOKEN_TABLE_OFF = 0x{off:x}")
                print(f"  MARKERS_OFF = 0x{markers_start:x}")
                print(f"  NAMES_OFF = 0x{names_start_calc:x}")
                
            break  # Found it
    
    # Optimization: skip ahead if we hit a long non-ASCII run
    if not valid and pos > off + 10:
        off = pos
