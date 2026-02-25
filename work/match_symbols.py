#!/usr/bin/env python3
"""Match running kernel symbol names with firmware addresses."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# Offsets from previous analysis
TABLE_START = 0x87A550
NUM_SYMS = 43664
NAMES_OFF = 0x8A4F94
TOKEN_TABLE_OFF = 0x926000

# Parse token table
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

# Decode ALL firmware symbols into a list
fw_symbols = []
pos = NAMES_OFF
for i in range(NUM_SYMS):
    entry_len = data[pos]
    entry_data = data[pos+1:pos+1+entry_len]
    pos += 1 + entry_len
    
    addr = struct.unpack_from('<I', data, TABLE_START + i * 4)[0]
    
    if entry_len > 0:
        sym_type = decode_name(entry_data[0:1])
        sym_name = decode_name(entry_data[1:])
    else:
        sym_type = '?'
        sym_name = ''
    
    fw_symbols.append((addr, sym_type, sym_name))

# Build name->address lookup
name_to_addr = {}
for i, (addr, stype, name) in enumerate(fw_symbols):
    key = f"{stype} {name}"
    name_to_addr[key] = (addr, i)

# Now match running kernel symbols
# Lines 1940-1975 from running kernel (1-based line numbers)
running_symbols = [
    (1940, 't', 'profiling_store'),
    (1941, 't', 'put_cred_rcu'),
    (1942, 'T', '__put_cred'),
    (1943, 'T', 'exit_creds'),
    (1944, 'T', 'get_task_cred'),
    (1945, 'T', 'commit_creds'),
    (1946, 'T', 'abort_creds'),
    (1947, 'T', 'cred_alloc_blank'),
    (1948, 'T', 'prepare_creds'),
    (1949, 'T', 'prepare_exec_creds'),
    (1950, 'T', 'copy_creds'),
    (1951, 'T', 'override_creds'),
    (1952, 'T', 'revert_creds'),
    (1953, 'T', 'prepare_kernel_cred'),
    (1954, 'T', 'set_security_override'),
    (1955, 'T', 'set_security_override_from_ctx'),
    (1956, 'T', 'set_create_files_as'),
]

print("Running kernel symbol -> Firmware address mapping:")
print(f"{'Line':>6} {'Type':>4} {'Name':<35} {'FW Addr':>12} {'FW Index':>10}")
print("-" * 75)

for line_num, stype, name in running_symbols:
    key = f"{stype} {name}"
    if key in name_to_addr:
        addr, fw_idx = name_to_addr[key]
        marker = " <<<<" if name in ('commit_creds', 'prepare_kernel_cred') else ""
        print(f"{line_num:>6} {stype:>4} {name:<35} 0x{addr:08x} {fw_idx:>10}{marker}")
    else:
        # Try lowercase type
        key2 = f"{stype.lower()} {name}"
        if key2 in name_to_addr:
            addr, fw_idx = name_to_addr[key2]
            print(f"{line_num:>6} {stype:>4} {name:<35} 0x{addr:08x} {fw_idx:>10} (type case diff)")
        else:
            print(f"{line_num:>6} {stype:>4} {name:<35} {'NOT FOUND':>12}")

# Also verify with known addresses from stack traces
print("\n\nVerification with known stack trace addresses:")
known = [
    ('dump_backtrace', 0xc0012838),
    ('show_stack', 0xc00129c0),
    ('warn_slowpath_common', 0xc002a61c),
    ('warn_slowpath_null', 0xc002a740),
    ('kernel_init', 0xc07d4fa0),
    ('dump_stack', 0xc07e0dac),
    ('do_one_initcall', 0xc0a28b50),
]

for name, running_addr in known:
    # Find in firmware
    for i, (addr, stype, sname) in enumerate(fw_symbols):
        if sname == name and stype in ('T', 't'):
            diff = addr - running_addr
            print(f"  {name}: running=0x{running_addr:08x}, firmware=0x{addr:08x}, diff={diff:+d}")
            break
