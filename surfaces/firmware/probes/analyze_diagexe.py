import re, struct

with open('C:/InfoSec/android-redteam/work/diagexe_bin', 'rb') as f:
    data = f.read()

print(f'Binary size: {len(data)} bytes')
print()

# Extract all printable strings
strings = [(m.start(), m.group().decode()) for m in re.finditer(rb'[\x20-\x7e]{5,}', data)]

# Categories of interest
categories = {
    'DM/Protocol': [],
    'Buffer/Memory': [],
    'Read/Write/IO': [],
    'USB/tty': [],
    'Socket': [],
    'Error/Debug': [],
    'Security': [],
}

for offset, s in strings:
    sl = s.lower()
    if any(k in sl for k in ['dm_', 'diag', 'hdlc', 'frame', 'packet', 'protocol', '0x7e', '0x7f', 'escape']):
        categories['DM/Protocol'].append(f'  0x{offset:06x}: {s}')
    elif any(k in sl for k in ['buffer', 'alloc', 'malloc', 'size', 'length', 'overflow', 'memcpy', 'memset']):
        categories['Buffer/Memory'].append(f'  0x{offset:06x}: {s}')
    elif any(k in sl for k in ['read', 'write', 'recv', 'send', 'ioctl', 'open', 'close', 'select', 'poll']):
        categories['Read/Write/IO'].append(f'  0x{offset:06x}: {s}')
    elif any(k in sl for k in ['tty', 'usb', 'serial', 'com', 'umts', 'gadget']):
        categories['USB/tty'].append(f'  0x{offset:06x}: {s}')
    elif any(k in sl for k in ['socket', 'connect', 'bind', 'listen', 'accept', 'unix', 'stream']):
        categories['Socket'].append(f'  0x{offset:06x}: {s}')
    elif any(k in sl for k in ['error', 'fail', 'warn', 'debug', 'log', 'assert']):
        categories['Error/Debug'].append(f'  0x{offset:06x}: {s}')
    elif any(k in sl for k in ['root', 'uid', 'gid', 'setuid', 'cap', 'priv', 'switch', 'user']):
        categories['Security'].append(f'  0x{offset:06x}: {s}')

for cat, items in categories.items():
    if items:
        print(f'=== {cat} ({len(items)} strings) ===')
        for item in items[:25]:
            print(item)
        if len(items) > 25:
            print(f'  ... and {len(items)-25} more')
        print()

# Also look for hardcoded buffer sizes and interesting constants
print("=== Potential buffer size constants ===")
# Search for common buffer allocation patterns in ARM
# Look for MOV/LDR instructions loading specific sizes
for offset in range(0, len(data)-4, 4):
    insn = struct.unpack_from('<I', data, offset)[0]
    # ARM MOV immediate: condition[31:28] 00 1 1101 S 0000 Rd[15:12] imm12
    if (insn & 0x0FE00000) == 0x03A00000:
        rd = (insn >> 12) & 0xF
        imm = insn & 0xFFF
        rotate = (imm >> 8) & 0xF
        val = imm & 0xFF
        val = (val >> (rotate*2)) | (val << (32 - rotate*2)) & 0xFFFFFFFF
        if val in [256, 512, 1024, 2048, 4096, 8192, 16384, 0x800, 0x1000, 0x2000, 0x4000]:
            print(f'  0x{offset:06x}: MOV R{rd}, #{val} (0x{val:x})')
