"""Deep analysis of sboot.bin bootloader and param.bin settings."""
import struct
import os
import tarfile
import io
import re

DATA_DIR = r'C:\InfoSec\android-redteam\data'

# ============================================================
# PARAM.BIN analysis — it's a tar archive
# ============================================================
print("=" * 70)
print("PARAM.BIN — Samsung Parameter Partition")
print("=" * 70)

param_path = os.path.join(DATA_DIR, 'param.bin')
with open(param_path, 'rb') as f:
    param = f.read()

print(f"Size: {len(param)} bytes")
print(f"Header: {param[:16]}")

# It's a tar (ustar) archive
try:
    with tarfile.open(fileobj=io.BytesIO(param), mode='r:') as tf:
        print(f"\nContained files:")
        for m in tf.getmembers():
            print(f"  {m.size:>8}  {m.name}")
        
        # Extract adv-env.img
        for m in tf.getmembers():
            if 'env' in m.name.lower() or 'param' in m.name.lower():
                f = tf.extractfile(m)
                if f:
                    data = f.read()
                    outpath = os.path.join(DATA_DIR, m.name.replace('/', '_'))
                    with open(outpath, 'wb') as out:
                        out.write(data)
                    print(f"\n  Extracted {m.name} -> {outpath} ({len(data)} bytes)")
                    
                    # Parse env - Samsung stores key=value pairs
                    print(f"\n  Content analysis of {m.name}:")
                    # Look for text content
                    text_regions = []
                    i = 0
                    while i < len(data):
                        if 32 <= data[i] < 127:
                            start = i
                            while i < len(data) and 32 <= data[i] < 127:
                                i += 1
                            if i - start >= 4:
                                text = data[start:i].decode('ascii')
                                text_regions.append((start, text))
                        i += 1
                    
                    for offset, text in text_regions:
                        print(f"    0x{offset:04x}: {text}")
except Exception as e:
    print(f"  Tar parse error: {e}")
    # Maybe it's not a standard tar, try looking at raw content
    print("  Trying raw content scan...")

# ============================================================
# SBOOT.BIN deep analysis — focus on security mechanisms
# ============================================================
print(f"\n{'='*70}")
print("SBOOT.BIN — Bootloader Security Mechanisms")
print(f"{'='*70}")

sboot_path = os.path.join(DATA_DIR, 'sboot.bin')
with open(sboot_path, 'rb') as f:
    sboot = f.read()

print(f"Size: {len(sboot)} bytes")

# Find all printable string runs >= 6 chars
print("\n--- All strings >= 6 chars (security/boot related) ---")
strings = []
i = 0
while i < len(sboot):
    if 32 <= sboot[i] < 127:
        start = i
        while i < len(sboot) and (32 <= sboot[i] < 127 or sboot[i] == 0x0a):
            i += 1
        if i - start >= 6:
            s = sboot[start:i].decode('ascii', errors='replace').strip()
            strings.append((start, s))
    i += 1

# Filter for security-relevant strings
security_keywords = [
    'lock', 'unlock', 'debug', 'root', 'verify', 'sign', 'cert', 'key',
    'odin', 'loke', 'download', 'flash', 'boot', 'secure', 'tima', 'knox',
    'warranty', 'jtag', 'uart', 'carrier', 'network', 'sim', 'att',
    'frp', 'oem', 'aes', 'rsa', 'sha', 'hash', 'fuse', 'efuse',
    'mode', 'level', 'param', 'switch', 'eng', 'user', 'devel',
    'check', 'fail', 'pass', 'error', 'abort', 'skip', 'bypass',
    'cc_mode', 'sud', 'reboot', 'partition', 'kernel', 'recovery',
    'emmc', 'mmc', 'write', 'read', 'erase', 'protect',
    'block', 'allow', 'deny', 'restrict', 'enable', 'disable',
    'nand', 'pit', 'thor', 'ragnaroek', 'odin_download',
]

relevant = []
for offset, s in strings:
    s_lower = s.lower()
    for kw in security_keywords:
        if kw in s_lower:
            relevant.append((offset, s))
            break

# Group and deduplicate
seen = set()
for offset, s in relevant:
    if s not in seen:
        seen.add(s)
        # Truncate long strings
        display = s[:100] + "..." if len(s) > 100 else s
        print(f"  0x{offset:06x}: {display}")

# ============================================================
# Look for format strings (printf patterns) — these reveal function behavior
# ============================================================
print(f"\n--- Format strings (reveal function behavior) ---")
fmt_strings = [(o, s) for o, s in strings if '%' in s and any(c in s for c in 'dxsXpul')]
seen = set()
for offset, s in fmt_strings:
    if s not in seen and len(s) > 8:
        seen.add(s)
        display = s[:120] + "..." if len(s) > 120 else s
        # Only show security-relevant ones
        s_lower = s.lower()
        if any(kw in s_lower for kw in ['lock', 'debug', 'download', 'check', 'fail',
                                          'verify', 'sign', 'boot', 'odin', 'key',
                                          'tima', 'knox', 'fuse', 'mode', 'carrier',
                                          'warranty', 'param', 'secure', 'kernel',
                                          'partition', 'emmc', 'oem', 'efuse']):
            print(f"  0x{offset:06x}: {display}")

# ============================================================
# Analyze ODIN protocol handler in sboot
# ============================================================
print(f"\n--- ODIN Protocol Handler Analysis ---")
odin_offset = sboot.find(b'ODIN')
loke_offset = sboot.find(b'LOKE')
thor_offset = sboot.find(b'THOR')
print(f"  'ODIN' at: 0x{odin_offset:06x}" if odin_offset != -1 else "  'ODIN': not found")
print(f"  'LOKE' at: 0x{loke_offset:06x}" if loke_offset != -1 else "  'LOKE': not found")
print(f"  'THOR' at: 0x{thor_offset:06x}" if thor_offset != -1 else "  'THOR': not found")

# Find all occurrences
for pattern, name in [(b'ODIN', 'ODIN'), (b'LOKE', 'LOKE'), (b'THOR', 'THOR')]:
    idx = 0
    offsets = []
    while True:
        idx = sboot.find(pattern, idx)
        if idx == -1:
            break
        offsets.append(idx)
        idx += 1
    if offsets:
        print(f"  All '{name}' occurrences: {[f'0x{o:06x}' for o in offsets]}")

# ============================================================
# CC MODE analysis — what blocks downloads
# ============================================================
print(f"\n--- CC MODE Analysis ---")
cc_idx = sboot.find(b'CC MODE')
if cc_idx != -1:
    # Get surrounding context
    start = max(0, cc_idx - 100)
    end = min(len(sboot), cc_idx + 100)
    context = sboot[start:end]
    # Extract readable strings from context
    text = "".join(chr(b) if 32 <= b < 127 else "|" for b in context)
    print(f"  Context around 'CC MODE' (0x{cc_idx:06x}):")
    for line in text.split('|'):
        if len(line.strip()) >= 3:
            print(f"    {line.strip()}")

# ============================================================
# DEBUG_LEVEL analysis
# ============================================================
print(f"\n--- DEBUG_LEVEL Analysis ---")
for pattern in [b'DEBUG_LEVEL', b'debug_level']:
    idx = 0
    while True:
        idx = sboot.find(pattern, idx)
        if idx == -1:
            break
        start = max(0, idx - 32)
        end = min(len(sboot), idx + 64)
        context = sboot[start:end]
        text = "".join(chr(b) if 32 <= b < 127 else "|" for b in context)
        readable = [s for s in text.split('|') if len(s.strip()) >= 3]
        print(f"  At 0x{idx:06x}: {' // '.join(readable)}")
        idx += 1

# ============================================================
# OEM KEY analysis
# ============================================================
print(f"\n--- OEM KEY Analysis ---")
for pattern in [b'OEM_KEY', b'SKIP_AES', b'PREORDER']:
    idx = 0
    while True:
        idx = sboot.find(pattern, idx)
        if idx == -1:
            break
        start = max(0, idx - 16)
        end = min(len(sboot), idx + 64)
        context = sboot[start:end]
        text = "".join(chr(b) if 32 <= b < 127 else "|" for b in context)
        readable = [s for s in text.split('|') if len(s.strip()) >= 3]
        print(f"  At 0x{idx:06x}: {' // '.join(readable)}")
        idx += 1

print("\nDone.")
