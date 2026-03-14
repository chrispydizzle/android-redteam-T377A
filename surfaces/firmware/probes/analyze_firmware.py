"""Extract and analyze key partitions from firmware tars.
Focuses on sboot.bin (bootloader) and param.bin (settings).
"""
import tarfile
import os
import struct
import sys

IMAGES_DIR = r'C:\InfoSec\android-redteam\images'
OUTPUT_DIR = r'C:\InfoSec\android-redteam\data'

def extract_from_tar(tar_path, filename, output_path):
    """Extract a single file from a Samsung tar.md5."""
    with tarfile.open(tar_path, 'r:') as tf:
        for m in tf.getmembers():
            if m.name == filename:
                f = tf.extractfile(m)
                if f:
                    data = f.read()
                    with open(output_path, 'wb') as out:
                        out.write(data)
                    return data
    return None

# Extract sboot.bin and param.bin from BL tar
bl_tar = os.path.join(IMAGES_DIR, 'BL_T377AUCU2AQGF_CL11788437_QB14156771_REV00_user_low_ship.tar.md5')

print("=" * 60)
print("Extracting sboot.bin (bootloader)...")
print("=" * 60)
sboot_path = os.path.join(OUTPUT_DIR, 'sboot.bin')
sboot = extract_from_tar(bl_tar, 'sboot.bin', sboot_path)
if sboot:
    print(f"  Size: {len(sboot)} bytes ({len(sboot)/1024:.1f} KB)")
    
    # Basic analysis
    print(f"\n  First 64 bytes (header):")
    for i in range(0, 64, 16):
        chunk = sboot[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {i:04x}: {hex_str}  {ascii_str}")
    
    # Search for interesting strings
    print(f"\n  Interesting strings found:")
    interesting = [b'ODIN', b'LOKE', b'CERT', b'SIGN', b'LOCK', b'UNLOCK',
                   b'CARR', b'ATT', b'DOWNLOAD', b'DEBUG', b'UART', b'JTAG',
                   b'ROOT', b'SELINUX', b'ENG', b'USER', b'SECURE', b'BOOT',
                   b'FAIL', b'PASS', b'VERIFY', b'CHECK', b'HASH', b'SHA',
                   b'RSA', b'AES', b'KEY', b'TIMA', b'KNOX', b'WARRANTY',
                   b'SBL', b'BL_', b'KERNEL', b'RAMDISK', b'FOTA',
                   b'EMMC', b'PARTITION', b'NAND']
    found_strings = set()
    for pattern in interesting:
        idx = 0
        while True:
            idx = sboot.find(pattern, idx)
            if idx == -1:
                break
            # Get surrounding context
            start = max(0, idx - 4)
            end = min(len(sboot), idx + len(pattern) + 20)
            context = sboot[start:end]
            ascii_ctx = "".join(chr(b) if 32 <= b < 127 else "." for b in context)
            key = f"0x{idx:06x}: {ascii_ctx}"
            if key not in found_strings:
                found_strings.add(key)
                print(f"    {key}")
            idx += 1
    
    # Look for ARM exception vectors
    print(f"\n  ARM32 analysis:")
    word0 = struct.unpack("<I", sboot[0:4])[0]
    print(f"    First word: 0x{word0:08X}")
    if (word0 & 0xFF000000) == 0xEA000000:
        branch_offset = (word0 & 0x00FFFFFF) << 2
        print(f"    ARM branch instruction → offset 0x{branch_offset + 8:08X}")
    
    # Check for embedded certificates/keys
    # Look for ASN.1 SEQUENCE tag (0x30 0x82) which indicates certificates
    cert_count = 0
    idx = 0
    while True:
        idx = sboot.find(b'\x30\x82', idx)
        if idx == -1:
            break
        length = struct.unpack(">H", sboot[idx+2:idx+4])[0]
        if 256 < length < 4096:  # Reasonable cert size
            cert_count += 1
            if cert_count <= 5:
                print(f"    Potential ASN.1 certificate at 0x{idx:06x} (length: {length})")
        idx += 1
    if cert_count > 5:
        print(f"    ... and {cert_count - 5} more potential certificates")
else:
    print("  FAILED to extract")

print(f"\n{'='*60}")
print("Extracting param.bin...")
print(f"{'='*60}")
param_path = os.path.join(OUTPUT_DIR, 'param.bin')
param = extract_from_tar(bl_tar, 'param.bin', param_path)
if param:
    print(f"  Size: {len(param)} bytes ({len(param)/1024:.1f} KB)")
    
    # Header analysis
    print(f"\n  First 128 bytes:")
    for i in range(0, 128, 16):
        chunk = param[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {i:04x}: {hex_str}  {ascii_str}")
    
    # Search for Samsung param signatures
    print(f"\n  Known Samsung param structures:")
    # Samsung PARAM partition often has "SAMSUNG_ANDROID" or version strings
    for pattern in [b'SAMSUNG', b'ANDROID', b'PARAM', b'VERSION', b'DEBUG',
                    b'BOOT_MODE', b'WARRANTY', b'CARRIER', b'SIM', b'LOCK',
                    b'ODIN', b'DOWNLOAD', b'UART', b'USB', b'ROOT',
                    b'SELINUX', b'dm-verity', b'ENG', b'USERDEBUG']:
        idx = param.find(pattern)
        if idx != -1:
            start = max(0, idx - 8)
            end = min(len(param), idx + len(pattern) + 32)
            context = param[start:end]
            ascii_ctx = "".join(chr(b) if 32 <= b < 127 else "." for b in context)
            print(f"    0x{idx:06x}: {ascii_ctx}")
    
    # Check for all non-null regions (param is often mostly zeros)
    non_null = 0
    regions = []
    in_region = False
    region_start = 0
    for i in range(len(param)):
        if param[i] != 0:
            if not in_region:
                region_start = i
                in_region = True
            non_null += 1
        else:
            if in_region:
                if i - region_start >= 8:  # Only track regions >= 8 bytes
                    regions.append((region_start, i))
                in_region = False
    if in_region and len(param) - region_start >= 8:
        regions.append((region_start, len(param)))
    
    print(f"\n  Non-null bytes: {non_null}/{len(param)} ({100*non_null/len(param):.1f}%)")
    print(f"  Data regions (>= 8 bytes): {len(regions)}")
    for start, end in regions[:20]:
        chunk = param[start:min(end, start+48)]
        ascii_ctx = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    0x{start:06x}-0x{end:06x} ({end-start:>6} bytes): {ascii_ctx[:60]}")
else:
    print("  FAILED to extract")

print("\nDone.")
