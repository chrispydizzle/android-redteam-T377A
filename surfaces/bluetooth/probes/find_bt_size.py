import struct
data = open('/tmp/vmlinux', 'rb').read()
base = 0xC0008000

# binder_poll is at 0xc05dd54c. Find BL calls from binder_poll to find binder_get_thread
binder_poll = 0xc05dd54c - base
print("=== Disassembling binder_poll for BL calls ===")
for j in range(0, 200, 4):
    off = binder_poll + j
    insn = struct.unpack('<I', data[off:off+4])[0]
    addr = 0xc05dd54c + j
    if (insn & 0x0F000000) == 0x0B000000:
        s = insn & 0xFFFFFF
        if s & 0x800000: s -= 0x1000000
        target = addr + 8 + (s << 2)
        print(f"  0x{addr:08x}: BL 0x{target:08x}")

# Now let's find binder_get_thread by looking for kzalloc call
# kzalloc on ARM32 typically calls __kmalloc with a size constant
# binder_get_thread should be near binder_poll
# Let's look for MOVW instructions near binder functions with sizes 128-256
print("\n=== Searching for kzalloc size in binder_get_thread candidates ===")
# Search 0xc05d8000 - 0xc05e2000 for PUSH followed by MOVW with size 128-256
for off in range(0xc05d8000 - base, 0xc05e2000 - base, 4):
    insn = struct.unpack('<I', data[off:off+4])[0]
    # Look for MOVW rd, #N where N is 128-256
    if (insn & 0xFFF00000) == 0xE3000000:
        imm = ((insn >> 4) & 0xF000) | (insn & 0xFFF)
        rd = (insn >> 12) & 0xF
        if 80 <= imm <= 256:
            addr = base + off
            # Check if next few instructions include a BL to kmalloc/kzalloc
            for k in range(4, 40, 4):
                if off + k + 4 > len(data): break
                insn2 = struct.unpack('<I', data[off+k:off+k+4])[0]
                if (insn2 & 0x0F000000) == 0x0B000000:
                    s2 = insn2 & 0xFFFFFF
                    if s2 & 0x800000: s2 -= 0x1000000
                    target = (base + off + k) + 8 + (s2 << 2)
                    # kzalloc/kmalloc are typically in c00xxxxx or c01xxxxx range
                    if 0xc0080000 <= target <= 0xc0200000:
                        print(f"  0x{addr:08x}: MOVW r{rd}, #{imm} (0x{imm:x}) ... BL 0x{target:08x}")
                        break
