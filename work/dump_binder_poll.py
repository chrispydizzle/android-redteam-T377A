import struct

d = open('/tmp/vmlinux', 'rb').read()
VADDR_BASE = 0xC0008000

# The binder_poll string reference is at 0xc05dd820 (literal pool)
# LDR instructions referencing it are around 0xc05dd6f8-0xc05dd7d8
# The function probably starts before 0xc05dd6f8

# Look for PUSH (function prologue) before 0xc05dd6f8
target = 0xc05dd6f8 - VADDR_BASE
for k in range(target, max(0, target - 512), -4):
    insn = struct.unpack('<I', d[k:k+4])[0]
    if (insn & 0xFFFF0000) == 0xE92D0000:  # STMDB SP!, {regs} = PUSH
        func_start = k
        break

print(f'Function likely starts at offset {func_start:#x} (vaddr {VADDR_BASE + func_start:#010x})')

# Write raw binary for disassembly
func_end = func_start + 512  # Dump 512 bytes
raw = d[func_start:func_end]
open('/tmp/binder_poll.bin', 'wb').write(raw)
print(f'Wrote {len(raw)} bytes to /tmp/binder_poll.bin')
print(f'Disassemble with: arm-linux-gnueabi-objdump -D -b binary -m arm --start-address=0 --stop-address={len(raw)} /tmp/binder_poll.bin')

# Also dump the literal pool
pool_start = 0xc05dd800 - VADDR_BASE
pool_end = pool_start + 64
print(f'\nLiteral pool ({VADDR_BASE + pool_start:#010x}):')
for i in range(pool_start, min(pool_end, len(d)), 4):
    val = struct.unpack('<I', d[i:i+4])[0]
    vaddr = VADDR_BASE + i
    # Try to identify what this value is
    label = ""
    if 0xC0000000 <= val < 0xD0000000:
        label = " (kernel addr)"
    print(f'  {vaddr:#010x}: {val:#010x}{label}')
