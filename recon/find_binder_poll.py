import struct, re

d = open('/tmp/vmlinux', 'rb').read()

# Kernel loads at 0xC0008000, so offset 0 in binary = vaddr 0xC0008000
VADDR_BASE = 0xC0008000

# Find binder_poll string vaddr
binder_poll_str_off = d.find(b'binder_poll\x00')
binder_poll_str_vaddr = VADDR_BASE + binder_poll_str_off
print(f'binder_poll string at vaddr {binder_poll_str_vaddr:#010x}')

# Search for ARM32 literal pool entries that reference this vaddr
# On ARM, literal pools contain 32-bit addresses
# Search for the bytes of binder_poll_str_vaddr in little-endian
target_bytes = struct.pack('<I', binder_poll_str_vaddr)
print(f'Looking for bytes: {target_bytes.hex()}')

refs = []
for i in range(0, min(len(d) - 4, 0x800000)):  # Search in text section
    if d[i:i+4] == target_bytes:
        ref_vaddr = VADDR_BASE + i
        refs.append((i, ref_vaddr))
        if len(refs) <= 5:
            print(f'  Reference at offset {i:#x} (vaddr {ref_vaddr:#010x})')

print(f'Total references: {len(refs)}')

# For each reference, find the LDR instruction that loads from this literal pool entry
# The LDR rx, [pc, #off] computes: pc + 8 + off = literal_pool_addr
# So the LDR instruction is at: literal_pool_addr - 8 - off
# We need to search backwards from each literal pool entry for a matching LDR

# Actually, let's just dump the code around the first reference
if refs:
    for ri, (off, va) in enumerate(refs[:3]):
        # Look backwards to find the function that uses this literal
        # Typical pattern: function prologue then LDR, or LDR within function
        # Dump 256 bytes before the literal pool to find the LDR
        start = max(0, off - 512)
        chunk = d[start:off + 16]
        
        # Search for LDR instructions that target this literal pool entry
        # ARM LDR: cond 01 0P U0W1 Rn Rd offset12
        # LDR Rd, [PC, #imm] for literal pool: cond=always(0xE), P=1, U=1, W=0
        # Encoding: 0xE59Fd000 | (off & 0xFFF) where Rn=PC=0xF
        for j in range(0, len(chunk) - 4, 4):
            insn = struct.unpack('<I', chunk[j:j+4])[0]
            abs_off = start + j
            pc_val = VADDR_BASE + abs_off + 8  # ARM PC = instruction + 8
            # Check if this is LDR Rx, [PC, #imm]
            if (insn & 0x0F7F0000) == 0x051F0000:  # LDR Rx, [PC, +/-imm]
                imm = insn & 0xFFF
                if insn & 0x00800000:  # U bit (add)
                    target = pc_val + imm
                else:
                    target = pc_val - imm
                if target == va:
                    rd = (insn >> 12) & 0xF
                    func_start = abs_off
                    print(f'\n  LDR R{rd}, =binder_poll_str at vaddr {VADDR_BASE + abs_off:#010x}')
                    print(f'  Likely binder_poll function near this address')
                    
                    # Dump surrounding code as hex for manual analysis
                    # Look backwards for function prologue (PUSH/STMDB)
                    for k in range(abs_off, max(0, abs_off - 256), -4):
                        insn2 = struct.unpack('<I', d[k:k+4])[0]
                        if (insn2 & 0xFFFF0000) == 0xE92D0000:  # PUSH {regs}
                            print(f'  Function prologue (PUSH) at {VADDR_BASE + k:#010x}')
                            # Dump function from prologue to prologue+512
                            print(f'  Hex dump of function:')
                            for m in range(k, min(k + 256, len(d)), 4):
                                insn3 = struct.unpack('<I', d[m:m+4])[0]
                                vaddr = VADDR_BASE + m
                                print(f'    {vaddr:#010x}: {insn3:08x}')
                            break
