#!/usr/bin/env python3
"""Find cred offset in task_struct by disassembling commit_creds."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# Try different base addresses to find commit_creds in the binary
# commit_creds virtual addr: 0xc0054328
for base in [0xc0008000, 0xc0008180, 0xc0008944, 0xc0008540]:
    cc_off = 0xc0054328 - base
    if 0 <= cc_off < len(data) - 64:
        instrs = [struct.unpack_from('<I', data, cc_off + i*4)[0] for i in range(16)]
        # Check if first instruction looks like ARM function prologue
        first = instrs[0]
        is_push = (first & 0xFFFF0000) in [0xe92d0000, 0xe52d0000]  # stmdb/str sp
        is_mov = (first & 0xFFF00000) == 0xe1a00000  # mov
        print(f"base=0x{base:08x} offset=0x{cc_off:x}:")
        for i, ins in enumerate(instrs):
            # Decode simple ARM instructions
            desc = ""
            if (ins & 0x0FFF0000) == 0x059f0000:  # ldr rN, [pc, #imm]
                rd = (ins >> 12) & 0xF
                imm = ins & 0xFFF
                target = cc_off + i*4 + 8 + imm
                if target < len(data):
                    val = struct.unpack_from('<I', data, target)[0]
                    desc = f"ldr r{rd}, [pc, #0x{imm:x}] → 0x{val:08x}"
            elif (ins & 0xFFFF0000) == 0xe92d0000:
                desc = f"push {{{ins & 0xFFFF:#06x}}}"
            elif (ins & 0x0F000000) == 0x05000000:  # str/ldr with immediate
                is_load = (ins >> 20) & 1
                rd = (ins >> 12) & 0xF
                rn = (ins >> 16) & 0xF
                imm = ins & 0xFFF
                up = (ins >> 23) & 1
                op = "ldr" if is_load else "str"
                sign = "+" if up else "-"
                desc = f"{op} r{rd}, [r{rn}, #{sign}0x{imm:x}]"
            elif (ins & 0x0FF00000) == 0xe3a00000:  # mov rN, #imm
                rd = (ins >> 12) & 0xF
                imm = ins & 0xFF
                rot = ((ins >> 8) & 0xF) * 2
                val = (imm >> rot) | (imm << (32 - rot)) if rot else imm
                desc = f"mov r{rd}, #0x{val:x}"
            
            print(f"  +{i*4:3d}: {ins:08x}  {desc}")
        print()

# Also search for the string 'cred' offset pattern in the kernel
# The key str/ldr instruction that accesses task->cred will have
# an immediate offset that tells us the cred field offset
