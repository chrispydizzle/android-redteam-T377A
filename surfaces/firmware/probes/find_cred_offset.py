#!/usr/bin/env python3
"""Find text_offset by matching function prologue pattern."""
import struct

with open(r'C:\InfoSec\android-redteam\work\vmlinux_aqgf', 'rb') as f:
    data = f.read()

# The function prologue for commit_creds should be:
# e1a0c00d  mov ip, sp
# e92dXXXX  push {...}
# e24cb004  sub fp, ip, #4
prologue = bytes([0x0d, 0xc0, 0xa0, 0xe1])  # e1a0c00d little-endian

# Search near expected offsets for this prologue
# commit_creds = 0xc0054328
# The base offset varies. Let's try finding the prologue.
for base_guess in range(0x4b000, 0x4e000, 4):
    if data[base_guess:base_guess+4] == prologue:
        next_instr = struct.unpack_from('<I', data, base_guess+4)[0]
        if (next_instr & 0xFFFF0000) == 0xe92d0000:  # push
            # This could be commit_creds!
            text_offset = 0xc0054328 - base_guess
            print(f"Prologue at 0x{base_guess:x}, text_offset=0x{text_offset:08x}")
            
            # Verify: check if _stext (0xc0008944) also has a known pattern
            stext_file = 0xc0008944 - text_offset
            if 0 <= stext_file < len(data):
                val = struct.unpack_from('<I', data, stext_file)[0]
                print(f"  _stext file offset 0x{stext_file:x}: 0x{val:08x}")
            
            # Dump more of the function
            print(f"  commit_creds disassembly:")
            for i in range(40):
                off = base_guess + i * 4
                ins = struct.unpack_from('<I', data, off)[0]
                desc = ""
                # Decode key instructions
                if (ins & 0x0F000000) == 0x05000000:  # str/ldr immediate
                    is_load = (ins >> 20) & 1
                    rd = (ins >> 12) & 0xF
                    rn = (ins >> 16) & 0xF
                    imm = ins & 0xFFF
                    up = (ins >> 23) & 1
                    sign = "" if up else "-"
                    op = "ldr" if is_load else "str"
                    desc = f"{op} r{rd}, [r{rn}, #{sign}{imm:#x}]"
                elif (ins & 0xFFFF0000) == 0xe92d0000:
                    regs = []
                    for b in range(16):
                        if ins & (1 << b): regs.append(f"r{b}")
                    desc = f"push {{{', '.join(regs)}}}"
                elif (ins & 0x0FF00000) == 0xe3a00000:
                    rd = (ins >> 12) & 0xF
                    imm = ins & 0xFF
                    rot = ((ins >> 8) & 0xF) * 2
                    if rot:
                        val = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF
                    else:
                        val = imm
                    desc = f"mov r{rd}, #{val:#x}"
                elif (ins & 0x0FFF0000) == 0x059f0000:  # ldr Rd, [pc, #imm]
                    rd = (ins >> 12) & 0xF
                    imm = ins & 0xFFF
                    target = off + 8 + imm
                    if target < len(data):
                        val = struct.unpack_from('<I', data, target)[0]
                        desc = f"ldr r{rd}, =0x{val:08x}"
                elif ins == 0xe1a0c00d:
                    desc = "mov ip, sp"
                elif (ins & 0xFFFFF000) == 0xe24cb000:
                    imm = ins & 0xFFF
                    desc = f"sub fp, ip, #{imm:#x}"
                elif (ins & 0x0F000000) == 0x0b000000:
                    desc = "bl ..."
                elif (ins & 0x0FF0F000) == 0x01500000:
                    rn = (ins >> 16) & 0xF
                    rm = ins & 0xF
                    desc = f"cmp r{rn}, r{rm}"
                elif (ins & 0x0FF00000) == 0x03500000:
                    rn = (ins >> 16) & 0xF
                    imm = ins & 0xFF
                    desc = f"cmp r{rn}, #{imm:#x}"
                elif (ins & 0x0FF00FFF) == 0x01a00000:
                    rd = (ins >> 12) & 0xF
                    rm = ins & 0xF
                    desc = f"mov r{rd}, r{rm}"
                
                # Highlight cred-related stores/loads
                highlight = ""
                if desc and ("[r" in desc) and any(f"#{x:#x}" in desc for x in range(0x200, 0x400)):
                    highlight = " *** POSSIBLE CRED OFFSET ***"
                
                print(f"    +{i*4:3d}: {ins:08x}  {desc}{highlight}")
            print()
