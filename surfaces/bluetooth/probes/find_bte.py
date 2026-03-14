import struct
data = open('/tmp/vmlinux','rb').read()
base = 0xC0008000
# Search for MOVW with immediate 0x6208 (low 16 bits of BINDER_THREAD_EXIT)
for i in range(0, len(data)-4, 4):
    insn = struct.unpack('<I', data[i:i+4])[0]
    # MOVW encoding: 0xe30X_XXXX where imm16 = ((insn>>4)&0xF000) | (insn&0xFFF)
    if (insn & 0xFFF00000) == 0xE3000000:
        imm = ((insn>>4) & 0xF000) | (insn & 0xFFF)
        if imm == 0x6208:
            addr = base + i
            # Check next instruction for MOVT with 0x4004
            if i+4 < len(data):
                insn2 = struct.unpack('<I', data[i+4:i+8])[0]
                if (insn2 & 0xFFF00000) == 0xE3400000:
                    imm2 = ((insn2>>4) & 0xF000) | (insn2 & 0xFFF)
                    if imm2 == 0x4004:
                        print(f'BINDER_THREAD_EXIT ref at 0x{addr:08x}')
