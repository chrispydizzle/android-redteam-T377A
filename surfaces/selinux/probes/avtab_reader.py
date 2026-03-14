#!/usr/bin/env python3
"""Android SELinux binary policy v30 avtab reader.
Reads the avtab starting at the known offset and handles xperms entries."""
import struct
import sys
from collections import defaultdict

POLICY = "/tmp/sepolicy"
AVTAB_OFFSET = 162696  # Found by searching for nel=29594

# Specifier flags
AVTAB_ALLOWED = 0x0001
AVTAB_AUDITALLOW = 0x0002
AVTAB_AUDITDENY = 0x0004
AVTAB_NEVERALLOW = 0x0080
AVTAB_TRANSITION = 0x0010
AVTAB_MEMBER = 0x0020
AVTAB_CHANGE = 0x0040
AVTAB_XPERMS_ALLOWED = 0x0100
AVTAB_XPERMS_AUDITALLOW = 0x0200
AVTAB_XPERMS_DONTAUDIT = 0x0400
AVTAB_ENABLED = 0x8000

SPEC_NAMES = {
    0x0001: "allow", 0x0002: "auditallow", 0x0004: "auditdeny",
    0x0010: "type_transition", 0x0020: "type_member", 0x0040: "type_change",
    0x0080: "neverallow",
    0x0100: "allowxperm", 0x0200: "auditallowxperm", 0x0400: "dontauditxperm",
}

XPERMS_MASK = AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT

def read_avtab(data, offset, type_names, class_names):
    """Read all avtab entries starting at offset."""
    pos = offset
    nel = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    print(f"Avtab nel={nel}, starting at offset {offset}")

    entries = []
    bad_entries = []
    spec_counts = defaultdict(int)

    for i in range(nel):
        epos = pos
        if pos + 8 > len(data):
            print(f"Truncated at entry {i}, pos={pos}")
            break

        src, tgt, cls, spec = struct.unpack_from('<HHHH', data, pos)
        pos += 8
        spec_clean = spec & ~AVTAB_ENABLED
        popcount = bin(spec_clean).count('1')

        if spec_clean & XPERMS_MASK:
            # xperms entry: 1 byte specified + 1 byte driver + 32 bytes perms
            if pos + 34 > len(data):
                print(f"Truncated xperms at entry {i}")
                break
            xspec = data[pos]
            driver = data[pos + 1]
            xperms = struct.unpack_from('<8I', data, pos + 2)
            pos += 34
            entries.append((src, tgt, cls, spec, 'xperms', (xspec, driver, xperms)))
            spec_counts[spec] += 1
        elif popcount == 1 and spec_clean in SPEC_NAMES:
            # Regular entry: 4 bytes data
            if pos + 4 > len(data):
                print(f"Truncated data at entry {i}")
                break
            val = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            entries.append((src, tgt, cls, spec, 'regular', val))
            spec_counts[spec] += 1
        elif popcount > 1:
            # Multi-specifier: this is the problematic case
            # Need to figure out data size
            bad_entries.append((i, epos, src, tgt, cls, spec))
            # Heuristic: if ANY xperms bit set, assume xperms size
            if spec_clean & XPERMS_MASK:
                pos += 34
            else:
                pos += 4
            spec_counts[spec] += 1
        else:
            # Zero or unknown specifier
            bad_entries.append((i, epos, src, tgt, cls, spec))
            pos += 4  # guess
            spec_counts[spec] += 1

    return entries, bad_entries, spec_counts, pos

def main():
    data = open(POLICY, 'rb').read()
    print(f"Policy size: {len(data)} bytes")

    # First, extract type and class names from the parsed data
    # We'll use the libsepol-parsed names from our sepol_dump output
    # For now, let's just read types and classes inline

    # Parse header
    magic = struct.unpack_from('<I', data, 0)[0]
    slen = struct.unpack_from('<I', data, 4)[0]
    pstr = data[8:8+slen].decode('ascii')
    off = 8 + slen
    version = struct.unpack_from('<I', data, off)[0]
    config = struct.unpack_from('<I', data, off+4)[0]
    sym_num = struct.unpack_from('<I', data, off+8)[0]
    ocon_num = struct.unpack_from('<I', data, off+12)[0]
    mls = config & 1
    off += 16

    print(f"Version: {version}, MLS: {mls}, Syms: {sym_num}")

    # Skip through symbol tables to build type/class name maps
    type_names = {}
    class_names = {}
    
    for s in range(sym_num):
        nprim = struct.unpack_from('<I', data, off)[0]
        nel = struct.unpack_from('<I', data, off+4)[0]
        off += 8
        
        if s == 0:  # commons
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                key = data[off:off+klen].decode('ascii', errors='replace'); off += klen
                val = struct.unpack_from('<I', data, off)[0]; off += 4
                cnp = struct.unpack_from('<I', data, off)[0]; off += 4
                cnel = struct.unpack_from('<I', data, off)[0]; off += 4
                for _ in range(cnel):
                    pklen = struct.unpack_from('<I', data, off)[0]; off += 4
                    off += pklen  # perm key
                    off += 4  # perm val
        elif s == 1:  # classes
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                key = data[off:off+klen].decode('ascii', errors='replace'); off += klen
                comklen = struct.unpack_from('<I', data, off)[0]; off += 4
                if comklen > 0: off += comklen
                val = struct.unpack_from('<I', data, off)[0]; off += 4
                class_names[val] = key
                # class perms
                cnp = struct.unpack_from('<I', data, off)[0]; off += 4
                cnel = struct.unpack_from('<I', data, off)[0]; off += 4
                for _ in range(cnel):
                    pklen = struct.unpack_from('<I', data, off)[0]; off += 4
                    off += pklen + 4
                # constraints
                ncons = struct.unpack_from('<I', data, off)[0]; off += 4
                for _ in range(ncons):
                    nexpr = struct.unpack_from('<I', data, off)[0]; off += 4
                    for _ in range(nexpr):
                        off += 12  # expr_type, attr, op
                        # ebitmap: names
                        ms = struct.unpack_from('<I', data, off)[0]; off += 4
                        hb = struct.unpack_from('<I', data, off)[0]; off += 4
                        cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                        off += cnt * 12  # startbit(4) + map(8)
                        # v25+ type_names: 2 ebitmaps
                        for _ in range(2):
                            ms2 = struct.unpack_from('<I', data, off)[0]; off += 4
                            hb2 = struct.unpack_from('<I', data, off)[0]; off += 4
                            cnt2 = struct.unpack_from('<I', data, off)[0]; off += 4
                            off += cnt2 * 12
                # validatetrans
                nvalcons = struct.unpack_from('<I', data, off)[0]; off += 4
                for _ in range(nvalcons):
                    nexpr = struct.unpack_from('<I', data, off)[0]; off += 4
                    for _ in range(nexpr):
                        off += 12
                        ms = struct.unpack_from('<I', data, off)[0]; off += 4
                        hb = struct.unpack_from('<I', data, off)[0]; off += 4
                        cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                        off += cnt * 12
                        for _ in range(2):
                            ms2 = struct.unpack_from('<I', data, off)[0]; off += 4
                            hb2 = struct.unpack_from('<I', data, off)[0]; off += 4
                            cnt2 = struct.unpack_from('<I', data, off)[0]; off += 4
                            off += cnt2 * 12
                # defaults (v27+)
                if version >= 27: off += 8  # default_user, default_role
                if version >= 28: off += 4  # default_range
                if version >= 30: off += 4  # default_type
        elif s == 2:  # roles
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                off += klen + 4  # key + value
                # dominates ebitmap
                ms = struct.unpack_from('<I', data, off)[0]; off += 4
                hb = struct.unpack_from('<I', data, off)[0]; off += 4
                cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                off += cnt * 12
                if version >= 26:  # types ebitmap
                    ms = struct.unpack_from('<I', data, off)[0]; off += 4
                    hb = struct.unpack_from('<I', data, off)[0]; off += 4
                    cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                    off += cnt * 12
        elif s == 3:  # types
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                key = data[off:off+klen].decode('ascii', errors='replace'); off += klen
                val = struct.unpack_from('<I', data, off)[0]; off += 4
                primary = struct.unpack_from('<I', data, off)[0]; off += 4
                if version >= 24:
                    flavor = struct.unpack_from('<I', data, off)[0]; off += 4
                    bounds = struct.unpack_from('<I', data, off)[0]; off += 4
                type_names[val] = key
        elif s == 4:  # users
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                off += klen + 4  # key + value
                # roles ebitmap
                ms = struct.unpack_from('<I', data, off)[0]; off += 4
                hb = struct.unpack_from('<I', data, off)[0]; off += 4
                cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                off += cnt * 12
                if mls:
                    # MLS range
                    items = struct.unpack_from('<I', data, off)[0]; off += 4
                    off += 4  # sens
                    ms = struct.unpack_from('<I', data, off)[0]; off += 4
                    hb = struct.unpack_from('<I', data, off)[0]; off += 4
                    cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                    off += cnt * 12
                    if items > 1:
                        off += 4  # sens
                        ms = struct.unpack_from('<I', data, off)[0]; off += 4
                        hb = struct.unpack_from('<I', data, off)[0]; off += 4
                        cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                        off += cnt * 12
                    # default level
                    off += 4  # sens
                    ms = struct.unpack_from('<I', data, off)[0]; off += 4
                    hb = struct.unpack_from('<I', data, off)[0]; off += 4
                    cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                    off += cnt * 12
        elif s == 5:  # booleans
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                off += klen + 8  # key + value + state
        elif s == 6:  # levels (MLS)
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                off += klen + 4  # key + isalias
                # level
                off += 4  # sens
                ms = struct.unpack_from('<I', data, off)[0]; off += 4
                hb = struct.unpack_from('<I', data, off)[0]; off += 4
                cnt = struct.unpack_from('<I', data, off)[0]; off += 4
                off += cnt * 12
        elif s == 7:  # categories (MLS)
            for _ in range(nel):
                klen = struct.unpack_from('<I', data, off)[0]; off += 4
                off += klen + 8  # key + value + isalias

    print(f"After symbols: offset {off} (0x{off:x})")
    print(f"Types: {len(type_names)}, Classes: {len(class_names)}")

    # Verify: the avtab should start right after the symbols
    # Check if our computed offset matches the known avtab offset
    if off == AVTAB_OFFSET:
        print("OFFSET MATCH! Symbols end exactly at avtab start.")
    else:
        print(f"OFFSET MISMATCH: computed {off}, expected {AVTAB_OFFSET}")
        print(f"Difference: {off - AVTAB_OFFSET}")
        # Use the computed offset
    
    # Read avtab
    entries, bad_entries, spec_counts, end_pos = read_avtab(data, off, type_names, class_names)

    print(f"\n=== AVTAB RESULTS ===")
    print(f"Total entries parsed: {len(entries)}")
    print(f"Bad entries: {len(bad_entries)}")
    print(f"\nSpecifier distribution:")
    for spec, count in sorted(spec_counts.items()):
        name = SPEC_NAMES.get(spec & ~AVTAB_ENABLED, f"0x{spec:04x}")
        print(f"  {name} (0x{spec:04x}): {count}")

    if bad_entries:
        print(f"\nFirst 10 bad entries:")
        for idx, epos, src, tgt, cls, spec in bad_entries[:10]:
            sn = type_names.get(src, f"type_{src}")
            tn = type_names.get(tgt, f"type_{tgt}")
            cn = class_names.get(cls, f"class_{cls}")
            print(f"  [{idx}] {sn} -> {tn} : {cn} spec=0x{spec:04x} (popcount={bin(spec).count('1')})")

    # ====== SECURITY ANALYSIS ======
    print("\n" + "="*60)
    print("SECURITY ANALYSIS")
    print("="*60)

    # Build lookup by source type
    rules_by_src = defaultdict(list)
    transitions = []
    for e in entries:
        src, tgt, cls, spec, kind, val = e
        rules_by_src[src].append(e)
        spec_clean = spec & ~AVTAB_ENABLED
        if spec_clean == AVTAB_TRANSITION:
            transitions.append(e)

    # Find key type IDs
    name_to_id = {v: k for k, v in type_names.items()}
    
    key_types = ['shell', 'untrusted_app', 'bluetooth', 'diagexe', 
                 'rd_shell', 'rd_shell_exec', 'su', 'su_exec', 'kernel',
                 'init', 'system_server', 'recovery', 'platform_app',
                 'sec_untrusted_app', 'system_app']
    
    print("\nKey type IDs:")
    for t in key_types:
        tid = name_to_id.get(t, None)
        print(f"  {t}: {tid}")

    # 1. Transitions FROM shell
    shell_id = name_to_id.get('shell')
    if shell_id:
        print(f"\n--- TRANSITIONS FROM shell (ID={shell_id}) ---")
        count = 0
        for e in entries:
            src, tgt, cls, spec, kind, val = e
            if src == shell_id and (spec & ~AVTAB_ENABLED) == AVTAB_TRANSITION:
                tn = type_names.get(tgt, f"type_{tgt}")
                cn = class_names.get(cls, f"class_{cls}")
                dname = type_names.get(val, f"type_{val}") if kind == 'regular' else "?"
                print(f"  type_transition shell {tn}:{cn} {dname};")
                count += 1
        if count == 0: print("  (none)")

    # 2. Transitions FROM untrusted_app
    ua_id = name_to_id.get('untrusted_app')
    if ua_id:
        print(f"\n--- TRANSITIONS FROM untrusted_app (ID={ua_id}) ---")
        count = 0
        for e in entries:
            src, tgt, cls, spec, kind, val = e
            if src == ua_id and (spec & ~AVTAB_ENABLED) == AVTAB_TRANSITION:
                tn = type_names.get(tgt, f"type_{tgt}")
                cn = class_names.get(cls, f"class_{cls}")
                dname = type_names.get(val, f"type_{val}") if kind == 'regular' else "?"
                print(f"  type_transition untrusted_app {tn}:{cn} {dname};")
                count += 1
        if count == 0: print("  (none)")

    # 3. ALL type_transitions
    print(f"\n--- ALL TYPE TRANSITIONS ({len(transitions)} total) ---")
    for e in transitions[:100]:
        src, tgt, cls, spec, kind, val = e
        sn = type_names.get(src, f"type_{src}")
        tn = type_names.get(tgt, f"type_{tgt}")
        cn = class_names.get(cls, f"class_{cls}")
        dname = type_names.get(val, f"type_{val}") if kind == 'regular' else "?"
        print(f"  type_transition {sn} {tn}:{cn} {dname};")
    if len(transitions) > 100:
        print(f"  ... and {len(transitions) - 100} more")

    # 4. ALLOW rules for shell (execute perms)
    if shell_id:
        print(f"\n--- ALLOW FROM shell (execute-related) ---")
        for e in entries:
            src, tgt, cls, spec, kind, val = e
            if src == shell_id and (spec & ~AVTAB_ENABLED) == AVTAB_ALLOWED and kind == 'regular':
                tn = type_names.get(tgt, f"type_{tgt}")
                cn = class_names.get(cls, f"class_{cls}")
                print(f"  allow shell {tn}:{cn} 0x{val:08x};")

    # 5. Rules targeting rd_shell_exec, su_exec
    for target_name in ['rd_shell_exec', 'su_exec']:
        tid = name_to_id.get(target_name)
        if tid:
            print(f"\n--- ALL RULES WITH TARGET {target_name} (ID={tid}) ---")
            for e in entries:
                src, tgt, cls, spec, kind, val = e
                if tgt == tid:
                    sn = type_names.get(src, f"type_{src}")
                    cn = class_names.get(cls, f"class_{cls}")
                    spec_name = SPEC_NAMES.get(spec & ~AVTAB_ENABLED, f"0x{spec:04x}")
                    if kind == 'regular':
                        print(f"  {spec_name} {sn} {target_name}:{cn} 0x{val:08x};")
                    else:
                        print(f"  {spec_name} {sn} {target_name}:{cn} [xperms];")

    # 6. Transitions TO interesting domains
    for target_name in ['rd_shell', 'su', 'kernel', 'init', 'recovery', 'system_server']:
        tid = name_to_id.get(target_name)
        if tid:
            print(f"\n--- TRANSITIONS TO {target_name} (default_type={tid}) ---")
            count = 0
            for e in transitions:
                src, tgt, cls, spec, kind, val = e
                if kind == 'regular' and val == tid:
                    sn = type_names.get(src, f"type_{src}")
                    tn = type_names.get(tgt, f"type_{tgt}")
                    cn = class_names.get(cls, f"class_{cls}")
                    print(f"  type_transition {sn} {tn}:{cn} {target_name};")
                    count += 1
            if count == 0: print("  (none)")

    # 7. diagexe rules
    diag_id = name_to_id.get('diagexe')
    if diag_id:
        print(f"\n--- ALL ALLOW FROM diagexe ---")
        for e in entries:
            src, tgt, cls, spec, kind, val = e
            if src == diag_id and (spec & ~AVTAB_ENABLED) == AVTAB_ALLOWED:
                tn = type_names.get(tgt, f"type_{tgt}")
                cn = class_names.get(cls, f"class_{cls}")
                if kind == 'regular':
                    print(f"  allow diagexe {tn}:{cn} 0x{val:08x};")
                else:
                    print(f"  allowxperm diagexe {tn}:{cn} [xperms];")

    # 8. bluetooth rules  
    bt_id = name_to_id.get('bluetooth')
    if bt_id:
        print(f"\n--- KEY BLUETOOTH RULES (capability, socket, chr_file) ---")
        for e in entries:
            src, tgt, cls, spec, kind, val = e
            if src == bt_id and (spec & ~AVTAB_ENABLED) == AVTAB_ALLOWED:
                cn = class_names.get(cls, f"class_{cls}")
                if any(x in cn for x in ['capability', 'socket', 'chr_file', 'rawip',
                                          'netlink', 'packet', 'tcp', 'udp']):
                    tn = type_names.get(tgt, f"type_{tgt}")
                    if kind == 'regular':
                        print(f"  allow bluetooth {tn}:{cn} 0x{val:08x};")

    print("\n=== ANALYSIS COMPLETE ===")

if __name__ == '__main__':
    main()
