#!/usr/bin/env python3
"""Android SELinux avtab reader v2 - uses pre-exported type/class names
and jumps straight to the known avtab offset."""
import struct
import sys
from collections import defaultdict

POLICY = "/tmp/sepolicy"
AVTAB_OFFSET = 162696  # Verified by searching for nel=29594

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
XPERMS_MASK = 0x0700

SPEC_NAMES = {
    0x0001: "allow", 0x0002: "auditallow", 0x0004: "auditdeny",
    0x0010: "type_transition", 0x0020: "type_member", 0x0040: "type_change",
    0x0080: "neverallow",
    0x0100: "allowxperm", 0x0200: "auditallowxperm", 0x0400: "dontauditxperm",
}

def load_names(path):
    """Load type or class names from tab-separated file."""
    names = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split('\t')
            names[int(parts[0])] = parts[1]
    return names

def main():
    type_names = load_names("/tmp/type_names.txt")
    class_names = load_names("/tmp/class_names.txt")
    name_to_id = {v: k for k, v in type_names.items()}
    
    data = open(POLICY, 'rb').read()
    
    # Read avtab
    pos = AVTAB_OFFSET
    nel = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    print(f"Avtab: nel={nel}, offset={AVTAB_OFFSET}")

    entries = []
    spec_counts = defaultdict(int)
    bad_count = 0

    for i in range(nel):
        if pos + 8 > len(data):
            print(f"TRUNCATED at entry {i}, pos={pos}")
            break

        src, tgt, cls, spec = struct.unpack_from('<HHHH', data, pos)
        pos += 8
        spec_clean = spec & ~AVTAB_ENABLED

        if spec_clean & XPERMS_MASK:
            if pos + 34 > len(data):
                print(f"TRUNCATED xperms at entry {i}")
                break
            xspec = data[pos]
            driver = data[pos + 1]
            pos += 34
            entries.append((src, tgt, cls, spec_clean, None))
            spec_counts[spec_clean] += 1
        elif spec_clean in SPEC_NAMES and bin(spec_clean).count('1') == 1:
            if pos + 4 > len(data):
                print(f"TRUNCATED data at entry {i}")
                break
            val = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            entries.append((src, tgt, cls, spec_clean, val))
            spec_counts[spec_clean] += 1
        else:
            # Unknown specifier - try to figure out data size
            if i < 3 or bad_count < 5:
                print(f"BAD entry {i}: src={src} tgt={tgt} cls={cls} spec=0x{spec:04x}")
            if spec_clean & XPERMS_MASK:
                pos += 34
            else:
                pos += 4
            bad_count += 1
            spec_counts[spec_clean] += 1

    print(f"\nParsed: {len(entries)} good, {bad_count} bad")
    print(f"End position: {pos}, remaining: {len(data) - pos}")
    print(f"\nSpecifier distribution:")
    for spec, count in sorted(spec_counts.items()):
        name = SPEC_NAMES.get(spec, f"0x{spec:04x}")
        print(f"  {name}: {count}")

    # ============ SECURITY ANALYSIS ============
    print("\n" + "="*70)
    print("                     SECURITY ANALYSIS")
    print("="*70)

    # Index by source
    allow_by_src = defaultdict(list)
    transitions = []
    for e in entries:
        src, tgt, cls, spec, val = e
        if spec == AVTAB_ALLOWED:
            allow_by_src[src].append(e)
        elif spec == AVTAB_TRANSITION:
            transitions.append(e)

    def tn(v): return type_names.get(v, f"type_{v}")
    def cn(v): return class_names.get(v, f"class_{v}")

    # 1. PERMISSIVE CHECK (already done by libsepol - none found)
    print("\n[1] PERMISSIVE TYPES: None (confirmed)")

    # 2. DOMAIN TRANSITIONS FROM SHELL
    shell_id = name_to_id.get('shell')
    print(f"\n[2] DOMAIN TRANSITIONS FROM shell (ID={shell_id})")
    shell_trans = [e for e in transitions if e[0] == shell_id]
    if shell_trans:
        for e in shell_trans:
            print(f"  type_transition shell {tn(e[1])}:{cn(e[2])} {tn(e[4])};")
    else:
        print("  *** NONE - shell cannot transition to ANY domain ***")

    # 3. DOMAIN TRANSITIONS FROM untrusted_app
    ua_id = name_to_id.get('untrusted_app')
    print(f"\n[3] DOMAIN TRANSITIONS FROM untrusted_app (ID={ua_id})")
    ua_trans = [e for e in transitions if e[0] == ua_id]
    if ua_trans:
        for e in ua_trans:
            print(f"  type_transition untrusted_app {tn(e[1])}:{cn(e[2])} {tn(e[4])};")
    else:
        print("  *** NONE ***")

    # 4. ALL TYPE TRANSITIONS (look for anything interesting)
    print(f"\n[4] ALL TYPE TRANSITIONS ({len(transitions)} total)")
    # Group by default (destination) type
    trans_by_dest = defaultdict(list)
    for e in transitions:
        trans_by_dest[e[4]].append(e)
    
    # Show transitions to interesting destinations
    interesting = ['rd_shell', 'su', 'kernel', 'init', 'recovery', 
                   'system_server', 'shell', 'root']
    for dest_name in interesting:
        did = name_to_id.get(dest_name)
        if did and did in trans_by_dest:
            print(f"\n  Transitions to {dest_name}:")
            for e in trans_by_dest[did]:
                print(f"    type_transition {tn(e[0])} {tn(e[1])}:{cn(e[2])} {dest_name};")

    # Show ALL transitions (grouped)
    print(f"\n  All transitions by destination domain:")
    for did, elist in sorted(trans_by_dest.items(), key=lambda x: len(x[1]), reverse=True):
        dest = tn(did)
        sources = set(tn(e[0]) for e in elist)
        print(f"    -> {dest} ({len(elist)} rules, from: {', '.join(sorted(sources)[:5])}{'...' if len(sources) > 5 else ''})")

    # 5. rd_shell_exec RULES
    rdsh_id = name_to_id.get('rd_shell_exec')
    rdsh_domain_id = name_to_id.get('rd_shell')
    print(f"\n[5] rd_shell_exec ANALYSIS")
    print(f"  rd_shell_exec ID: {rdsh_id}")
    print(f"  rd_shell domain ID: {rdsh_domain_id}")
    if rdsh_id:
        rules = [e for e in entries if e[1] == rdsh_id]
        if rules:
            for e in rules:
                spec_name = SPEC_NAMES.get(e[3], f"0x{e[3]:04x}")
                print(f"  {spec_name} {tn(e[0])} rd_shell_exec:{cn(e[2])} 0x{e[4]:08x};")
        else:
            print("  *** NO RULES reference rd_shell_exec at all ***")

    # 6. su_exec RULES
    su_id = name_to_id.get('su_exec')
    su_domain_id = name_to_id.get('su')
    print(f"\n[6] su_exec ANALYSIS")
    print(f"  su_exec ID: {su_id}")
    print(f"  su domain ID: {su_domain_id}")
    if su_id:
        rules = [e for e in entries if e[1] == su_id]
        if rules:
            for e in rules:
                spec_name = SPEC_NAMES.get(e[3], f"0x{e[3]:04x}")
                print(f"  {spec_name} {tn(e[0])} su_exec:{cn(e[2])} 0x{e[4]:08x};")
        else:
            print("  *** NO RULES reference su_exec at all ***")

    # 7. SHELL ALLOW RULES
    print(f"\n[7] ALL ALLOW RULES FROM shell ({len(allow_by_src.get(shell_id, []))} rules)")
    if shell_id in allow_by_src:
        for e in allow_by_src[shell_id]:
            print(f"  allow shell {tn(e[1])}:{cn(e[2])} 0x{e[4]:08x};")

    # 8. DIAGEXE ALLOW RULES
    diag_id = name_to_id.get('diagexe')
    print(f"\n[8] ALL ALLOW RULES FROM diagexe ({len(allow_by_src.get(diag_id, []))} rules)")
    if diag_id in allow_by_src:
        for e in allow_by_src[diag_id]:
            print(f"  allow diagexe {tn(e[1])}:{cn(e[2])} 0x{e[4]:08x};")

    # 9. BLUETOOTH ALLOW RULES
    bt_id = name_to_id.get('bluetooth')
    print(f"\n[9] BLUETOOTH ALLOW RULES ({len(allow_by_src.get(bt_id, []))} rules)")
    if bt_id in allow_by_src:
        for e in allow_by_src[bt_id]:
            c = cn(e[2])
            if any(x in c for x in ['capability', 'socket', 'rawip', 'chr_file', 
                                      'netlink', 'packet', 'tcp', 'udp', 'process']):
                print(f"  allow bluetooth {tn(e[1])}:{c} 0x{e[4]:08x};")

    # 10. ENTRYPOINT ANALYSIS
    print(f"\n[10] DOMAIN ENTRYPOINTS (allow X Y:file entrypoint)")
    # file class is typically class 6 or we search for "file" in class_names
    file_cls = None
    for cid, cname in class_names.items():
        if cname == 'file':
            file_cls = cid
            break
    
    if file_cls:
        # entrypoint is usually perm bit 9 (value 0x100) but varies
        # Let's just look for all allow rules on file class with entrypoint-like perms
        for e in entries:
            if e[3] == AVTAB_ALLOWED and e[2] == file_cls and e[4] is not None:
                # Check if entrypoint perm is set (bit varies by policy)
                # In AOSP, entrypoint for "file" class is usually perm 17 (0x10000)
                if e[4] & 0x10000:  # entrypoint
                    print(f"  {tn(e[0])} <- {tn(e[1])} (perms=0x{e[4]:08x})")

    # 11. SAMSUNG-SPECIFIC DOMAIN COMPARISON
    print(f"\n[11] SAMSUNG DOMAIN PRIVILEGE COMPARISON")
    samsung_domains = ['sec_untrusted_app', 'filtered_untrusted_app', 'carrier_app',
                       'platform_app', 'system_app', 'knox_system_app', 
                       'sysaccess_platform_app']
    for domain in samsung_domains:
        did = name_to_id.get(domain)
        if did:
            rules = allow_by_src.get(did, [])
            cap_rules = [e for e in rules if 'capability' in cn(e[2])]
            print(f"  {domain}: {len(rules)} allow rules, {len(cap_rules)} capability rules")
            for e in cap_rules:
                print(f"    {cn(e[2])}: 0x{e[4]:08x}")

    # 12. WHO CAN TRANSITION (any domain with process:transition perms)
    process_cls = None
    for cid, cname in class_names.items():
        if cname == 'process':
            process_cls = cid
            break
    
    if process_cls:
        print(f"\n[12] PROCESS TRANSITION PERMISSIONS (allow X Y:process transition)")
        # transition perm for process class is usually perm 1 (0x0001) 
        for e in entries:
            if (e[3] == AVTAB_ALLOWED and e[2] == process_cls and 
                e[4] is not None and e[4] & 0x0001):  # transition perm
                src_name = tn(e[0])
                tgt_name = tn(e[1])
                # Only show ones where source is our accessible domain
                if src_name in ('shell', 'untrusted_app', 'bluetooth', 'diagexe',
                                'sec_untrusted_app', 'platform_app'):
                    print(f"  allow {src_name} {tgt_name}:process {{transition}} (0x{e[4]:08x})")

    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)

if __name__ == '__main__':
    main()
