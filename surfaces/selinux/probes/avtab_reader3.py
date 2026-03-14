#!/usr/bin/env python3
"""Android SELinux policy analyzer v3 - handles xperms by scanning.
Reads regular (12-byte) entries from known-good regions and scans
for valid entries in the xperms region."""
import struct
import sys
from collections import defaultdict

POLICY = "/tmp/sepolicy"
AVTAB_OFFSET = 162696

AVTAB_ALLOWED = 0x0001
AVTAB_AUDITALLOW = 0x0002
AVTAB_AUDITDENY = 0x0004
AVTAB_TRANSITION = 0x0010
AVTAB_MEMBER = 0x0020
AVTAB_CHANGE = 0x0040
AVTAB_NEVERALLOW = 0x0080
AVTAB_XPERMS_ALLOWED = 0x0100
AVTAB_XPERMS_AUDITALLOW = 0x0200
AVTAB_XPERMS_DONTAUDIT = 0x0400

VALID_SPECS = {1,2,4,0x10,0x20,0x40,0x80,0x100,0x200,0x400}

SPEC_NAMES = {
    0x0001: "allow", 0x0002: "auditallow", 0x0004: "auditdeny",
    0x0010: "type_transition", 0x0020: "type_member", 0x0040: "type_change",
    0x0080: "neverallow",
    0x0100: "allowxperm", 0x0200: "auditallowxperm", 0x0400: "dontauditxperm",
}

def load_names(path):
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
    ntypes = max(type_names.keys())
    nclasses = max(class_names.keys())

    data = open(POLICY, 'rb').read()
    pos = AVTAB_OFFSET
    nel = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    print(f"Avtab: nel={nel}")

    # Strategy: Read entries in two passes
    # Pass 1: Read 12-byte entries from start until we hit xperms (entry 4822)
    # Pass 2: Scan for the end of xperms section, then read remaining 12-byte entries
    
    entries = []
    
    # Pass 1: entries 0-4821 (all regular, 12 bytes)
    for i in range(4822):
        src, tgt, cls, spec = struct.unpack_from('<HHHH', data, pos)
        val = struct.unpack_from('<I', data, pos + 8)[0]
        pos += 12
        entries.append((src, tgt, cls, spec & 0x7FFF, val))

    print(f"Pass 1: read {len(entries)} regular entries (0-4821)")
    xperms_start = pos  # 220564

    # Entry 4822 is the first xperms entry (spec=0x0100)
    # Skip it (42 bytes) and scan for where regular entries resume
    # Try to find runs of consecutive valid entries at every 2-byte offset
    
    # Scan from xperms_start to find where valid regular entries resume
    scan_start = xperms_start
    scan_end = min(len(data) - 60, AVTAB_OFFSET + 4 + nel * 42)  # upper bound
    
    resume_offset = None
    for off in range(scan_start, scan_end, 2):
        valid = 0
        p = off
        for _ in range(10):  # need 10 consecutive valid entries
            if p + 12 > len(data): break
            s, t, c, sp = struct.unpack_from('<HHHH', data, p)
            sc = sp & 0x7FFF
            if (1 <= s <= ntypes and 1 <= t <= ntypes and 
                1 <= c <= nclasses and sc in VALID_SPECS and 
                bin(sc).count('1') == 1 and not (sc & 0x700)):
                valid += 1
                p += 12
            else:
                break
        if valid >= 10:
            resume_offset = off
            break

    if resume_offset:
        print(f"Xperms section: {xperms_start} to {resume_offset} ({resume_offset - xperms_start} bytes)")
        
        # Count how many entries we're skipping
        # The xperms section has entries of size 42 each
        xperms_bytes = resume_offset - xperms_start
        approx_xperms = xperms_bytes // 42
        print(f"Approx {approx_xperms} xperms entries ({xperms_bytes} bytes)")
        
        # Pass 2: read remaining regular entries
        pos = resume_offset
        pass2_count = 0
        while True:
            if pos + 12 > len(data): break
            src, tgt, cls, spec = struct.unpack_from('<HHHH', data, pos)
            val = struct.unpack_from('<I', data, pos + 8)[0]
            sc = spec & 0x7FFF
            
            if (1 <= src <= ntypes and 1 <= tgt <= ntypes and 
                1 <= cls <= nclasses and sc in VALID_SPECS and 
                bin(sc).count('1') == 1):
                if sc & 0x700:
                    # Another xperms entry — skip it
                    pos += 42
                    continue
                entries.append((src, tgt, cls, sc, val))
                pos += 12
                pass2_count += 1
            else:
                # End of avtab or another xperms section
                # Try skipping 42 bytes (xperms) and check again
                next_pos = pos + 42
                if next_pos + 12 <= len(data):
                    s2, t2, c2, sp2 = struct.unpack_from('<HHHH', data, next_pos)
                    sc2 = sp2 & 0x7FFF
                    if (1 <= s2 <= ntypes and 1 <= t2 <= ntypes and 
                        1 <= c2 <= nclasses and sc2 in VALID_SPECS):
                        pos = next_pos
                        continue
                break

        print(f"Pass 2: read {pass2_count} more regular entries")
    
    total = len(entries)
    print(f"\nTotal regular entries recovered: {total}")

    # ============ SECURITY ANALYSIS ============
    def tn(v): return type_names.get(v, f"type_{v}")
    def cn(v): return class_names.get(v, f"class_{v}")

    allow_by_src = defaultdict(list)
    transitions = []
    all_allow = []
    
    for e in entries:
        src, tgt, cls, spec, val = e
        if spec == AVTAB_ALLOWED:
            allow_by_src[src].append(e)
            all_allow.append(e)
        elif spec == AVTAB_TRANSITION:
            transitions.append(e)

    print(f"\nAllow rules: {len(all_allow)}")
    print(f"Type transitions: {len(transitions)}")
    print(f"Other: {total - len(all_allow) - len(transitions)}")

    # ===== KEY ANALYSIS =====
    
    # 1. PERMISSIVE
    print("\n" + "="*70)
    print("[1] PERMISSIVE TYPES: None (confirmed by libsepol)")
    
    # 2. TRANSITIONS FROM SHELL
    shell_id = name_to_id.get('shell')
    print(f"\n[2] TRANSITIONS FROM shell (ID={shell_id})")
    st = [e for e in transitions if e[0] == shell_id]
    for e in st:
        print(f"  type_transition shell {tn(e[1])}:{cn(e[2])} {tn(e[4])};")
    if not st: print("  *** NONE ***")

    # 3. TRANSITIONS FROM untrusted_app
    ua_id = name_to_id.get('untrusted_app')
    print(f"\n[3] TRANSITIONS FROM untrusted_app (ID={ua_id})")
    ut = [e for e in transitions if e[0] == ua_id]
    for e in ut:
        print(f"  type_transition untrusted_app {tn(e[1])}:{cn(e[2])} {tn(e[4])};")
    if not ut: print("  *** NONE ***")

    # 4. ALL TYPE TRANSITIONS
    print(f"\n[4] ALL TYPE TRANSITIONS ({len(transitions)} total)")
    trans_by_dest = defaultdict(list)
    for e in transitions:
        trans_by_dest[e[4]].append(e)
    for did, elist in sorted(trans_by_dest.items(), key=lambda x: len(x[1]), reverse=True):
        sources = sorted(set(tn(e[0]) for e in elist))
        print(f"  -> {tn(did)} ({len(elist)} rules from: {', '.join(sources[:8])}{'...' if len(sources) > 8 else ''})")

    # 5. TRANSITIONS TO INTERESTING DOMAINS
    print(f"\n[5] TRANSITIONS TO CRITICAL DOMAINS")
    for target in ['kernel', 'init', 'recovery', 'system_server', 'su', 'rd_shell']:
        tid = name_to_id.get(target)
        if tid and tid in trans_by_dest:
            print(f"\n  -> {target}:")
            for e in trans_by_dest[tid]:
                print(f"    type_transition {tn(e[0])} {tn(e[1])}:{cn(e[2])} {target};")
        elif tid:
            print(f"  -> {target}: (none)")
        else:
            print(f"  -> {target}: TYPE NOT FOUND IN POLICY")

    # 6. rd_shell_exec and su_exec analysis
    for target_type in ['rd_shell_exec', 'su_exec']:
        tid = name_to_id.get(target_type)
        print(f"\n[6] ALL RULES TARGETING {target_type} (ID={tid})")
        if tid:
            rules = [e for e in entries if e[1] == tid]
            for e in rules:
                sn = SPEC_NAMES.get(e[3], f"0x{e[3]:04x}")
                print(f"  {sn} {tn(e[0])} {target_type}:{cn(e[2])} 0x{e[4]:08x};")
            if not rules: print("  *** NO RULES ***")

    # 7. SHELL ALLOW RULES (full dump)
    print(f"\n[7] ALL ALLOW FROM shell ({len(allow_by_src.get(shell_id, []))} rules)")
    if shell_id in allow_by_src:
        for e in sorted(allow_by_src[shell_id], key=lambda x: (x[2], x[1])):
            print(f"  allow shell {tn(e[1])}:{cn(e[2])} 0x{e[4]:08x};")

    # 8. DIAGEXE RULES
    diag_id = name_to_id.get('diagexe')
    print(f"\n[8] ALL ALLOW FROM diagexe ({len(allow_by_src.get(diag_id, []))} rules)")
    if diag_id in allow_by_src:
        for e in sorted(allow_by_src[diag_id], key=lambda x: (x[2], x[1])):
            print(f"  allow diagexe {tn(e[1])}:{cn(e[2])} 0x{e[4]:08x};")

    # 9. BLUETOOTH RULES (capability, socket, device access)
    bt_id = name_to_id.get('bluetooth')
    print(f"\n[9] BLUETOOTH KEY RULES ({len(allow_by_src.get(bt_id, []))} total)")
    if bt_id in allow_by_src:
        for e in sorted(allow_by_src[bt_id], key=lambda x: (x[2], x[1])):
            c = cn(e[2])
            if any(x in c for x in ['capability', 'socket', 'rawip', 'chr_file', 
                                      'netlink', 'packet', 'tcp', 'udp', 'process',
                                      'binder', 'unix']):
                print(f"  allow bluetooth {tn(e[1])}:{c} 0x{e[4]:08x};")

    # 10. ENTRYPOINT ANALYSIS
    # Find all domains that have entrypoint permissions on file types
    print(f"\n[10] DOMAIN ENTRYPOINTS")
    # file class
    file_cls = None
    for cid, cname in class_names.items():
        if cname == 'file': file_cls = cid; break
    if file_cls:
        for e in all_allow:
            if e[2] == file_cls and e[4] & 0x10000:  # entrypoint bit
                print(f"  {tn(e[0])} <- {tn(e[1])}")

    # 11. PROCESS TRANSITION PERMISSIONS
    process_cls = None
    for cid, cname in class_names.items():
        if cname == 'process': process_cls = cid; break
    
    if process_cls:
        print(f"\n[11] PROCESS TRANSITION PERMISSIONS (from our domains)")
        our_domains = set()
        for d in ['shell', 'untrusted_app', 'bluetooth', 'diagexe',
                   'sec_untrusted_app', 'platform_app', 'system_app',
                   'carrier_app', 'filtered_untrusted_app']:
            did = name_to_id.get(d)
            if did: our_domains.add(did)
        
        for e in all_allow:
            if e[2] == process_cls and e[0] in our_domains and e[4] & 0x0001:
                print(f"  allow {tn(e[0])} {tn(e[1])}:process 0x{e[4]:08x}")

    # 12. SAMSUNG DOMAIN COMPARISON
    print(f"\n[12] SAMSUNG DOMAIN PRIVILEGE COMPARISON")
    samsung_domains = ['untrusted_app', 'sec_untrusted_app', 'filtered_untrusted_app',
                       'carrier_app', 'platform_app', 'system_app', 'knox_system_app',
                       'sysaccess_platform_app', 'shell']
    for domain in samsung_domains:
        did = name_to_id.get(domain)
        if did:
            rules = allow_by_src.get(did, [])
            # Count by class
            cap_rules = [e for e in rules if 'capability' in cn(e[2])]
            file_rules = [e for e in rules if cn(e[2]) == 'file']
            sock_rules = [e for e in rules if 'socket' in cn(e[2])]
            binder_rules = [e for e in rules if 'binder' in cn(e[2])]
            print(f"  {domain:30s}: {len(rules):4d} allow, {len(cap_rules):2d} capability, {len(file_rules):3d} file, {len(sock_rules):3d} socket")
            for e in cap_rules:
                print(f"    {cn(e[2])}: 0x{e[4]:08x}")
        else:
            print(f"  {domain:30s}: NOT FOUND")

    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)

if __name__ == '__main__':
    main()
