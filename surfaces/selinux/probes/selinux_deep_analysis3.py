#!/usr/bin/env python3
"""Pure Python Android SELinux binary policy v30 parser.
Correctly handles v20+ format where sym table sizes are interleaved with data."""

import struct
import sys

POLICY_PATH = "/tmp/sepolicy"

def u32(data, off):
    return struct.unpack_from('<I', data, off)[0], off + 4

def read_str(data, off):
    slen, off = u32(data, off)
    s = data[off:off+slen]
    if s and s[-1] == 0:
        s = s[:-1]
    return s.decode('ascii', errors='replace'), off + slen

def read_ebitmap(data, off):
    """Read an ebitmap. Returns (set_of_bits, new_offset)."""
    mapsize, off = u32(data, off)
    highbit, off = u32(data, off)
    count, off = u32(data, off)
    bits = set()
    for _ in range(count):
        startbit, off = u32(data, off)
        lo = struct.unpack_from('<I', data, off)[0]; off += 4
        hi = struct.unpack_from('<I', data, off)[0]; off += 4
        mapval = lo | (hi << 32)
        for b in range(64):
            if mapval & (1 << b):
                bits.add(startbit + b)
    return bits, off

def skip_mls_level(data, off):
    sens, off = u32(data, off)
    _, off = read_ebitmap(data, off)
    return off

def skip_mls_range(data, off):
    off = skip_mls_level(data, off)
    off = skip_mls_level(data, off)
    return off

class PolicyDB:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        self.types = {}
        self.type_flavors = {}  # id -> 0=type, 1=attrib, 2=alias
        self.classes = {}
        self.class_perms = {}
        self.commons = {}
        self.allows = []
        self.transitions = []
        self.roles = {}
        self._parse()

    def _parse(self):
        d = self.data
        off = 0

        # Header
        magic, off = u32(d, off)
        assert magic == 0xf97cff8c, f"Bad magic: 0x{magic:08x}"
        slen, off = u32(d, off)
        ptype = d[off:off+slen].rstrip(b'\x00').decode(); off += slen
        self.version, off = u32(d, off)
        config, off = u32(d, off)
        self.mls = bool(config & 1)
        sym_num, off = u32(d, off)
        ocon_num, off = u32(d, off)
        print(f"Policy: '{ptype}' v{self.version}, MLS={self.mls}, syms={sym_num}, ocons={ocon_num}")

        # For v20+, each sym table: read (nprim, nel), then parse nel entries
        parsers = [
            self._parse_commons, self._parse_classes, self._parse_roles,
            self._parse_types, self._parse_users, self._parse_bools,
            self._parse_levels, self._parse_cats
        ]
        for i in range(sym_num):
            nprim, off = u32(d, off)
            nel, off = u32(d, off)
            if i < len(parsers):
                off = parsers[i](d, off, nel, nprim)
            else:
                print(f"  [sym {i}] nprim={nprim} nel={nel} (skipped)")

        # Access vector table
        off = self._parse_avtab(d, off)

        # Conditional list
        off = self._parse_cond_list(d, off)

        # Role transitions
        off = self._parse_role_trans(d, off)

        # Role allows
        off = self._parse_role_allow(d, off)

        # Filename transitions (v25+)
        if self.version >= 25:
            off = self._parse_filename_trans(d, off)

        # After this: ocontexts, genfs, range_trans, then type_attr_map, then permissive bitmap

        # Skip ocontexts
        for i in range(ocon_num):
            off = self._skip_ocontext(d, off, i)

        # genfs
        off = self._skip_genfs(d, off)

        # MLS range transitions
        if self.mls:
            off = self._skip_range_trans(d, off)

        # Type attribute map (v24+) — for each type, which attributes it has
        if self.version >= 24:
            off = self._parse_type_attr_map(d, off)

        # Permissive types bitmap (v23+)
        if self.version >= 23:
            off = self._parse_permissive_map(d, off)

        n_types = sum(1 for v in self.type_flavors.values() if v == 0)
        n_attrs = sum(1 for v in self.type_flavors.values() if v == 1)
        print(f"\nParsed: {n_types} types, {n_attrs} attributes, {len(self.classes)} classes")
        print(f"  {len(self.allows)} allow rules, {len(self.transitions)} type_transitions")

    def _parse_commons(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            key = d[off:off+key_len].rstrip(b'\x00').decode(); off += key_len
            val, off = u32(d, off)
            primary, off = u32(d, off)
            nperms, off = u32(d, off)
            perms = {}
            for _ in range(nperms):
                pk, off = u32(d, off)
                pname = d[off:off+pk].rstrip(b'\x00').decode(); off += pk
                pval, off = u32(d, off)
                perms[pval] = pname
            self.commons[key] = perms
        print(f"  Commons: {nel} ({', '.join(sorted(self.commons.keys())[:8])}...)")
        return off

    def _parse_classes(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            key = d[off:off+key_len].rstrip(b'\x00').decode(); off += key_len
            val, off = u32(d, off)
            primary, off = u32(d, off)

            # Common name
            common_len, off = u32(d, off)
            common_name = ""
            if common_len > 0:
                common_name = d[off:off+common_len].rstrip(b'\x00').decode(); off += common_len

            # Class-specific perms
            nperms, off = u32(d, off)
            perms = {}
            if common_name and common_name in self.commons:
                perms.update(self.commons[common_name])
            for _ in range(nperms):
                pk, off = u32(d, off)
                pname = d[off:off+pk].rstrip(b'\x00').decode(); off += pk
                pval, off = u32(d, off)
                perms[pval] = pname

            # Constraints
            ncons, off = u32(d, off)
            for _ in range(ncons):
                _, off = read_ebitmap(d, off)  # permission set
                nexpr, off = u32(d, off)
                for _ in range(nexpr):
                    etype, off = u32(d, off)
                    attr, off = u32(d, off)
                    op, off = u32(d, off)
                    if etype in (5, 6):  # CEXPR_NAMES, CEXPR_TYPE
                        _, off = read_ebitmap(d, off)
                        if self.mls and etype == 5 and attr >= 5:
                            _, off = read_ebitmap(d, off)
                            _, off = read_ebitmap(d, off)

            # Validate transitions (v19+)
            if self.version >= 19:
                nvtrans, off = u32(d, off)
                for _ in range(nvtrans):
                    _, off = read_ebitmap(d, off)
                    nexpr, off = u32(d, off)
                    for _ in range(nexpr):
                        etype, off = u32(d, off)
                        attr, off = u32(d, off)
                        op, off = u32(d, off)
                        if etype in (5, 6):
                            _, off = read_ebitmap(d, off)
                            if self.mls and etype == 5 and attr >= 5:
                                _, off = read_ebitmap(d, off)
                                _, off = read_ebitmap(d, off)

            # Default object (v27+)
            if self.version >= 27:
                _, off = u32(d, off)  # default_user
                _, off = u32(d, off)  # default_role
                _, off = u32(d, off)  # default_range
            if self.version >= 28:
                _, off = u32(d, off)  # default_type

            self.classes[val] = key
            self.class_perms[val] = perms
        print(f"  Classes: {nel}")
        return off

    def _parse_roles(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            key = d[off:off+key_len].rstrip(b'\x00').decode(); off += key_len
            val, off = u32(d, off)
            if self.version >= 24:
                _, off = u32(d, off)  # bounds
            _, off = read_ebitmap(d, off)  # dominates
            _, off = read_ebitmap(d, off)  # types
            self.roles[val] = key
        print(f"  Roles: {nel} ({', '.join(self.roles.values())})")
        return off

    def _parse_types(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            key = d[off:off+key_len].rstrip(b'\x00').decode(); off += key_len
            val, off = u32(d, off)
            primary, off = u32(d, off)
            flavor, off = u32(d, off)  # 0=type, 1=attrib, 2=alias
            if self.version >= 24:
                _, off = u32(d, off)  # bounds
            self.types[val] = key
            self.type_flavors[val] = flavor
        print(f"  Types+Attrs: {nel}")
        return off

    def _parse_users(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            off += key_len  # skip name
            _, off = u32(d, off)  # value
            if self.version >= 24:
                _, off = u32(d, off)  # bounds
            _, off = read_ebitmap(d, off)  # roles
            if self.mls:
                off = skip_mls_range(d, off)  # default range
                off = skip_mls_range(d, off)  # exp range? Actually this depends on version
        print(f"  Users: {nel}")
        return off

    def _parse_bools(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            off += key_len
            _, off = u32(d, off)  # value
            _, off = u32(d, off)  # state
        print(f"  Bools: {nel}")
        return off

    def _parse_levels(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            off += key_len
            _, off = u32(d, off)  # value
            _, off = u32(d, off)  # isalias
            off = skip_mls_level(d, off)
        print(f"  Levels: {nel}")
        return off

    def _parse_cats(self, d, off, nel, nprim):
        for _ in range(nel):
            key_len, off = u32(d, off)
            off += key_len
            _, off = u32(d, off)  # value
            _, off = u32(d, off)  # isalias
        print(f"  Cats: {nel}")
        return off

    def _parse_avtab(self, d, off):
        nel, off = u32(d, off)
        print(f"  AVtab: {nel} entries")
        for i in range(nel):
            source, off = u32(d, off)
            target, off = u32(d, off)
            tclass, off = u32(d, off)
            specified, off = u32(d, off)

            if specified & 0x0700:
                # Extended permissions (xperms, v30+)
                _, off = u32(d, off)    # specified type (ioctl)
                _, off = u32(d, off)    # driver
                off += 32               # 256-bit perms bitmap
            elif specified & 0x0070:
                # Type rules (transition/member/change)
                datum, off = u32(d, off)
                if specified & 0x0010:  # AVTAB_TRANSITION
                    self.transitions.append((source, target, tclass, datum))
            else:
                # AV rules (allow/auditallow/dontaudit)
                perms_val, off = u32(d, off)
                if specified & 0x0001:  # AVTAB_ALLOWED
                    perm_bits = set()
                    for b in range(32):
                        if perms_val & (1 << b):
                            perm_bits.add(b + 1)
                    self.allows.append((source, target, tclass, perm_bits))
        return off

    def _parse_cond_list(self, d, off):
        nel, off = u32(d, off)
        for _ in range(nel):
            cur_state, off = u32(d, off)
            # Expression
            nexpr, off = u32(d, off)
            for _ in range(nexpr):
                etype, off = u32(d, off)
                boolean, off = u32(d, off)
            # True list
            off = self._parse_cond_av_list(d, off)
            # False list
            off = self._parse_cond_av_list(d, off)
        print(f"  Conditionals: {nel}")
        return off

    def _parse_cond_av_list(self, d, off):
        nel, off = u32(d, off)
        for _ in range(nel):
            source, off = u32(d, off)
            target, off = u32(d, off)
            tclass, off = u32(d, off)
            specified, off = u32(d, off)
            if specified & 0x0700:
                _, off = u32(d, off)
                _, off = u32(d, off)
                off += 32
            elif specified & 0x0070:
                datum, off = u32(d, off)
                if specified & 0x0010:
                    self.transitions.append((source, target, tclass, datum))
            else:
                perms_val, off = u32(d, off)
                if specified & 0x0001:
                    perm_bits = set()
                    for b in range(32):
                        if perms_val & (1 << b):
                            perm_bits.add(b + 1)
                    self.allows.append((source, target, tclass, perm_bits))
        return off

    def _parse_role_trans(self, d, off):
        nel, off = u32(d, off)
        for _ in range(nel):
            _, off = u32(d, off)  # role
            _, off = u32(d, off)  # type
            if self.version >= 26:
                _, off = u32(d, off)  # tclass
            _, off = u32(d, off)  # new_role
        print(f"  Role transitions: {nel}")
        return off

    def _parse_role_allow(self, d, off):
        nel, off = u32(d, off)
        for _ in range(nel):
            _, off = u32(d, off)  # role
            _, off = u32(d, off)  # new_role
        print(f"  Role allows: {nel}")
        return off

    def _parse_filename_trans(self, d, off):
        nel, off = u32(d, off)
        for _ in range(nel):
            name_len, off = u32(d, off)
            off += name_len  # filename
            _, off = u32(d, off)  # stype
            _, off = u32(d, off)  # ttype
            _, off = u32(d, off)  # tclass
            _, off = u32(d, off)  # otype
        print(f"  Filename transitions: {nel}")
        return off

    def _skip_ocontext(self, d, off, ocon_type):
        nel, off = u32(d, off)
        for _ in range(nel):
            if ocon_type == 0:  # isid
                _, off = u32(d, off)  # sid
                off = self._read_context(d, off)
            elif ocon_type == 1:  # fs
                name_len, off = u32(d, off)
                off += name_len
                off = self._read_context(d, off)
                off = self._read_context(d, off)
            elif ocon_type == 2:  # port
                _, off = u32(d, off)  # protocol
                _, off = u32(d, off)  # low
                _, off = u32(d, off)  # high
                off = self._read_context(d, off)
            elif ocon_type == 3:  # netif
                name_len, off = u32(d, off)
                off += name_len
                off = self._read_context(d, off)
                off = self._read_context(d, off)
            elif ocon_type == 4:  # node
                off += 4  # addr
                off += 4  # mask
                off = self._read_context(d, off)
            elif ocon_type == 5:  # fsuse
                _, off = u32(d, off)  # behavior
                name_len, off = u32(d, off)
                off += name_len
                off = self._read_context(d, off)
            elif ocon_type == 6:  # node6
                off += 16  # addr
                off += 16  # mask
                off = self._read_context(d, off)
        return off

    def _read_context(self, d, off):
        _, off = u32(d, off)  # user
        _, off = u32(d, off)  # role
        _, off = u32(d, off)  # type
        if self.mls:
            off = skip_mls_range(d, off)
        return off

    def _skip_genfs(self, d, off):
        nel, off = u32(d, off)
        for _ in range(nel):
            name_len, off = u32(d, off)
            off += name_len  # fstype
            nentries, off = u32(d, off)
            for _ in range(nentries):
                name_len, off = u32(d, off)
                off += name_len  # path
                _, off = u32(d, off)  # sclass
                off = self._read_context(d, off)
        print(f"  GenFS: {nel}")
        return off

    def _skip_range_trans(self, d, off):
        nel, off = u32(d, off)
        for _ in range(nel):
            _, off = u32(d, off)  # source
            _, off = u32(d, off)  # target
            if self.version >= 21:
                _, off = u32(d, off)  # tclass
            off = skip_mls_range(d, off)
        print(f"  Range transitions: {nel}")
        return off

    def _parse_type_attr_map(self, d, off):
        # For each type (1..nprim), read ebitmap of attributes
        self.type_attrs = {}
        n = len([k for k in self.types if self.type_flavors.get(k) == 0])
        # Actually, the type_attr_map has one ebitmap per type value (1..ntypes)
        max_type = max(self.types.keys()) if self.types else 0
        for i in range(1, max_type + 1):
            bits, off = read_ebitmap(d, off)
            if i in self.types:
                self.type_attrs[i] = bits
        print(f"  Type-attr map: {max_type} entries")
        return off

    def _parse_permissive_map(self, d, off):
        bits, off = read_ebitmap(d, off)
        self.permissive_types = bits
        names = [self.types.get(b, f"?{b}") for b in sorted(bits)]
        print(f"  Permissive types: {len(bits)} {names if names else '(none)'}")
        return off

    # === Query methods ===

    def tname(self, tid):
        return self.types.get(tid, f"?{tid}")

    def cname(self, cid):
        return self.classes.get(cid, f"?{cid}")

    def pnames(self, cid, pbits):
        perms = self.class_perms.get(cid, {})
        return [perms.get(b, f"p{b}") for b in sorted(pbits)]

    def query_allow(self, source=None, target=None, perm_filter=None):
        results = []
        src_ids = set(tid for tid, n in self.types.items() if n == source) if source else None
        tgt_ids = set(tid for tid, n in self.types.items() if n == target) if target else None
        for s, t, c, p in self.allows:
            if src_ids and s not in src_ids: continue
            if tgt_ids and t not in tgt_ids: continue
            pn = set(self.pnames(c, p))
            if perm_filter and not (pn & set(perm_filter)): continue
            results.append((self.tname(s), self.tname(t), self.cname(c), pn))
        return results

    def query_transitions(self, source=None, default=None):
        results = []
        src_ids = set(tid for tid, n in self.types.items() if n == source) if source else None
        def_ids = set(tid for tid, n in self.types.items() if n == default) if default else None
        for s, t, c, d in self.transitions:
            if src_ids and s not in src_ids: continue
            if def_ids and d not in def_ids: continue
            results.append((self.tname(s), self.tname(t), self.cname(c), self.tname(d)))
        return results

    def entrypoints(self):
        ep = {}
        for s, t, c, p in self.allows:
            if "entrypoint" in set(self.pnames(c, p)):
                ep.setdefault(self.tname(s), []).append(self.tname(t))
        return ep


def main():
    print("="*70)
    print("  SELinux Policy Deep Analysis — Samsung SM-T377A")
    print("="*70)

    pdb = PolicyDB(POLICY_PATH)

    # ============ 1. PERMISSIVE TYPES ============
    print("\n" + "="*70)
    print("  1. PERMISSIVE TYPES (instant escalation if reachable)")
    print("="*70)
    if hasattr(pdb, 'permissive_types') and pdb.permissive_types:
        for tid in sorted(pdb.permissive_types):
            print(f"  *** PERMISSIVE: {pdb.tname(tid)} ***")
    else:
        print("  (none)")

    # ============ 2. TRANSITIONS FROM shell ============
    print("\n" + "="*70)
    print("  2. TYPE TRANSITIONS FROM shell")
    print("="*70)
    for s, t, c, d in pdb.query_transitions(source="shell"):
        marker = " *** INTERESTING ***" if d not in ("shell", "shell_data_file") else ""
        print(f"  type_transition {s} {t}:{c} {d};{marker}")

    # ============ 3. TRANSITIONS FROM untrusted_app ============
    print("\n" + "="*70)
    print("  3. TYPE TRANSITIONS FROM untrusted_app")
    print("="*70)
    for s, t, c, d in pdb.query_transitions(source="untrusted_app"):
        marker = " *** INTERESTING ***" if d not in ("untrusted_app", "app_data_file") else ""
        print(f"  type_transition {s} {t}:{c} {d};{marker}")

    # ============ 4. rd_shell_exec ============
    print("\n" + "="*70)
    print("  4a. WHO CAN ACCESS rd_shell_exec?")
    print("="*70)
    for s, t, c, p in pdb.query_allow(target="rd_shell_exec"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(p))} }};")

    print("\n  4b. TRANSITIONS TO rd_shell:")
    for s, t, c, d in pdb.query_transitions(default="rd_shell"):
        print(f"  type_transition {s} {t}:{c} {d};")

    print("\n  4c. WHAT CAN rd_shell DO?")
    for s, t, c, p in pdb.query_allow(source="rd_shell"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(p))} }};")

    # ============ 5. su_exec / su ============
    print("\n" + "="*70)
    print("  5a. WHO CAN ACCESS su_exec?")
    print("="*70)
    for s, t, c, p in pdb.query_allow(target="su_exec"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(p))} }};")

    print("\n  5b. TRANSITIONS TO su:")
    for s, t, c, d in pdb.query_transitions(default="su"):
        print(f"  type_transition {s} {t}:{c} {d};")

    print("\n  5c. WHAT CAN su DO?")
    for s, t, c, p in pdb.query_allow(source="su"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(p))} }};")

    # ============ 6. SHELL EXECUTE TARGETS ============
    print("\n" + "="*70)
    print("  6. SHELL EXECUTE PERMISSIONS")
    print("="*70)
    exec_rules = pdb.query_allow(source="shell", perm_filter=["execute", "execute_no_trans"])
    for s, t, c, p in exec_rules:
        exec_p = p & {"execute", "execute_no_trans", "entrypoint", "read", "open", "getattr"}
        print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(exec_p))} }};")

    # ============ 7. ENTRYPOINTS ============
    print("\n" + "="*70)
    print("  7. DOMAIN ENTRYPOINTS (file type -> domain)")
    print("="*70)
    ep = pdb.entrypoints()
    for domain in sorted(ep):
        print(f"  {domain} <- {', '.join(sorted(ep[domain]))}")

    # ============ 8. SHELL -> EXEC -> TRANSITION CHAINS ============
    print("\n" + "="*70)
    print("  8. SHELL EXECUTE → DOMAIN TRANSITION CHAINS")
    print("="*70)
    shell_exec = set(t for _, t, _, p in pdb.query_allow(source="shell", perm_filter=["execute"]))
    for domain, entry_files in ep.items():
        if domain == "shell":
            continue
        overlap = shell_exec & set(entry_files)
        if overlap:
            # Check if transition rule exists
            for ft in overlap:
                trans = pdb.query_transitions(source="shell")
                for s, t, c, d in trans:
                    if t == ft:
                        print(f"  *** CHAIN: shell -exec-> {ft} -transition-> {d} ***")

    # ============ 9. BLUETOOTH PRIVILEGES ============
    print("\n" + "="*70)
    print("  9. BLUETOOTH DOMAIN KEY PRIVILEGES")
    print("="*70)
    interesting_classes = {"chr_file", "blk_file", "capability", "capability2",
                          "rawip_socket", "packet_socket", "unix_stream_socket",
                          "binder", "service_manager", "property_service"}
    for s, t, c, p in pdb.query_allow(source="bluetooth"):
        if c in interesting_classes:
            print(f"  allow bluetooth {t}:{c} {{ {' '.join(sorted(p))} }};")

    # ============ 10. DIAGEXE PRIVILEGES ============
    print("\n" + "="*70)
    print("  10. DIAGEXE DOMAIN ALL RULES")
    print("="*70)
    for s, t, c, p in pdb.query_allow(source="diagexe"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(p))} }};")

    # ============ 11. SECURITY-CRITICAL WRITES ============
    print("\n" + "="*70)
    print("  11. WRITE TO kernel/security_file/selinuxfs")
    print("="*70)
    for tgt in ["kernel", "security_file", "selinuxfs"]:
        rules = pdb.query_allow(target=tgt, perm_filter=["write", "setattr", "relabelfrom", "relabelto"])
        for s, t, c, p in rules:
            print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(p))} }};")

    # ============ 12. SAMSUNG APP DOMAIN COMPARISON ============
    print("\n" + "="*70)
    print("  12. SAMSUNG DOMAIN CAPABILITY COMPARISON")
    print("="*70)
    for domain in ["untrusted_app", "sec_untrusted_app", "filtered_untrusted_app",
                   "platform_app", "system_app", "carrier_app", "knox_system_app"]:
        caps = pdb.query_allow(source=domain, perm_filter=None)
        cap_rules = [r for r in caps if r[2] in ("capability", "capability2")]
        chr_rules = [r for r in caps if r[2] == "chr_file"]
        binder_rules = [r for r in caps if r[2] in ("binder", "service_manager")]
        print(f"  {domain}: {len(caps)} total rules, "
              f"{len(cap_rules)} capability, {len(chr_rules)} chr_file, "
              f"{len(binder_rules)} binder/svc_mgr")

    print("\n" + "="*70)
    print("  ANALYSIS COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main()
