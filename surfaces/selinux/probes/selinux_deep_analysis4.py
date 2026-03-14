#!/usr/bin/env python3
"""Pure Python Android SELinux binary policy v30 parser.
Format: datum fields are read BEFORE the key string (AOSP policydb.c convention)."""

import struct
import sys

POLICY_PATH = "/tmp/sepolicy"

def u32(d, o):
    return struct.unpack_from('<I', d, o)[0], o + 4

def read_ebitmap(d, o):
    mapsize, o = u32(d, o)
    highbit, o = u32(d, o)
    count, o = u32(d, o)
    bits = set()
    for _ in range(count):
        startbit, o = u32(d, o)
        lo = struct.unpack_from('<I', d, o)[0]; o += 4
        hi = struct.unpack_from('<I', d, o)[0]; o += 4
        for b in range(32):
            if lo & (1 << b): bits.add(startbit + b)
            if hi & (1 << b): bits.add(startbit + 32 + b)
    return bits, o

def skip_mls_level(d, o):
    _, o = u32(d, o)       # sens
    _, o = read_ebitmap(d, o)  # cats
    return o

def skip_mls_range(d, o):
    o = skip_mls_level(d, o)
    o = skip_mls_level(d, o)
    return o


class PolicyDB:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        self.types = {}
        self.type_flavors = {}
        self.classes = {}
        self.class_perms = {}
        self.commons = {}
        self.allows = []
        self.transitions = []
        self.roles = {}
        self.permissive_types = set()
        self.type_attrs = {}
        self._parse()

    def _parse(self):
        d = self.data
        o = 0
        magic, o = u32(d, o)
        slen, o = u32(d, o)
        ptype = d[o:o+slen].rstrip(b'\x00').decode(); o += slen
        self.version, o = u32(d, o)
        config, o = u32(d, o)
        self.mls = bool(config & 1)
        sym_num, o = u32(d, o)
        ocon_num, o = u32(d, o)
        print(f"Policy: '{ptype}' v{self.version} MLS={self.mls} syms={sym_num} ocons={ocon_num}")

        parsers = [self._p_commons, self._p_classes, self._p_roles, self._p_types,
                   self._p_users, self._p_bools, self._p_levels, self._p_cats]
        for i in range(sym_num):
            nprim, o = u32(d, o)
            nel, o = u32(d, o)
            o = parsers[i](d, o, nel, nprim)

        o = self._p_avtab(d, o)
        o = self._p_condlist(d, o)
        o = self._p_role_trans(d, o)
        o = self._p_role_allow(d, o)
        if self.version >= 25:
            o = self._p_filename_trans(d, o)
        for i in range(ocon_num):
            o = self._p_ocontext(d, o, i)
        o = self._p_genfs(d, o)
        if self.mls:
            o = self._p_range_trans(d, o)
        if self.version >= 24:
            o = self._p_type_attr_map(d, o)
        if self.version >= 23:
            self.permissive_types, o = read_ebitmap(d, o)
            names = [self.types.get(b, f"?{b}") for b in sorted(self.permissive_types)]
            print(f"  Permissive: {names if names else '(none)'}")

        nt = sum(1 for v in self.type_flavors.values() if v == 0)
        na = sum(1 for v in self.type_flavors.values() if v == 1)
        print(f"\nTotal: {nt} types, {na} attrs, {len(self.classes)} classes, "
              f"{len(self.allows)} allow, {len(self.transitions)} transitions")

    # --- COMMONS: 4 u32 (len, value, nprim, nel) + key + nel perms ---
    def _p_commons(self, d, o, nel, nprim):
        for _ in range(nel):
            klen, o = u32(d, o)
            val, o = u32(d, o)
            pnprim, o = u32(d, o)
            pnel, o = u32(d, o)
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
            perms = {}
            for _ in range(pnel):
                pklen, o = u32(d, o)
                pval, o = u32(d, o)
                pname = d[o:o+pklen].rstrip(b'\x00').decode(); o += pklen
                perms[pval] = pname
            self.commons[key] = perms
        print(f"  Commons: {nel} ({', '.join(sorted(self.commons)[:6])})")
        return o

    # --- CLASSES: 6 u32 (len, len2, value, nprim, nel, ncons) + key + common + perms + constraints ---
    def _p_classes(self, d, o, nel, nprim):
        for _ in range(nel):
            klen, o = u32(d, o)
            comlen, o = u32(d, o)
            val, o = u32(d, o)
            pnprim, o = u32(d, o)
            pnel, o = u32(d, o)
            ncons, o = u32(d, o)
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
            perms = {}
            comkey = ""
            if comlen > 0:
                comkey = d[o:o+comlen].rstrip(b'\x00').decode(); o += comlen
                if comkey in self.commons:
                    perms.update(self.commons[comkey])
            for _ in range(pnel):
                pklen, o = u32(d, o)
                pval, o = u32(d, o)
                pname = d[o:o+pklen].rstrip(b'\x00').decode(); o += pklen
                perms[pval] = pname
            for _ in range(ncons):
                _, o = read_ebitmap(d, o)
                nexpr, o = u32(d, o)
                for _ in range(nexpr):
                    et, o = u32(d, o)
                    at, o = u32(d, o)
                    op, o = u32(d, o)
                    if et in (5, 6):
                        _, o = read_ebitmap(d, o)
                        if self.mls and et == 5 and at >= 5:
                            _, o = read_ebitmap(d, o)
                            _, o = read_ebitmap(d, o)
            if self.version >= 19:
                nvt, o = u32(d, o)
                for _ in range(nvt):
                    _, o = read_ebitmap(d, o)
                    nexpr, o = u32(d, o)
                    for _ in range(nexpr):
                        et, o = u32(d, o)
                        at, o = u32(d, o)
                        op, o = u32(d, o)
                        if et in (5, 6):
                            _, o = read_ebitmap(d, o)
                            if self.mls and et == 5 and at >= 5:
                                _, o = read_ebitmap(d, o)
                                _, o = read_ebitmap(d, o)
            if self.version >= 27:
                _, o = u32(d, o)  # def_user
                _, o = u32(d, o)  # def_role
                _, o = u32(d, o)  # def_range
            if self.version >= 28:
                _, o = u32(d, o)  # def_type
            self.classes[val] = key
            self.class_perms[val] = perms
        print(f"  Classes: {nel}")
        return o

    # --- ROLES: 3 u32 (len, value, bounds[v24+]) + key + dominates_bitmap + types_bitmap ---
    def _p_roles(self, d, o, nel, nprim):
        for _ in range(nel):
            klen, o = u32(d, o)
            val, o = u32(d, o)
            if self.version >= 24:
                _, o = u32(d, o)
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
            _, o = read_ebitmap(d, o)
            _, o = read_ebitmap(d, o)
            self.roles[val] = key
        print(f"  Roles: {nel} ({', '.join(self.roles.values())})")
        return o

    # --- TYPES: 4/5 u32 (len, value, primary, flavor, [bounds]) + key ---
    def _p_types(self, d, o, nel, nprim):
        nfields = 5 if self.version >= 24 else 4
        for _ in range(nel):
            klen, o = u32(d, o)
            val, o = u32(d, o)
            primary, o = u32(d, o)
            flavor, o = u32(d, o)
            if self.version >= 24:
                _, o = u32(d, o)  # bounds
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
            self.types[val] = key
            self.type_flavors[val] = flavor
        print(f"  Types+Attrs: {nel}")
        return o

    def _p_users(self, d, o, nel, nprim):
        for _ in range(nel):
            klen, o = u32(d, o)
            val, o = u32(d, o)
            if self.version >= 24:
                _, o = u32(d, o)
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
            _, o = read_ebitmap(d, o)
            if self.mls:
                o = skip_mls_range(d, o)
                o = skip_mls_range(d, o)
        print(f"  Users: {nel}")
        return o

    def _p_bools(self, d, o, nel, nprim):
        for _ in range(nel):
            klen, o = u32(d, o)
            val, o = u32(d, o)
            state, o = u32(d, o)
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
        print(f"  Bools: {nel}")
        return o

    def _p_levels(self, d, o, nel, nprim):
        for _ in range(nel):
            klen, o = u32(d, o)
            val, o = u32(d, o)
            isalias, o = u32(d, o)
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
            o = skip_mls_level(d, o)
        print(f"  Levels: {nel}")
        return o

    def _p_cats(self, d, o, nel, nprim):
        for _ in range(nel):
            klen, o = u32(d, o)
            val, o = u32(d, o)
            isalias, o = u32(d, o)
            key = d[o:o+klen].rstrip(b'\x00').decode(); o += klen
        print(f"  Cats: {nel}")
        return o

    def _p_avtab(self, d, o):
        nel, o = u32(d, o)
        print(f"  AVtab: {nel} entries")
        for _ in range(nel):
            src, o = u32(d, o)
            tgt, o = u32(d, o)
            tcls, o = u32(d, o)
            spec, o = u32(d, o)
            if spec & 0x0700:  # xperms
                _, o = u32(d, o)
                _, o = u32(d, o)
                o += 32
            elif spec & 0x0070:  # type rules
                datum, o = u32(d, o)
                if spec & 0x0010:
                    self.transitions.append((src, tgt, tcls, datum))
            else:  # av rules
                pval, o = u32(d, o)
                if spec & 0x0001:
                    pbits = set()
                    for b in range(32):
                        if pval & (1 << b): pbits.add(b + 1)
                    self.allows.append((src, tgt, tcls, pbits))
        return o

    def _p_condlist(self, d, o):
        nel, o = u32(d, o)
        for _ in range(nel):
            _, o = u32(d, o)  # cur_state
            nexpr, o = u32(d, o)
            for _ in range(nexpr):
                _, o = u32(d, o)  # type
                _, o = u32(d, o)  # bool
            o = self._p_cond_av(d, o)
            o = self._p_cond_av(d, o)
        print(f"  Conditionals: {nel}")
        return o

    def _p_cond_av(self, d, o):
        nel, o = u32(d, o)
        for _ in range(nel):
            src, o = u32(d, o)
            tgt, o = u32(d, o)
            tcls, o = u32(d, o)
            spec, o = u32(d, o)
            if spec & 0x0700:
                _, o = u32(d, o); _, o = u32(d, o); o += 32
            elif spec & 0x0070:
                datum, o = u32(d, o)
                if spec & 0x0010:
                    self.transitions.append((src, tgt, tcls, datum))
            else:
                pval, o = u32(d, o)
                if spec & 0x0001:
                    pbits = set()
                    for b in range(32):
                        if pval & (1 << b): pbits.add(b + 1)
                    self.allows.append((src, tgt, tcls, pbits))
        return o

    def _p_role_trans(self, d, o):
        nel, o = u32(d, o)
        for _ in range(nel):
            _, o = u32(d, o); _, o = u32(d, o)
            if self.version >= 26: _, o = u32(d, o)
            _, o = u32(d, o)
        print(f"  Role trans: {nel}")
        return o

    def _p_role_allow(self, d, o):
        nel, o = u32(d, o)
        for _ in range(nel):
            _, o = u32(d, o); _, o = u32(d, o)
        print(f"  Role allow: {nel}")
        return o

    def _p_filename_trans(self, d, o):
        nel, o = u32(d, o)
        for _ in range(nel):
            flen, o = u32(d, o)
            o += flen
            _, o = u32(d, o); _, o = u32(d, o); _, o = u32(d, o); _, o = u32(d, o)
        print(f"  Fname trans: {nel}")
        return o

    def _read_context(self, d, o):
        _, o = u32(d, o); _, o = u32(d, o); _, o = u32(d, o)
        if self.mls: o = skip_mls_range(d, o)
        return o

    def _p_ocontext(self, d, o, i):
        nel, o = u32(d, o)
        for _ in range(nel):
            if i == 0:  # isid
                _, o = u32(d, o); o = self._read_context(d, o)
            elif i == 1:  # fs
                flen, o = u32(d, o); o += flen
                o = self._read_context(d, o); o = self._read_context(d, o)
            elif i == 2:  # port
                _, o = u32(d, o); _, o = u32(d, o); _, o = u32(d, o)
                o = self._read_context(d, o)
            elif i == 3:  # netif
                flen, o = u32(d, o); o += flen
                o = self._read_context(d, o); o = self._read_context(d, o)
            elif i == 4:  # node
                o += 8; o = self._read_context(d, o)
            elif i == 5:  # fsuse
                _, o = u32(d, o); flen, o = u32(d, o); o += flen
                o = self._read_context(d, o)
            elif i == 6:  # node6
                o += 32; o = self._read_context(d, o)
        return o

    def _p_genfs(self, d, o):
        nel, o = u32(d, o)
        for _ in range(nel):
            flen, o = u32(d, o); o += flen
            nc, o = u32(d, o)
            for _ in range(nc):
                plen, o = u32(d, o); o += plen
                _, o = u32(d, o)
                o = self._read_context(d, o)
        print(f"  GenFS: {nel}")
        return o

    def _p_range_trans(self, d, o):
        nel, o = u32(d, o)
        for _ in range(nel):
            _, o = u32(d, o); _, o = u32(d, o)
            if self.version >= 21: _, o = u32(d, o)
            o = skip_mls_range(d, o)
        print(f"  Range trans: {nel}")
        return o

    def _p_type_attr_map(self, d, o):
        mx = max(self.types.keys()) if self.types else 0
        for i in range(1, mx + 1):
            bits, o = read_ebitmap(d, o)
            if i in self.types:
                self.type_attrs[i] = bits
        print(f"  Type-attr map: {mx}")
        return o

    # === Query helpers ===
    def tn(self, tid): return self.types.get(tid, f"?{tid}")
    def cn(self, cid): return self.classes.get(cid, f"?{cid}")
    def pn(self, cid, pb):
        pm = self.class_perms.get(cid, {})
        return sorted(pm.get(b, f"p{b}") for b in pb)

    def q_allow(self, src=None, tgt=None, pfilt=None):
        si = set(t for t,n in self.types.items() if n==src) if src else None
        ti = set(t for t,n in self.types.items() if n==tgt) if tgt else None
        r = []
        for s,t,c,p in self.allows:
            if si and s not in si: continue
            if ti and t not in ti: continue
            pn = set(self.pn(c,p))
            if pfilt and not (pn & set(pfilt)): continue
            r.append((self.tn(s), self.tn(t), self.cn(c), pn))
        return r

    def q_trans(self, src=None, dflt=None):
        si = set(t for t,n in self.types.items() if n==src) if src else None
        di = set(t for t,n in self.types.items() if n==dflt) if dflt else None
        r = []
        for s,t,c,d in self.transitions:
            if si and s not in si: continue
            if di and d not in di: continue
            r.append((self.tn(s), self.tn(t), self.cn(c), self.tn(d)))
        return r

    def entrypoints(self):
        ep = {}
        for s,t,c,p in self.allows:
            if "entrypoint" in set(self.pn(c,p)):
                ep.setdefault(self.tn(s), []).append(self.tn(t))
        return ep


def main():
    print("="*70)
    print("  SELinux Policy Deep Analysis — Samsung SM-T377A")
    print("="*70)
    pdb = PolicyDB(POLICY_PATH)

    P = lambda h: print(f"\n{'='*70}\n  {h}\n{'='*70}")

    P("1. PERMISSIVE TYPES")
    if pdb.permissive_types:
        for t in sorted(pdb.permissive_types):
            print(f"  *** PERMISSIVE: {pdb.tn(t)} ***")
    else:
        print("  (none)")

    P("2. TYPE TRANSITIONS FROM shell")
    for s,t,c,d in pdb.q_trans(src="shell"):
        tag = " ***" if d not in ("shell","shell_data_file") else ""
        print(f"  type_transition {s} {t}:{c} {d};{tag}")

    P("3. TYPE TRANSITIONS FROM untrusted_app")
    for s,t,c,d in pdb.q_trans(src="untrusted_app"):
        tag = " ***" if d not in ("untrusted_app","app_data_file","untrusted_app_tmpfs") else ""
        print(f"  type_transition {s} {t}:{c} {d};{tag}")

    P("4a. WHO CAN ACCESS rd_shell_exec?")
    for s,t,c,p in pdb.q_allow(tgt="rd_shell_exec"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(p)} }};")
    P("4b. TRANSITIONS TO rd_shell")
    for s,t,c,d in pdb.q_trans(dflt="rd_shell"):
        print(f"  type_transition {s} {t}:{c} {d};")
    P("4c. WHAT CAN rd_shell DO?")
    for s,t,c,p in pdb.q_allow(src="rd_shell"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(p)} }};")

    P("5a. WHO CAN ACCESS su_exec?")
    for s,t,c,p in pdb.q_allow(tgt="su_exec"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(p)} }};")
    P("5b. TRANSITIONS TO su")
    for s,t,c,d in pdb.q_trans(dflt="su"):
        print(f"  type_transition {s} {t}:{c} {d};")
    P("5c. WHAT CAN su DO?")
    for s,t,c,p in pdb.q_allow(src="su"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(p)} }};")

    P("6. SHELL EXECUTE PERMISSIONS")
    for s,t,c,p in pdb.q_allow(src="shell", pfilt=["execute","execute_no_trans"]):
        rp = p & {"execute","execute_no_trans","read","open","getattr","entrypoint"}
        print(f"  allow {s} {t}:{c} {{ {' '.join(sorted(rp))} }};")

    P("7. DOMAIN ENTRYPOINTS")
    ep = pdb.entrypoints()
    for dom in sorted(ep):
        print(f"  {dom} <- {', '.join(sorted(ep[dom]))}")

    P("8. SHELL EXEC → DOMAIN TRANSITION CHAINS")
    shell_exec = set(t for _,t,_,p in pdb.q_allow(src="shell", pfilt=["execute"]))
    for dom, efs in ep.items():
        if dom == "shell": continue
        overlap = shell_exec & set(efs)
        if overlap:
            for ft in overlap:
                for s,t,c,d in pdb.q_trans(src="shell"):
                    if t == ft:
                        print(f"  *** CHAIN: shell -exec-> {ft} -transition-> {d} ***")
                print(f"  shell can execute {ft} (entrypoint for {dom})")

    P("9. BLUETOOTH DOMAIN KEY PRIVILEGES")
    ic = {"chr_file","blk_file","capability","capability2","rawip_socket",
          "packet_socket","unix_stream_socket","binder","service_manager"}
    for s,t,c,p in pdb.q_allow(src="bluetooth"):
        if c in ic:
            print(f"  allow bluetooth {t}:{c} {{ {' '.join(p)} }};")

    P("10. DIAGEXE DOMAIN ALL RULES")
    for s,t,c,p in pdb.q_allow(src="diagexe"):
        print(f"  allow {s} {t}:{c} {{ {' '.join(p)} }};")

    P("11. WRITE TO kernel/security_file/selinuxfs")
    for tg in ["kernel","security_file","selinuxfs"]:
        for s,t,c,p in pdb.q_allow(tgt=tg, pfilt=["write","setattr","relabelfrom","relabelto"]):
            print(f"  allow {s} {t}:{c} {{ {' '.join(p)} }};")

    P("12. SAMSUNG DOMAIN COMPARISON")
    for dom in ["untrusted_app","sec_untrusted_app","filtered_untrusted_app",
                "platform_app","system_app","carrier_app","knox_system_app"]:
        all_r = pdb.q_allow(src=dom)
        cap_r = [r for r in all_r if r[2] in ("capability","capability2")]
        chr_r = [r for r in all_r if r[2]=="chr_file"]
        bnd_r = [r for r in all_r if r[2] in ("binder","service_manager")]
        print(f"  {dom}: {len(all_r)} rules, {len(cap_r)} cap, {len(chr_r)} chr, {len(bnd_r)} binder")
        for s,t,c,p in cap_r:
            print(f"    {c}: {' '.join(p)}")

    print(f"\n{'='*70}\n  ANALYSIS COMPLETE\n{'='*70}")


if __name__ == "__main__":
    main()
