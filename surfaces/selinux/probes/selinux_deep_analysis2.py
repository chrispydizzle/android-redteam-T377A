#!/usr/bin/env python3
"""Direct libsepol ctypes wrapper to parse Android SELinux binary policy v30.
Falls back to pure binary parsing if libsepol also fails."""

import ctypes
import ctypes.util
import struct
import sys
import os

POLICY_PATH = "/tmp/sepolicy"

# ============================================================
# Approach 1: Try libsepol via ctypes
# ============================================================
def try_libsepol():
    lib_path = ctypes.util.find_library("sepol")
    if not lib_path:
        print("libsepol not found")
        return False
    
    try:
        sepol = ctypes.CDLL(lib_path)
        
        # sepol_policy_file_t *pf
        pf = ctypes.c_void_p()
        rc = sepol.sepol_policy_file_create(ctypes.byref(pf))
        if rc < 0:
            print(f"sepol_policy_file_create failed: {rc}")
            return False
        
        # Open the file
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        libc.fopen.restype = ctypes.c_void_p
        libc.fopen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        fp = libc.fopen(POLICY_PATH.encode(), b"rb")
        if not fp:
            print("Failed to open policy file")
            return False
        
        # Set the file pointer
        sepol.sepol_policy_file_set_fp(pf, ctypes.c_void_p(fp))
        
        # Create policydb handle
        pdb = ctypes.c_void_p()
        rc = sepol.sepol_policydb_create(ctypes.byref(pdb))
        if rc < 0:
            print(f"sepol_policydb_create failed: {rc}")
            return False
        
        # Read the policy
        rc = sepol.sepol_policydb_read(pdb, pf)
        if rc < 0:
            print(f"sepol_policydb_read failed: {rc}")
            print("libsepol cannot parse this Android policy")
            sepol.sepol_policydb_free(pdb)
            libc.fclose(ctypes.c_void_p(fp))
            return False
        
        print("libsepol loaded policy successfully!")
        # If we get here, we can use libsepol to query
        # But the internal structures are opaque...
        sepol.sepol_policydb_free(pdb)
        libc.fclose(ctypes.c_void_p(fp))
        return True
    except Exception as e:
        print(f"libsepol error: {e}")
        return False

# ============================================================
# Approach 2: Pure Python binary policy parser
# ============================================================

def read_u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0], offset + 4

def read_str(data, offset):
    slen, offset = read_u32(data, offset)
    s = data[offset:offset+slen]
    # Strip null terminator if present
    if s and s[-1] == 0:
        s = s[:-1]
    return s.decode('ascii', errors='replace'), offset + slen

def read_bitmap(data, offset, highbit=0):
    """Read an ebitmap (extended bitmap) from policy."""
    mapsize, offset = read_u32(data, offset)
    highbit_val, offset = read_u32(data, offset)
    count, offset = read_u32(data, offset)
    
    bits = set()
    for _ in range(count):
        startbit, offset = read_u32(data, offset)
        mapval = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        for b in range(64):
            if mapval & (1 << b):
                bits.add(startbit + b)
    return bits, offset

class PolicyDB:
    """Minimal Android SELinux binary policy parser."""
    
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        
        self.types = {}      # id -> name
        self.type_attrs = {}  # id -> set of attribute ids
        self.classes = {}    # id -> name
        self.class_perms = {} # id -> {perm_name: perm_bit}
        self.commons = {}    # name -> {perm_name: perm_bit}
        self.roles = {}      # id -> name
        self.allows = []     # list of (src_id, tgt_id, class_id, perms_set)
        self.transitions = [] # list of (src_id, tgt_id, class_id, default_id)
        self.permissive = set() # type ids that are permissive
        
        self._parse()
    
    def _parse(self):
        data = self.data
        off = 0
        
        # Header
        magic, off = read_u32(data, off)
        assert magic == 0xf97cff8c, f"Bad magic: 0x{magic:08x}"
        
        slen, off = read_u32(data, off)
        ptype = data[off:off+slen].decode('ascii', errors='replace').rstrip('\x00')
        off += slen
        print(f"Policy type: '{ptype}'")
        
        self.version, off = read_u32(data, off)
        print(f"Policy version: {self.version}")
        
        config, off = read_u32(data, off)
        self.mls = bool(config & 1)
        print(f"MLS: {self.mls}")
        
        sym_num, off = read_u32(data, off)
        ocon_num, off = read_u32(data, off)
        print(f"Symbol tables: {sym_num}, OContext types: {ocon_num}")
        
        # Symbol table sizes (nprim, nel for each table)
        sym_sizes = []
        for i in range(sym_num):
            nprim, off = read_u32(data, off)
            nel, off = read_u32(data, off)
            sym_sizes.append((nprim, nel))
            
        print(f"Symbol table sizes: {sym_sizes}")
        # Tables: 0=commons, 1=classes, 2=roles, 3=types, 4=users,
        #         5=bools, 6=levels, 7=cats
        
        # Parse each symbol table
        # Table 0: commons
        nprim, nel = sym_sizes[0]
        off = self._parse_commons(data, off, nel)
        
        # Table 1: classes
        nprim, nel = sym_sizes[1]
        off = self._parse_classes(data, off, nel)
        
        # Table 2: roles
        nprim, nel = sym_sizes[2]
        off = self._parse_roles(data, off, nel)
        
        # Table 3: types
        nprim, nel = sym_sizes[3]
        off = self._parse_types(data, off, nel)
        
        # Skip remaining symbol tables (users, bools, levels, cats)
        # We need to skip them properly to reach the AV rules
        # Table 4: users
        nprim, nel = sym_sizes[4]
        off = self._skip_users(data, off, nel)
        
        # Table 5: bools
        nprim, nel = sym_sizes[5]
        off = self._skip_bools(data, off, nel)
        
        # Table 6: levels (MLS)
        nprim, nel = sym_sizes[6]
        off = self._skip_levels(data, off, nel)
        
        # Table 7: cats (MLS)
        nprim, nel = sym_sizes[7]
        off = self._skip_cats(data, off, nel)
        
        # After symbol tables: access vector rules
        off = self._parse_avtab(data, off)
        
        # After avtab: conditional lists, role_trans, role_allow
        # then: filename_trans (v25+), then ocontexts, genfs
        # We need to find the type attributes section and permissive bitmap
        
        # Try to find permissive types bitmap
        self._find_permissive_types(data)
        
        print(f"\nParsed: {len(self.types)} types, {len(self.classes)} classes, "
              f"{len(self.allows)} allow rules, {len(self.transitions)} transitions, "
              f"{len(self.permissive)} permissive types")
    
    def _parse_commons(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)  # datum value
            primary, off = read_u32(data, off)  # primary name flag
            nperms, off = read_u32(data, off)  # number of permissions
            perms = {}
            for _ in range(nperms):
                pname, off = read_str(data, off)
                pval, off = read_u32(data, off)
                perms[pval] = pname
            self.commons[name] = perms
        return off
    
    def _parse_classes(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)  # value (1-based)
            primary, off = read_u32(data, off)
            
            # Common permissions name (may be null string)
            common_name, off = read_str(data, off)
            
            # Class-specific permissions
            nperms, off = read_u32(data, off)
            perms = {}
            
            # Inherit common perms
            if common_name and common_name in self.commons:
                perms.update(self.commons[common_name])
            
            for _ in range(nperms):
                pname, off = read_str(data, off)
                pval, off = read_u32(data, off)
                perms[pval] = pname
            
            # Constraints
            ncons, off = read_u32(data, off)
            for _ in range(ncons):
                # constraint: perms bitmap + expression
                cperm_bits, off = read_bitmap(data, off)
                nexpr, off = read_u32(data, off)
                for _ in range(nexpr):
                    expr_type, off = read_u32(data, off)
                    attr, off = read_u32(data, off)
                    op, off = read_u32(data, off)
                    if expr_type in (5, 6):  # CEXPR_NAMES, CEXPR_TYPE
                        names, off = read_bitmap(data, off)
                        if self.mls and expr_type == 5 and attr >= 5:
                            # MLS: type_names_set
                            names2, off = read_bitmap(data, off)
                            names3, off = read_bitmap(data, off)
            
            # Validate transitions (v32+ ncons)
            if self.version >= 19:
                nvtrans, off = read_u32(data, off)
                for _ in range(nvtrans):
                    cperm_bits, off = read_bitmap(data, off)
                    nexpr, off = read_u32(data, off)
                    for _ in range(nexpr):
                        expr_type, off = read_u32(data, off)
                        attr, off = read_u32(data, off)
                        op, off = read_u32(data, off)
                        if expr_type in (5, 6):
                            names, off = read_bitmap(data, off)
                            if self.mls and expr_type == 5 and attr >= 5:
                                names2, off = read_bitmap(data, off)
                                names3, off = read_bitmap(data, off)
            
            # Default type (v27+)
            if self.version >= 27:
                default_user, off = read_u32(data, off)
                default_role, off = read_u32(data, off)
                default_range, off = read_u32(data, off)
            if self.version >= 28:
                default_type, off = read_u32(data, off)
            
            self.classes[val] = name
            self.class_perms[val] = perms
        return off
    
    def _parse_roles(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)
            
            # Bounds (v24+)
            if self.version >= 24:
                bounds, off = read_u32(data, off)
            
            # Dominates bitmap
            dom_bits, off = read_bitmap(data, off)
            
            # Types bitmap
            type_bits, off = read_bitmap(data, off)
            
            self.roles[val] = name
        return off
    
    def _parse_types(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)
            primary, off = read_u32(data, off)
            
            # Flavor (attribute, alias, type)
            flavor, off = read_u32(data, off)
            
            # Bounds (v24+)
            if self.version >= 24:
                bounds, off = read_u32(data, off)
            
            self.types[val] = name
        return off
    
    def _skip_users(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)
            
            # Bounds (v24+)
            if self.version >= 24:
                bounds, off = read_u32(data, off)
            
            # Roles bitmap
            role_bits, off = read_bitmap(data, off)
            
            # MLS range
            if self.mls:
                off = self._skip_mls_range(data, off)
                off = self._skip_mls_range(data, off)
        return off
    
    def _skip_mls_range(self, data, off):
        # sens value
        sens, off = read_u32(data, off)
        # cats bitmap
        _, off = read_bitmap(data, off)
        return off
    
    def _skip_mls_level(self, data, off):
        return self._skip_mls_range(data, off)
    
    def _skip_bools(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)
            state, off = read_u32(data, off)
        return off
    
    def _skip_levels(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)
            # isalias
            isalias, off = read_u32(data, off)
            # level
            off = self._skip_mls_level(data, off)
        return off
    
    def _skip_cats(self, data, off, nel):
        for _ in range(nel):
            name, off = read_str(data, off)
            val, off = read_u32(data, off)
            isalias, off = read_u32(data, off)
        return off
    
    def _parse_avtab(self, data, off):
        """Parse the access vector table (allow, auditallow, etc.)"""
        nel, off = read_u32(data, off)
        print(f"\nAV table: {nel} entries")
        
        for i in range(nel):
            # AV table entry key
            source, off = read_u32(data, off)   # source type
            target, off = read_u32(data, off)   # target type
            tclass, off = read_u32(data, off)   # target class
            specified, off = read_u32(data, off) # specified (rule type)
            
            # specified bits:
            # 0x0001 = AVTAB_ALLOWED
            # 0x0002 = AVTAB_AUDITALLOW
            # 0x0004 = AVTAB_AUDITDENY
            # 0x0010 = AVTAB_TRANSITION
            # 0x0020 = AVTAB_MEMBER
            # 0x0040 = AVTAB_CHANGE
            # 0x0100 = AVTAB_XPERMS_ALLOWED (v30+)
            # 0x0200 = AVTAB_XPERMS_AUDITALLOW
            # 0x0400 = AVTAB_XPERMS_DONTAUDIT
            
            if specified & 0x0700:
                # Extended permissions (v30+)
                xperms_specified, off = read_u32(data, off)  # usually 1 (ioctl)
                driver, off = read_u32(data, off)
                # 8 u32 bitmap (256 bits)
                off += 32
            elif specified & 0x0070:
                # Type rule (transition/member/change) - datum is a type value
                datum, off = read_u32(data, off)
                if specified & 0x0010:  # AVTAB_TRANSITION
                    self.transitions.append((source, target, tclass, datum))
            else:
                # Access vector rule - datum is permissions bitmap
                perms_val, off = read_u32(data, off)
                if specified & 0x0001:  # AVTAB_ALLOWED
                    # Convert perms_val to set of permission bit positions
                    perm_bits = set()
                    for b in range(32):
                        if perms_val & (1 << b):
                            perm_bits.add(b + 1)  # 1-based
                    self.allows.append((source, target, tclass, perm_bits))
        
        return off
    
    def _find_permissive_types(self, data):
        """Search for permissive type bitmap in policy (v23+)."""
        # The permissive types map appears after conditional rules,
        # role transitions, etc. We search for a pattern:
        # It's an ebitmap, and we know most policies have 0 permissive types,
        # which means mapsize=0, highbit=0, count=0 (12 zero bytes)
        # For now, just report what we find in the type attributes
        pass
    
    def type_name(self, tid):
        return self.types.get(tid, f"type_{tid}")
    
    def class_name(self, cid):
        return self.classes.get(cid, f"class_{cid}")
    
    def perm_names(self, cid, perm_bits):
        """Convert permission bit positions to names for a given class."""
        perms = self.class_perms.get(cid, {})
        names = []
        for bit in sorted(perm_bits):
            name = perms.get(bit, f"perm_{bit}")
            names.append(name)
        return names
    
    def dump_rules_for_source(self, source_name):
        """Print all allow rules where source matches given type name."""
        src_ids = [tid for tid, name in self.types.items() if name == source_name]
        if not src_ids:
            print(f"  Type '{source_name}' not found in policy")
            return
        
        count = 0
        for src, tgt, cls, perms in self.allows:
            if src in src_ids:
                pnames = self.perm_names(cls, perms)
                print(f"  allow {self.type_name(src)} {self.type_name(tgt)}:{self.class_name(cls)} {{ {' '.join(pnames)} }};")
                count += 1
        print(f"  ({count} rules)")
        return count
    
    def dump_rules_for_target(self, target_name):
        """Print all allow rules where target matches given type name."""
        tgt_ids = [tid for tid, name in self.types.items() if name == target_name]
        if not tgt_ids:
            print(f"  Type '{target_name}' not found in policy")
            return
        
        count = 0
        for src, tgt, cls, perms in self.allows:
            if tgt in tgt_ids:
                pnames = self.perm_names(cls, perms)
                print(f"  allow {self.type_name(src)} {self.type_name(tgt)}:{self.class_name(cls)} {{ {' '.join(pnames)} }};")
                count += 1
        print(f"  ({count} rules)")
        return count
    
    def dump_transitions_for_source(self, source_name):
        """Print all type_transition rules from given source."""
        src_ids = [tid for tid, name in self.types.items() if name == source_name]
        if not src_ids:
            print(f"  Type '{source_name}' not found in policy")
            return
        
        count = 0
        for src, tgt, cls, default in self.transitions:
            if src in src_ids:
                print(f"  type_transition {self.type_name(src)} {self.type_name(tgt)}:{self.class_name(cls)} {self.type_name(default)};")
                count += 1
        print(f"  ({count} transitions)")
        return count
    
    def dump_transitions_to_target(self, target_name):
        """Print all type_transition rules that transition TO given type."""
        tgt_ids = [tid for tid, name in self.types.items() if name == target_name]
        if not tgt_ids:
            print(f"  Type '{target_name}' not found in policy")
            return
        
        count = 0
        for src, tgt, cls, default in self.transitions:
            if default in tgt_ids:
                print(f"  type_transition {self.type_name(src)} {self.type_name(tgt)}:{self.class_name(cls)} {self.type_name(default)};")
                count += 1
        print(f"  ({count} transitions)")
        return count
    
    def find_execute_rules(self, source_name):
        """Find all types that source can execute."""
        src_ids = [tid for tid, name in self.types.items() if name == source_name]
        if not src_ids:
            return []
        
        exec_targets = []
        for src, tgt, cls, perms in self.allows:
            if src in src_ids:
                pnames = set(self.perm_names(cls, perms))
                if pnames & {"execute", "execute_no_trans"}:
                    exec_targets.append((self.type_name(tgt), pnames))
        return exec_targets
    
    def find_entrypoints(self):
        """Find all entrypoint rules: allow domain file_type:file entrypoint."""
        entrypoints = {}
        for src, tgt, cls, perms in self.allows:
            pnames = set(self.perm_names(cls, perms))
            if "entrypoint" in pnames:
                domain = self.type_name(src)
                filetype = self.type_name(tgt)
                entrypoints.setdefault(domain, []).append(filetype)
        return entrypoints


def main():
    print("="*60)
    print("SELinux Policy Deep Analysis — SM-T377A")
    print("="*60)
    
    # Try libsepol first
    print("\n--- Trying libsepol ---")
    if try_libsepol():
        print("libsepol worked but we need setools for queries. Falling back to Python parser.")
    else:
        print("libsepol failed. Using pure Python parser.")
    
    # Parse with Python
    print("\n--- Pure Python binary parser ---")
    try:
        pdb = PolicyDB(POLICY_PATH)
    except Exception as e:
        print(f"Parser error at: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # ============================================================
    # ANALYSIS QUERIES
    # ============================================================
    
    # 1. Permissive types (check by name pattern)
    print("\n" + "="*60)
    print("1. TYPES CONTAINING 'permissive' or suspicious keywords")
    print("="*60)
    for tid, name in sorted(pdb.types.items(), key=lambda x: x[1]):
        if any(kw in name for kw in ["permissive", "unconfined", "su_", "root_", "rd_shell"]):
            print(f"  [{tid}] {name}")
    
    # 2. Type transitions FROM shell
    print("\n" + "="*60)
    print("2. TYPE TRANSITIONS FROM shell")
    print("="*60)
    pdb.dump_transitions_for_source("shell")
    
    # 3. Type transitions FROM untrusted_app
    print("\n" + "="*60)
    print("3. TYPE TRANSITIONS FROM untrusted_app")
    print("="*60)
    pdb.dump_transitions_for_source("untrusted_app")
    
    # 4. rd_shell_exec rules
    print("\n" + "="*60)
    print("4a. ALLOW RULES TARGETING rd_shell_exec")
    print("="*60)
    pdb.dump_rules_for_target("rd_shell_exec")
    
    print("\n" + "="*60)
    print("4b. TRANSITIONS TO rd_shell")
    print("="*60)
    pdb.dump_transitions_to_target("rd_shell")
    
    print("\n" + "="*60)
    print("4c. ALLOW RULES FROM rd_shell (what can it do?)")
    print("="*60)
    pdb.dump_rules_for_source("rd_shell")
    
    # 5. su_exec rules
    print("\n" + "="*60)
    print("5a. ALLOW RULES TARGETING su_exec")
    print("="*60)
    pdb.dump_rules_for_target("su_exec")
    
    print("\n" + "="*60)
    print("5b. TRANSITIONS TO su")
    print("="*60)
    pdb.dump_transitions_to_target("su")
    
    print("\n" + "="*60)
    print("5c. ALLOW RULES FROM su (what can it do?)")
    print("="*60)
    pdb.dump_rules_for_source("su")
    
    # 6. Shell execute permissions
    print("\n" + "="*60)
    print("6. SHELL EXECUTE TARGETS")
    print("="*60)
    exec_targets = pdb.find_execute_rules("shell")
    for tgt, perms in sorted(exec_targets):
        relevant = perms & {"execute", "execute_no_trans", "entrypoint"}
        print(f"  {tgt}: {', '.join(sorted(relevant))}")
    
    # 7. All entrypoints
    print("\n" + "="*60)
    print("7. DOMAIN ENTRYPOINTS")
    print("="*60)
    entrypoints = pdb.find_entrypoints()
    for domain in sorted(entrypoints):
        files = ", ".join(sorted(entrypoints[domain]))
        print(f"  {domain} <- {files}")
    
    # 8. Bluetooth domain privileges
    print("\n" + "="*60)
    print("8. BLUETOOTH DOMAIN — KEY PRIVILEGES")
    print("="*60)
    bt_count = 0
    for src, tgt, cls, perms in pdb.allows:
        if pdb.type_name(src) == "bluetooth":
            cname = pdb.class_name(cls)
            if cname in ("chr_file", "blk_file", "capability", "capability2",
                        "rawip_socket", "packet_socket", "netlink_socket",
                        "unix_stream_socket", "udp_socket", "tcp_socket",
                        "binder", "property_service", "service_manager"):
                pnames = pdb.perm_names(cls, perms)
                print(f"  allow bluetooth {pdb.type_name(tgt)}:{cname} {{ {' '.join(pnames)} }};")
                bt_count += 1
    print(f"  ({bt_count} rules)")
    
    # 9. Diagexe domain
    print("\n" + "="*60)
    print("9. DIAGEXE DOMAIN — ALL RULES")
    print("="*60)
    pdb.dump_rules_for_source("diagexe")
    
    # 10. Transitions FROM bluetooth
    print("\n" + "="*60)
    print("10. TYPE TRANSITIONS FROM bluetooth")
    print("="*60)
    pdb.dump_transitions_for_source("bluetooth")
    
    # 11. Who has write to security-critical types?
    print("\n" + "="*60)
    print("11. WRITE ACCESS TO kernel/security_file/selinuxfs")
    print("="*60)
    for src, tgt, cls, perms in pdb.allows:
        tname = pdb.type_name(tgt)
        if tname in ("kernel", "security_file", "selinuxfs"):
            pnames = set(pdb.perm_names(cls, perms))
            if pnames & {"write", "setattr", "relabelfrom", "relabelto"}:
                print(f"  allow {pdb.type_name(src)} {tname}:{pdb.class_name(cls)} {{ {' '.join(pnames)} }};")
    
    # 12. Samsung app domain capabilities
    print("\n" + "="*60)
    print("12. SAMSUNG APP DOMAIN CAPABILITIES")
    print("="*60)
    samsung_domains = ["sec_untrusted_app", "filtered_untrusted_app", "platform_app",
                       "carrier_app", "system_app", "knox_system_app", 
                       "sysaccess_platform_app", "policyloader_app"]
    for domain in samsung_domains:
        caps = []
        for src, tgt, cls, perms in pdb.allows:
            if pdb.type_name(src) == domain:
                cname = pdb.class_name(cls)
                if cname in ("capability", "capability2"):
                    pnames = pdb.perm_names(cls, perms)
                    caps.append(f"{cname}: {', '.join(pnames)}")
        if caps:
            print(f"  {domain}:")
            for c in caps:
                print(f"    {c}")
        else:
            print(f"  {domain}: (no capabilities)")
    
    # 13. Cross-reference: shell can execute X, X is entrypoint for domain Y
    print("\n" + "="*60)
    print("13. SHELL → EXECUTE → DOMAIN TRANSITION CHAINS")
    print("="*60)
    exec_types = set(tgt for tgt, _ in pdb.find_execute_rules("shell"))
    for domain, entry_files in entrypoints.items():
        overlap = exec_types & set(entry_files)
        if overlap and domain != "shell":
            # Check if there's a type_transition
            for src, tgt, cls, default in pdb.transitions:
                if pdb.type_name(src) == "shell" and pdb.type_name(tgt) in overlap:
                    print(f"  *** CHAIN: shell -execute-> {pdb.type_name(tgt)} -transition-> {pdb.type_name(default)} ***")
            # Even without transition, execute_no_trans means shell can run as itself
            for ft in overlap:
                print(f"  shell can execute {ft} (entrypoint for {domain})")
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
