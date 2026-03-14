#!/usr/bin/env python3
"""SELinux policy deep analysis for SM-T377A privilege escalation research."""
import sys, os

# Add setools from user-extracted .deb
sys.path.insert(0, os.path.expanduser("~/setools_install/usr/lib/python3/dist-packages"))

import setools

POLICY_PATH = "/mnt/c/InfoSec/android-redteam/work/sepolicy"

print(f"Loading policy: {POLICY_PATH}")
p = setools.SELinuxPolicy(POLICY_PATH)
print(f"Policy version: {p.version}")
print(f"Types: {len(list(p.types()))}")
print(f"Roles: {len(list(p.roles()))}")
print(f"Booleans: {len(list(p.bools()))}")

# ============================================================
# 1. PERMISSIVE DOMAINS (instant win if reachable)
# ============================================================
print("\n" + "="*60)
print("1. PERMISSIVE DOMAINS")
print("="*60)
permissive_count = 0
for t in p.types():
    if t.ispermissive:
        print(f"  PERMISSIVE: {t}")
        permissive_count += 1
if permissive_count == 0:
    print("  (none found)")
print(f"  Total: {permissive_count}")

# ============================================================
# 2. TYPE TRANSITIONS FROM shell
# ============================================================
print("\n" + "="*60)
print("2. TYPE TRANSITIONS FROM shell")
print("="*60)
count = 0
for rule in p.terules():
    if hasattr(rule, 'source') and str(rule.source) == "shell":
        if hasattr(rule, 'ruletype') and rule.ruletype.name == "type_transition":
            print(f"  {rule}")
            count += 1
print(f"  Total: {count}")

# ============================================================
# 3. TYPE TRANSITIONS FROM untrusted_app
# ============================================================
print("\n" + "="*60)
print("3. TYPE TRANSITIONS FROM untrusted_app")
print("="*60)
count = 0
for rule in p.terules():
    if hasattr(rule, 'source') and str(rule.source) == "untrusted_app":
        if hasattr(rule, 'ruletype') and rule.ruletype.name == "type_transition":
            print(f"  {rule}")
            count += 1
print(f"  Total: {count}")

# ============================================================
# 4. SHELL EXECUTE PERMISSIONS (what can shell execute?)
# ============================================================
print("\n" + "="*60)
print("4. SHELL EXECUTE PERMISSIONS")
print("="*60)
count = 0
for rule in p.terules():
    if hasattr(rule, 'source') and str(rule.source) == "shell":
        if hasattr(rule, 'perms'):
            perms = set(str(pp) for pp in rule.perms)
            if perms & {"execute", "execute_no_trans", "entrypoint"}:
                print(f"  {rule}")
                count += 1
print(f"  Total: {count}")

# ============================================================
# 5. rd_shell_exec RULES (root debug shell)
# ============================================================
print("\n" + "="*60)
print("5. rd_shell_exec / rd_shell RULES")
print("="*60)
count = 0
for rule in p.terules():
    s = str(rule)
    if "rd_shell" in s:
        print(f"  {rule}")
        count += 1
print(f"  Total: {count}")

# ============================================================
# 6. su_exec / su RULES
# ============================================================
print("\n" + "="*60)
print("6. su_exec / su RULES")
print("="*60)
count = 0
for rule in p.terules():
    s = str(rule)
    if "su_exec" in s or ((" su " in f" {s} ") and "source" not in s):
        # Match su as a type, not as substring of other words
        src = str(rule.source) if hasattr(rule, 'source') else ""
        tgt = str(rule.target) if hasattr(rule, 'target') else ""
        dflt = str(rule.default) if hasattr(rule, 'default') else ""
        if src == "su" or tgt == "su" or dflt == "su" or "su_exec" in s:
            print(f"  {rule}")
            count += 1
print(f"  Total: {count}")

# ============================================================
# 7. BLUETOOTH DOMAIN — chr_file, capabilities, sockets
# ============================================================
print("\n" + "="*60)
print("7. BLUETOOTH DOMAIN PRIVILEGES")
print("="*60)
count = 0
for rule in p.terules():
    if hasattr(rule, 'source') and str(rule.source) == "bluetooth":
        if hasattr(rule, 'perms'):
            tclass = str(rule.tclass)
            if tclass in ("chr_file", "blk_file", "capability", "capability2",
                          "rawip_socket", "packet_socket", "netlink_socket",
                          "unix_stream_socket", "unix_dgram_socket", "socket",
                          "udp_socket", "tcp_socket"):
                print(f"  {rule}")
                count += 1
print(f"  Total: {count}")

# ============================================================
# 8. DIAGEXE DOMAIN
# ============================================================
print("\n" + "="*60)
print("8. DIAGEXE DOMAIN PRIVILEGES")
print("="*60)
count = 0
for rule in p.terules():
    if hasattr(rule, 'source') and str(rule.source) == "diagexe":
        if hasattr(rule, 'perms'):
            print(f"  {rule}")
            count += 1
print(f"  Total: {count}")

# ============================================================
# 9. WHO CAN WRITE TO KERNEL/SECURITY TYPES?
# ============================================================
print("\n" + "="*60)
print("9. WRITE ACCESS TO KERNEL/SECURITY TYPES")
print("="*60)
for rule in p.terules():
    if hasattr(rule, 'target') and hasattr(rule, 'perms'):
        tgt = str(rule.target)
        perms = set(str(pp) for pp in rule.perms)
        if tgt in ("kernel", "security_file", "selinuxfs") and "write" in perms:
            print(f"  {rule}")

# ============================================================
# 10. ENTRYPOINT RULES (what file types are entrypoints for domains?)
# ============================================================
print("\n" + "="*60)
print("10. DOMAIN ENTRYPOINTS")
print("="*60)
entrypoints = {}
for rule in p.terules():
    if hasattr(rule, 'perms'):
        perms = set(str(pp) for pp in rule.perms)
        if "entrypoint" in perms:
            src = str(rule.source)
            tgt = str(rule.target)
            entrypoints.setdefault(src, []).append(tgt)
for domain in sorted(entrypoints):
    files = ", ".join(sorted(entrypoints[domain]))
    print(f"  {domain} <- {files}")

# ============================================================
# 11. ALL TYPES with interesting names
# ============================================================
print("\n" + "="*60)
print("11. INTERESTING TYPES")
print("="*60)
interesting_kw = ["root", "su", "debug", "engineer", "factory", "recovery",
                  "permissive", "unconfined", "rd_shell", "rdsh"]
for t in sorted(p.types(), key=str):
    name = str(t)
    for kw in interesting_kw:
        if kw in name:
            attrs = ", ".join(str(a) for a in t.attributes())
            print(f"  {name} (attrs: {attrs})")
            break

# ============================================================
# 12. SAMSUNG-SPECIFIC APP DOMAINS
# ============================================================
print("\n" + "="*60)
print("12. SAMSUNG APP DOMAIN CAPABILITIES")
print("="*60)
samsung_domains = ["sec_untrusted_app", "filtered_untrusted_app", "platform_app",
                   "carrier_app", "mrst_plugin_app", "knox_system_app",
                   "sysaccess_platform_app", "system_app", "policyloader_app"]
for domain in samsung_domains:
    caps = []
    for rule in p.terules():
        if hasattr(rule, 'source') and str(rule.source) == domain:
            if hasattr(rule, 'perms'):
                tclass = str(rule.tclass)
                if tclass in ("capability", "capability2"):
                    perms = ", ".join(str(pp) for pp in rule.perms)
                    caps.append(f"{tclass}: {perms}")
    if caps:
        print(f"  {domain}:")
        for c in caps:
            print(f"    {c}")
    else:
        print(f"  {domain}: (no capabilities)")

print("\n" + "="*60)
print("ANALYSIS COMPLETE")
print("="*60)
