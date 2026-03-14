#!/usr/bin/env python3
import sys
sys.path.insert(0, "/tmp/setools_ext/usr/lib/python3/dist-packages")
import setools
print("setools loaded")
p = setools.SELinuxPolicy("/mnt/c/InfoSec/android-redteam/work/sepolicy")
print(f"Policy version: {p.version}")
print(f"Types: {len(list(p.types()))}")

# Shell domain transitions
print("\n=== Type transitions FROM shell ===")
for rule in p.terules():
    if hasattr(rule, "source") and str(rule.source) == "shell":
        if rule.ruletype.name == "type_transition":
            print(f"  {rule}")

# Shell allow rules with execute
print("\n=== Shell execute permissions ===")
for rule in p.terules():
    if hasattr(rule, "source") and str(rule.source) == "shell":
        if hasattr(rule, "perms"):
            perms = set(str(pp) for pp in rule.perms)
            if perms & {"execute", "execute_no_trans", "entrypoint"}:
                print(f"  {rule}")

# su_exec rules
print("\n=== su_exec rules ===")
for rule in p.terules():
    s = str(rule)
    if "su_exec" in s:
        print(f"  {rule}")

# Permissive types
print("\n=== Permissive types ===")
for t in p.types():
    if t.ispermissive:
        print(f"  {t}")

# Domain transitions TO interesting types
print("\n=== Transitions to root/system domains ===")
for rule in p.terules():
    if rule.ruletype.name == "type_transition":
        target = str(rule.default) if hasattr(rule, "default") else ""
        if target in ["su", "init", "kernel", "system_server", "vold", "installd"]:
            print(f"  {rule}")