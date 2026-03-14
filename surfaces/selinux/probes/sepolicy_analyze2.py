#!/usr/bin/env python3
import sys
sys.path.insert(0, "/tmp/setools_install/usr/lib/python3/dist-packages")
try:
    import setools
    print("setools loaded successfully")
    p = setools.SELinuxPolicy("/mnt/c/InfoSec/android-redteam/work/sepolicy")
    print(f"Policy version: {p.version}")
    
    # Find all type_transition rules from shell
    print("\n=== Type transitions FROM shell ===")
    count = 0
    for rule in p.terules():
        if hasattr(rule, 'source') and str(rule.source) == "shell":
            if rule.ruletype.name == "type_transition":
                print(f"  {rule}")
                count += 1
    print(f"Total: {count}")
    
    # Find all allow rules for shell domain
    print("\n=== Allow rules for shell (exec/execute) ===")
    count = 0
    for rule in p.terules():
        if hasattr(rule, 'source') and str(rule.source) == "shell":
            perms = set(str(p) for p in rule.perms) if hasattr(rule, 'perms') else set()
            if "execute" in perms or "execute_no_trans" in perms or "entrypoint" in perms:
                print(f"  {rule}")
                count += 1
    print(f"Total: {count}")
    
    # Find su_exec rules
    print("\n=== Rules involving su_exec ===")
    for rule in p.terules():
        s = str(rule)
        if "su_exec" in s:
            print(f"  {rule}")
    
    # Find permissive domains
    print("\n=== Permissive types ===")
    for t in p.types():
        if t.ispermissive:
            print(f"  {t}")
            
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()