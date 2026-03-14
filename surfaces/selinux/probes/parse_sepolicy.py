import re, struct

with open("work/sepolicy", "rb") as f:
    data = f.read()

print(f"Policy size: {len(data)} bytes")

# Find all readable strings (type/attribute names)
strings = set()
for m in re.finditer(rb'[a-z_][a-z0-9_]{2,50}', data):
    strings.add(m.group().decode())

# Look for interesting types
print("\n=== Types containing interesting keywords ===")
for kw in ["shell", "untrusted", "su_", "root", "system_server", "init", "kernel",
           "permissive", "recovery", "install", "debug", "engineer", "factory",
           "radio", "diag", "rild", "drparser", "smartcom", "samsung", "knox",
           "selinux", "dalvik", "zygote", "adbd"]:
    matches = sorted(s for s in strings if kw in s)
    if matches:
        print(f"  {kw}: {', '.join(matches[:10])}")

print(f"\nTotal unique strings: {len(strings)}")
# Print all types that look like domain names (heuristic)
domains = sorted(s for s in strings if not s.startswith("_") and len(s) > 3 and s.endswith(("_t", "_type")))
if domains:
    print(f"\nPossible types (*_t/*_type): {len(domains)}")
    for d in domains:
        print(f"  {d}")
