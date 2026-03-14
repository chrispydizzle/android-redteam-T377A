#!/usr/bin/env python3
"""Targeted analysis of runas domain and remaining questions."""
import struct

data = open('/tmp/sepolicy', 'rb').read()
type_names = {}
with open('/tmp/type_names.txt') as f:
    for line in f:
        parts = line.strip().split('\t')
        type_names[int(parts[0])] = parts[1]
class_names = {}
with open('/tmp/class_names.txt') as f:
    for line in f:
        parts = line.strip().split('\t')
        class_names[int(parts[0])] = parts[1]
name_to_id = {v: k for k, v in type_names.items()}

# Build entries
pos = 162700
entries = []
for i in range(4822):
    s, t, c, sp = struct.unpack_from('<HHHH', data, pos)
    v = struct.unpack_from('<I', data, pos + 8)[0]
    pos += 12
    entries.append((s, t, c, sp & 0x7FFF, v))

pos = 256952
ntypes = max(type_names.keys())
nclasses = max(class_names.keys())
VALID = {1, 2, 4, 0x10, 0x20, 0x40, 0x80}

while pos + 12 <= len(data):
    s, t, c, sp = struct.unpack_from('<HHHH', data, pos)
    v = struct.unpack_from('<I', data, pos + 8)[0]
    sc = sp & 0x7FFF
    if 1 <= s <= ntypes and 1 <= t <= ntypes and 1 <= c <= nclasses and sc in VALID:
        entries.append((s, t, c, sc, v))
        pos += 12
    elif sc & 0x700:
        pos += 42
    else:
        np = pos + 42
        if np + 12 <= len(data):
            s2, t2, c2, sp2 = struct.unpack_from('<HHHH', data, np)
            if 1 <= s2 <= ntypes and 1 <= t2 <= ntypes and 1 <= c2 <= nclasses and (sp2 & 0x7FFF) in VALID:
                pos = np
                continue
        np = pos + 12
        if np + 12 <= len(data):
            s2, t2, c2, sp2 = struct.unpack_from('<HHHH', data, np)
            if 1 <= s2 <= ntypes and 1 <= t2 <= ntypes and 1 <= c2 <= nclasses and (sp2 & 0x7FFF) in VALID:
                pos = np
                continue
        break

print("Total entries:", len(entries))

def tn(v):
    return type_names.get(v, "type_%d" % v)

def cn(v):
    return class_names.get(v, "class_%d" % v)

runas_id = name_to_id.get('runas')
runas_exec_id = name_to_id.get('runas_exec')
shell_id = name_to_id.get('shell')

print("\nrunas ID:", runas_id)
print("runas_exec ID:", runas_exec_id)
print("shell ID:", shell_id)

if runas_id:
    print("\n=== ALL RULES FROM runas ===")
    for e in entries:
        if e[0] == runas_id:
            spec = {1: 'allow', 2: 'auditallow', 4: 'auditdeny', 0x10: 'transition', 0x80: 'neverallow'}.get(e[3], hex(e[3]))
            print("  %s runas %s:%s 0x%08x" % (spec, tn(e[1]), cn(e[2]), e[4]))

    print("\n=== ALL RULES TO runas (as target) ===")
    for e in entries:
        if e[1] == runas_id:
            spec = {1: 'allow', 2: 'auditallow', 4: 'auditdeny', 0x10: 'transition', 0x80: 'neverallow'}.get(e[3], hex(e[3]))
            print("  %s %s runas:%s 0x%08x" % (spec, tn(e[0]), cn(e[2]), e[4]))

    print("\n=== TRANSITIONS INVOLVING runas ===")
    for e in entries:
        if e[3] == 0x10:
            if e[0] == runas_id or e[4] == runas_id:
                print("  type_transition %s %s:%s %s" % (tn(e[0]), tn(e[1]), cn(e[2]), tn(e[4])))

if runas_exec_id:
    print("\n=== ALL RULES ON runas_exec ===")
    for e in entries:
        if e[1] == runas_exec_id or e[0] == runas_exec_id:
            spec = {1: 'allow', 4: 'auditdeny', 0x10: 'transition'}.get(e[3], hex(e[3]))
            src_name = tn(e[0])
            tgt_name = tn(e[1])
            print("  %s %s %s:%s 0x%08x" % (spec, src_name, tgt_name, cn(e[2]), e[4]))

# Check all domains accessible from shell via multi-hop
print("\n=== MULTI-HOP DOMAIN REACHABILITY FROM SHELL ===")
transitions = [(e[0], e[4]) for e in entries if e[3] == 0x10 and cn(e[2]) == 'process']
# BFS from shell
reachable = set()
queue = [shell_id] if shell_id else []
visited = set()
while queue:
    current = queue.pop(0)
    if current in visited:
        continue
    visited.add(current)
    for src, dst in transitions:
        if src == current and dst not in visited:
            reachable.add(dst)
            queue.append(dst)
            print("  %s -> %s" % (tn(current), tn(dst)))

if not reachable:
    print("  Only: shell -> runas (if runas_exec is executable)")

# Check what at_distributor can do (it can access su_exec)
at_dist_id = name_to_id.get('at_distributor')
if at_dist_id:
    print("\n=== at_distributor KEY RULES ===")
    for e in entries:
        if e[0] == at_dist_id and e[3] == 1:
            c = cn(e[2])
            if any(x in c for x in ['capability', 'process', 'chr_file', 'socket']):
                print("  allow at_distributor %s:%s 0x%08x" % (tn(e[1]), c, e[4]))

# Check carrier_app - highest rule count Samsung domain
carrier_id = name_to_id.get('carrier_app')
if carrier_id:
    print("\n=== carrier_app UNIQUE RULES (vs untrusted_app) ===")
    ua_id = name_to_id.get('untrusted_app')
    ua_targets = set()
    if ua_id:
        for e in entries:
            if e[0] == ua_id and e[3] == 1:
                ua_targets.add((e[1], e[2]))
    for e in entries:
        if e[0] == carrier_id and e[3] == 1:
            if (e[1], e[2]) not in ua_targets:
                print("  allow carrier_app %s:%s 0x%08x" % (tn(e[1]), cn(e[2]), e[4]))

print("\n=== DONE ===")
