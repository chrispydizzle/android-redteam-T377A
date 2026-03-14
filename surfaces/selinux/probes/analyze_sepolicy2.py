import struct

data = open(r'C:\InfoSec\android-redteam\work\sepolicy', 'rb').read()

# Search for su-related types
su_terms = [b'su_exec', b'su_domain', b'su ', b'superuser', b'root_exec', 
            b'permissive', b'setenforce', b'disable', b'unconfined']
for term in su_terms:
    positions = []
    start = 0
    while True:
        pos = data.find(term, start)
        if pos == -1:
            break
        s = max(0, pos - 20)
        e = min(len(data), pos + len(term) + 20)
        while s > 0 and data[s-1] != 0:
            s -= 1
        while e < len(data) and data[e] != 0:
            e += 1
        context = data[s:e].decode('ascii', errors='replace')
        if context not in [c for _, c in positions]:
            positions.append((pos, context))
        start = pos + 1
    if positions:
        unique = set(c for _, c in positions)
        print(f'{term.decode()}: {len(unique)} strings')
        for s in sorted(unique)[:10]:
            print(f'  {s}')

# Look for specific interesting types
more_terms = [b'execute_no_trans', b'domain_trans', b'type_transition',
              b'engineer', b'debug', b'neverallow', b'permissive_domain',
              b'unconfined', b'mlstrustedsubject']
for term in more_terms:
    count = data.count(term)
    if count > 0:
        print(f'\n{term.decode()}: found {count} times')

# Check for any types containing 'exec' that might be transitioned to
exec_terms = set()
start = 0
while True:
    pos = data.find(b'_exec', start)
    if pos == -1:
        break
    s = pos
    while s > 0 and data[s-1] != 0 and data[s-1] != ord('\n'):
        s -= 1
    e = pos + 5
    while e < len(data) and data[e] != 0:
        e += 1
    name = data[s:e].decode('ascii', errors='replace')
    if len(name) < 50:
        exec_terms.add(name)
    start = pos + 1

print(f'\nAll _exec types ({len(exec_terms)}):')
for t in sorted(exec_terms):
    print(f'  {t}')
