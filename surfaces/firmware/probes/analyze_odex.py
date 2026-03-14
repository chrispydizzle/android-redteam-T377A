import re

with open('work/APNWidgetBaseRoot_ATT.odex', 'rb') as f:
    data = f.read()

# Extract printable strings >= 4 chars
strings = re.findall(b'[\x20-\x7e]{4,}', data)
seen = set()
keywords = ['smartcom', 'root', 'service', 'install', 'exec', 'command', 'shell',
            'system', 'pm ', 'su ', 'chmod', 'write', 'apn', 'check', 'app', 
            'intent', 'broadcast', 'bind', 'package', 'content', 'provider',
            'method', 'invoke', 'runtime', 'process', 'start', 'run',
            'class', 'dex', 'load', 'path', 'file', 'data', 'send']

for s in strings:
    t = s.decode('ascii', errors='replace')
    if t not in seen:
        seen.add(t)
        if any(k in t.lower() for k in keywords):
            print(t)

print("\n=== ALL UNIQUE STRINGS (sorted) ===")
all_strs = sorted(set(s.decode('ascii','replace') for s in strings if len(s) >= 8))
for s in all_strs:
    print(s)
