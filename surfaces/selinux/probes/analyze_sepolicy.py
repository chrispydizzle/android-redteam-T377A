import struct

data = open(r'C:\InfoSec\android-redteam\work\sepolicy', 'rb').read()
print(f'Policy size: {len(data)} bytes')

magic = struct.unpack('>I', data[:4])[0]
print(f'Magic: 0x{magic:08x}')

interesting = [b'shell', b'untrusted_app', b'system_server', b'init', b'kernel',
               b'su_exec', b'permissive', b'bluetooth', b'radio', b'mobicore',
               b'engineering', b'factory', b'recovery', b'adbd']

for term in interesting:
    positions = []
    start = 0
    while True:
        pos = data.find(term, start)
        if pos == -1:
            break
        s = pos
        while s > 0 and data[s-1] != 0:
            s -= 1
        e = pos
        while e < len(data) and data[e] != 0:
            e += 1
        context = data[s:e].decode('ascii', errors='replace')
        if context not in [c for _, c in positions]:
            positions.append((pos, context))
        start = pos + 1
    if positions:
        unique = set(c for _, c in positions)
        print(f'\n{term.decode()}: {len(unique)} unique strings')
        for s in sorted(unique)[:15]:
            print(f'  {s}')
