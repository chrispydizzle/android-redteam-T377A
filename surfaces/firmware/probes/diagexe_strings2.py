import re
with open('C:/InfoSec/android-redteam/work/diagexe_bin', 'rb') as f:
    data = f.read()
for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
    s = m.group().decode()
    if any(k in s.lower() for k in ['crc', 'check', 'sum', 'hash', 'verify', 'valid', 'hdlc', '7d', 'escape', 'sdm', 'smd', 'xfer', 'max', 'buf_size', 'buf_max', 'flag']):
        print(f'0x{m.start():06x}: {s}')
