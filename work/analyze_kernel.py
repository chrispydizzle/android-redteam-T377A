import struct

d = open('/tmp/vmlinux', 'rb').read()
print(f'Kernel size: {len(d)} bytes')

# Find "binder_poll" string 
idx = d.find(b'binder_poll\x00')
print(f'binder_poll string at offset {idx:#x} ({idx})')

# Find "binder_free_thread" string
idx2 = d.find(b'binder_free_thread\x00')
print(f'binder_free_thread string at offset {idx2:#x} ({idx2})')

# Find references to the binder_poll string address
# The kernel text starts at virtual 0xC0008000
# String section is typically after code
# Let me search for the actual function by looking for poll_wait calls

# On ARM32, binder_poll would be somewhere in the .text section
# Search for patterns near known binder code
# The function names are stored for kallsyms at specific offsets

# Search for "proc_wait\x00" or "thread->wait" patterns
for needle in [b'wait_for_proc_work', b'proc->wait', b'thread->wait']:
    idx3 = d.find(needle)
    if idx3 >= 0: print(f'{needle}: at {idx3:#x}')
    else: print(f'{needle}: NOT FOUND')

# Look for Samsung binder modifications 
for needle in [b'binder.proc_no_lock', b'binder_proc_no_lock', b'no_lock']:
    idx4 = d.find(needle)
    if idx4 >= 0: print(f'{needle}: at {idx4:#x}')

# Search for the specific binder_poll debug format
# Standard kernel uses: "%d:%d poll\n"
for needle in [b'%d:%d poll', b'poll\n']:
    idx5 = d.find(needle)
    if idx5 >= 0:
        ctx = d[max(0,idx5-20):idx5+40]
        print(f'{needle}: at {idx5:#x} context: {ctx}')

# Also check if there's a binder_poll_v2 or modified version
for needle in [b'binder_poll_v', b'poll_wait_for_proc', b'skip_poll']:
    idx6 = d.find(needle)
    if idx6 >= 0: print(f'{needle}: at {idx6:#x}')
