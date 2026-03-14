#!/usr/bin/env python3
"""Auto-pair with Samsung tablet using pexpect for interactive bluetoothctl."""
import subprocess, time, sys, os

TARGET = '02:00:00:00:00:21'

try:
    import pexpect
except ImportError:
    print("Installing pexpect...")
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pexpect'], capture_output=True)
    import pexpect

print(f"[*] Starting bluetoothctl for pairing with {TARGET}")

child = pexpect.spawn('bluetoothctl', timeout=60, encoding='utf-8')
child.logfile = sys.stdout

# Setup agent
child.sendline('agent on')
time.sleep(0.5)
child.sendline('default-agent')
time.sleep(0.5)

# Pair
print(f"\n[*] Initiating pairing... TAP PAIR ON TABLET NOW!")
child.sendline(f'pair {TARGET}')

# Wait for passkey prompt and auto-confirm
try:
    idx = child.expect(['Confirm passkey', 'Failed to pair', 'Paired: yes', pexpect.TIMEOUT], timeout=30)
    if idx == 0:
        print("\n[+] Passkey prompt received! Confirming YES...")
        child.sendline('yes')
        # Wait for result
        idx2 = child.expect(['Pairing successful', 'Failed to pair', 'auth failed', pexpect.TIMEOUT], timeout=20)
        if idx2 == 0:
            print("\n[+] *** PAIRING SUCCESSFUL! ***")
        else:
            print(f"\n[-] Pairing result: idx={idx2}")
    elif idx == 1:
        print("\n[-] Pairing failed immediately")
    elif idx == 2:
        print("\n[+] Already paired!")
    else:
        print("\n[-] Timeout waiting for passkey")
except Exception as e:
    print(f"\n[-] Error: {e}")

# Check result
time.sleep(2)
child.sendline(f'info {TARGET}')
time.sleep(2)

child.sendline('quit')
child.close()
