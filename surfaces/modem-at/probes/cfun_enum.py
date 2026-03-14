"""
Shannon 308 CFUN Mode Enumerator + AT Command Delta Scanner

Probes AT+CFUN modes 4-12 (engineering/test modes) on the Samsung SM-T377A.
For each mode:
  1. Switch to the mode
  2. Check AT+CLAC for new/removed commands
  3. Re-test previously blocked commands
  4. Log all responses
  5. Return to CFUN=0 (offline) for safety

SAFETY:
  - Does NOT test CFUN=1 (full radio, would connect to AT&T network)
  - Returns to CFUN=0 after each probe
  - 3-second delay between mode switches
  - Timeout on all reads
"""

import serial
import time
import json
import sys
import os
from datetime import datetime

PORT = 'COM11'
BAUD = 115200
TIMEOUT = 3
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'work', 'logs')

def send_at(ser, cmd, timeout=3):
    """Send AT command and return response."""
    ser.reset_input_buffer()
    ser.write(f'{cmd}\r\n'.encode())
    time.sleep(0.3)
    
    # Read with timeout
    ser.timeout = timeout
    resp = b''
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = ser.read(1024)
        if chunk:
            resp += chunk
        elif resp:
            break
        time.sleep(0.1)
    
    text = resp.decode('ascii', errors='replace').strip()
    # Remove echo of command
    lines = text.split('\n')
    filtered = [l.strip() for l in lines if l.strip() and not l.strip().startswith(cmd.split('=')[0].split('?')[0][:8])]
    return '\n'.join(filtered)

def get_clac(ser):
    """Get full AT command list."""
    resp = send_at(ser, 'AT+CLAC', timeout=5)
    commands = set()
    for line in resp.split('\n'):
        line = line.strip()
        if line.startswith('+CLAC:'):
            line = line[6:].strip()
        if line.startswith('AT') and line != 'OK':
            commands.add(line)
        elif line.startswith('+') and line != 'OK':
            commands.add(line)
    return commands

# Previously blocked commands to re-test in each mode
RETEST_COMMANDS = [
    'AT%SYSLOG',
    'AT%ITEST',
    'AT%NVREAD',
    'AT%NVWRITE',
    'AT%KEYSTRING',
    'AT+SSMCMD',
    'AT+SECBOOT',
    'AT+UNLOCKSIM',
    'AT+ENGMODE',
    'AT+DEBUGMODE',
    'AT%FACTLOCK',
    'AT%DMROPEN',
    'AT%DMRCLOSE',
    'AT+DUMPCTRL',
    'AT+VERSNAME',
    'AT+SIMSLOT',
    'AT$QCNVR',
    'AT%CTZR',
    'AT+XGENDATA',
    'AT+DEVCONINFO',
]

def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    logfile = os.path.join(LOG_DIR, f'cfun_enum_{timestamp}.json')
    
    print(f"=== Shannon 308 CFUN Mode Enumerator ===")
    print(f"Port: {PORT} @ {BAUD} baud")
    print(f"Log: {logfile}")
    print()
    
    ser = serial.Serial(PORT, BAUD, timeout=TIMEOUT)
    time.sleep(0.5)
    
    # Verify connection
    resp = send_at(ser, 'AT')
    if 'OK' not in resp:
        print(f"ERROR: No AT response. Got: [{resp}]")
        ser.close()
        sys.exit(1)
    print("[+] Modem responsive")
    
    # Get baseline (CFUN=0)
    print("[*] Getting baseline AT command list (CFUN=0)...")
    baseline_cmds = get_clac(ser)
    print(f"    Baseline: {len(baseline_cmds)} commands")
    
    # Get baseline responses for blocked commands
    print("[*] Testing blocked commands at baseline...")
    baseline_blocked = {}
    for cmd in RETEST_COMMANDS:
        resp = send_at(ser, cmd)
        baseline_blocked[cmd] = resp
        status = 'OK' if 'OK' in resp else 'ERROR' if 'ERROR' in resp else '???'
        print(f"    {cmd}: {status}")
    
    results = {
        'timestamp': timestamp,
        'port': PORT,
        'baseline_cmd_count': len(baseline_cmds),
        'baseline_cmds': sorted(list(baseline_cmds)),
        'baseline_blocked': baseline_blocked,
        'modes': {}
    }
    
    # Probe each CFUN mode
    modes_to_test = [4, 5, 6, 7, 8, 9, 10, 11, 12]
    
    for mode in modes_to_test:
        print(f"\n{'='*50}")
        print(f"[*] Testing CFUN={mode}...")
        print(f"{'='*50}")
        
        mode_result = {
            'cfun_response': '',
            'new_commands': [],
            'removed_commands': [],
            'cmd_count': 0,
            'blocked_changes': {},
            'errors': [],
        }
        
        # Switch mode
        resp = send_at(ser, f'AT+CFUN={mode}', timeout=5)
        mode_result['cfun_response'] = resp
        print(f"    CFUN={mode} response: {resp}")
        
        if 'ERROR' in resp:
            print(f"    [-] Mode {mode} rejected")
            mode_result['errors'].append(f'CFUN={mode} returned ERROR')
            results['modes'][str(mode)] = mode_result
            continue
        
        # Wait for mode to settle
        time.sleep(3)
        
        # Verify mode actually changed
        cfun_check = send_at(ser, 'AT+CFUN?')
        mode_result['cfun_verify'] = cfun_check
        print(f"    CFUN? verify: {cfun_check}")
        
        # Get command list in this mode
        print(f"    Getting AT command list...")
        mode_cmds = get_clac(ser)
        mode_result['cmd_count'] = len(mode_cmds)
        
        # Delta analysis
        new_cmds = mode_cmds - baseline_cmds
        removed_cmds = baseline_cmds - mode_cmds
        mode_result['new_commands'] = sorted(list(new_cmds))
        mode_result['removed_commands'] = sorted(list(removed_cmds))
        
        if new_cmds:
            print(f"    [!] NEW COMMANDS ({len(new_cmds)}):")
            for cmd in sorted(new_cmds):
                print(f"        + {cmd}")
        if removed_cmds:
            print(f"    [-] REMOVED COMMANDS ({len(removed_cmds)}):")
            for cmd in sorted(removed_cmds):
                print(f"        - {cmd}")
        if not new_cmds and not removed_cmds:
            print(f"    [=] No command changes (same {len(mode_cmds)} commands)")
        
        # Re-test blocked commands
        print(f"    Re-testing blocked commands...")
        for cmd in RETEST_COMMANDS:
            resp = send_at(ser, cmd)
            old_status = 'OK' if 'OK' in baseline_blocked[cmd] else 'ERROR'
            new_status = 'OK' if 'OK' in resp else 'ERROR'
            
            if new_status != old_status:
                mode_result['blocked_changes'][cmd] = {
                    'old': baseline_blocked[cmd][:100],
                    'new': resp[:200],
                    'change': f'{old_status} -> {new_status}'
                }
                print(f"    [!!!] {cmd}: {old_status} -> {new_status}")
                print(f"         Response: {resp[:120]}")
        
        # Test any new commands discovered
        for cmd in sorted(new_cmds)[:10]:  # Limit to 10 to avoid flooding
            test_cmd = cmd.split('=')[0] if '=' in cmd else cmd
            resp = send_at(ser, test_cmd)
            mode_result[f'new_cmd_test_{test_cmd}'] = resp
            print(f"    Testing new {test_cmd}: {resp[:80]}")
        
        results['modes'][str(mode)] = mode_result
        
        # Return to CFUN=0 for safety
        print(f"    Returning to CFUN=0...")
        send_at(ser, 'AT+CFUN=0', timeout=5)
        time.sleep(2)
        
        # Verify return
        check = send_at(ser, 'AT+CFUN?')
        if '+CFUN: 0' in check:
            print(f"    [+] Safely back to CFUN=0")
        else:
            print(f"    [!] WARNING: CFUN check: {check}")
    
    # Save results
    with open(logfile, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Summary
    print(f"\n{'='*50}")
    print(f"=== SUMMARY ===")
    print(f"{'='*50}")
    print(f"Baseline commands: {len(baseline_cmds)}")
    for mode in modes_to_test:
        m = results['modes'].get(str(mode), {})
        new = len(m.get('new_commands', []))
        removed = len(m.get('removed_commands', []))
        changes = len(m.get('blocked_changes', {}))
        errors = len(m.get('errors', []))
        status = 'ERROR' if errors else f'+{new}/-{removed} cmds, {changes} unblocked'
        print(f"  CFUN={mode}: {status}")
    
    print(f"\nResults saved to: {logfile}")
    ser.close()

if __name__ == '__main__':
    main()
