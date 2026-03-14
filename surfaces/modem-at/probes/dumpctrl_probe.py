"""
Shannon 308 DUMPCTRL Deep Probe + CP Dump Investigation

AT+DUMPCTRL consistently returns OK. This script:
1. Probes DUMPCTRL with various arguments/subcommands
2. Checks for CP crash dump files in /data/log/ and /data/cp_log/
3. Tests related dump commands (AT+XDUMPMEM, AT%MEMDUMP, etc)
4. Probes CFUN=9 (CLPC OFF) engineering implications
5. Tests modem NV access variants

SAFETY: All read-only probes. No radio activation (CFUN=1 avoided).
"""

import serial
import time
import sys
import os
import subprocess

PORT = 'COM11'
BAUD = 115200

def send_at(ser, cmd, timeout=3):
    """Send AT command and return clean response."""
    ser.reset_input_buffer()
    ser.write(f'{cmd}\r\n'.encode())
    time.sleep(0.5)
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
    return text

def adb_shell(cmd):
    """Run ADB shell command and return output."""
    try:
        result = subprocess.run(['adb', 'shell', cmd], capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except:
        return '<adb error>'

def main():
    ser = serial.Serial(PORT, BAUD, timeout=3)
    time.sleep(0.5)

    # Verify
    resp = send_at(ser, 'AT')
    if 'OK' not in resp:
        print(f"ERROR: No AT response: [{resp}]")
        sys.exit(1)
    print("[+] Modem connected\n")

    # ═══════════════════════════════════════
    # PHASE 1: DUMPCTRL argument probing
    # ═══════════════════════════════════════
    print("=" * 60)
    print("PHASE 1: AT+DUMPCTRL argument probing")
    print("=" * 60)

    dumpctrl_tests = [
        'AT+DUMPCTRL',
        'AT+DUMPCTRL?',
        'AT+DUMPCTRL=?',
        'AT+DUMPCTRL=0',
        'AT+DUMPCTRL=1',
        'AT+DUMPCTRL=2',
        'AT+DUMPCTRL=ON',
        'AT+DUMPCTRL=OFF',
        'AT+DUMPCTRL=ENABLE',
        'AT+DUMPCTRL=DISABLE',
        'AT+DUMPCTRL=START',
        'AT+DUMPCTRL=STOP',
        'AT+DUMPCTRL=STATUS',
        'AT+DUMPCTRL=DUMP',
        'AT+DUMPCTRL=GET',
        'AT+DUMPCTRL=LIST',
        'AT+DUMPCTRL=TRIGGER',
        'AT+DUMPCTRL=RAMDUMP',
    ]

    for cmd in dumpctrl_tests:
        resp = send_at(ser, cmd)
        # Clean up echo
        clean = resp.replace(cmd, '').strip()
        status = '✅' if 'OK' in resp else '❌' if 'ERROR' in resp else '❓'
        detail = clean.replace('OK', '').replace('\n', ' ').strip()
        if detail:
            print(f"  {status} {cmd:35s} → {detail}")
        else:
            print(f"  {status} {cmd:35s} → {'OK' if 'OK' in resp else 'ERROR' if 'ERROR' in resp else resp[:60]}")

    # ═══════════════════════════════════════
    # PHASE 2: Related dump/memory AT commands
    # ═══════════════════════════════════════
    print(f"\n{'=' * 60}")
    print("PHASE 2: Memory/dump-related AT commands")
    print("=" * 60)

    dump_commands = [
        'AT+XDUMPMEM',
        'AT+XDUMPMEM?',
        'AT%MEMDUMP',
        'AT%MEMDUMP?',
        'AT+CPLOG',
        'AT+CPLOG?',
        'AT+CPDUMP',
        'AT+RAMDUMP',
        'AT+SYSLOG',
        'AT%SYSLOG',
        'AT%SYSLOG=1',
        'AT+TRACE',
        'AT+TRACE?',
        'AT%TRACE',
        'AT+LOGPATH',
        'AT+LOGPATH?',
        'AT%LOGDUMP',
        'AT+CPCRASH',
        'AT+CPRESET',
        'AT+MODEMRESET',
        'AT%CPRESET',
        'AT+XDBGLOG',
        'AT+XDBGLOG?',
        'AT+DEBUGLEVEL',
        'AT+DEBUGLEVEL?',
        'AT%DEBUGLEVEL',
        'AT+SLOG',
        'AT+SLOG?',
        'AT%SLOG',
        'AT+NVDUMP',
        'AT+NVSAVE',
        'AT%NVDUMP',
        'AT+SECLOG',
        'AT+SECLOG?',
    ]

    interesting = []
    for cmd in dump_commands:
        resp = send_at(ser, cmd, timeout=2)
        clean = resp.replace(cmd, '').strip()
        is_ok = 'OK' in resp
        is_err = 'ERROR' in resp or 'error' in resp.lower()
        status = '✅' if is_ok and not is_err else '❌' if is_err else '❓'
        detail = clean.replace('OK', '').replace('\n', ' ').strip()
        if is_ok and not is_err:
            interesting.append((cmd, detail))
        print(f"  {status} {cmd:30s} → {detail[:80] if detail else 'OK' if is_ok else 'ERROR'}")

    # ═══════════════════════════════════════
    # PHASE 3: Check device for dump files
    # ═══════════════════════════════════════
    print(f"\n{'=' * 60}")
    print("PHASE 3: Device dump file locations (via ADB)")
    print("=" * 60)

    dump_paths = [
        '/data/log/',
        '/data/cp_log/',
        '/data/vendor/log/',
        '/data/vendor/ramdump/',
        '/data/tombstones/',
        '/sdcard/log/',
        '/data/log/cpcrash/',
        '/data/misc/cp/',
        '/sys/kernel/debug/modem/',
        '/proc/modem/',
        '/data/ramdump/',
    ]

    for path in dump_paths:
        result = adb_shell(f'ls -la {path} 2>/dev/null | head -20')
        if result and 'No such file' not in result and 'Permission denied' not in result:
            lines = result.split('\n')
            print(f"  📁 {path} ({len(lines)} entries)")
            for line in lines[:8]:
                print(f"     {line}")
            if len(lines) > 8:
                print(f"     ... +{len(lines)-8} more")
        else:
            reason = 'not found' if 'No such' in (result or '') else 'denied' if 'Permission' in (result or '') else 'empty/error'
            print(f"  ❌ {path} ({reason})")

    # ═══════════════════════════════════════
    # PHASE 4: CFUN=9 CLPC OFF investigation
    # ═══════════════════════════════════════
    print(f"\n{'=' * 60}")
    print("PHASE 4: CFUN=9 (CLPC OFF) engineering probe")
    print("=" * 60)

    send_at(ser, 'AT+CFUN=9', timeout=3)
    time.sleep(1)

    clpc_tests = [
        'AT+CLPC?',
        'AT+CLPC=?',
        'AT%CLPC',
        'AT+TXPWR?',
        'AT+TXPWR=?',
        'AT%TXPWR',
        'AT+RFTEST',
        'AT+RFTEST?',
        'AT%RFTEST',
        'AT+RFCAL',
        'AT+RFCAL?',
        'AT%RFCAL',
        'AT+ANTENNATEST',
        'AT%ANTENNATEST',
    ]

    for cmd in clpc_tests:
        resp = send_at(ser, cmd, timeout=2)
        clean = resp.replace(cmd, '').strip()
        is_ok = 'OK' in resp and 'ERROR' not in resp
        status = '✅' if is_ok else '❌'
        detail = clean.replace('OK', '').replace('\n', ' ').strip()
        if is_ok:
            interesting.append((cmd, f'(CFUN=9) {detail}'))
        print(f"  {status} {cmd:30s} → {detail[:80] if detail else 'OK' if is_ok else 'ERROR'}")

    # Return to safe mode
    send_at(ser, 'AT+CFUN=0', timeout=3)

    # ═══════════════════════════════════════
    # PHASE 5: NV access alternate approaches
    # ═══════════════════════════════════════
    print(f"\n{'=' * 60}")
    print("PHASE 5: NV item access alternatives")
    print("=" * 60)

    nv_tests = [
        'AT+EGMR=1,7',         # Read IMEI via EGMR
        'AT+EGMR=2,7',         # Read IMEI2
        'AT+CGSN=1',           # IMEI via CGSN
        'AT$QCNVR',            # Qualcomm NV read
        'AT%NVREAD=0',         # NV item 0
        'AT%NVREAD=1',         # NV item 1
        'AT%NVREAD=550',       # SPC (Service Programming Code)
        'AT%NVREAD=65',        # ESN/MEID
        'AT+NVSAVE',
        'AT+NVRESTORE',
        'AT+NVBACKUP',
        'AT+EFSREAD',
        'AT%EFSREAD',
        'AT$QCEFS',
    ]

    for cmd in nv_tests:
        resp = send_at(ser, cmd, timeout=2)
        clean = resp.replace(cmd.split('=')[0], '').strip()
        is_ok = 'OK' in resp and 'ERROR' not in resp
        status = '✅' if is_ok else '❌'
        detail = clean.replace('OK', '').replace('\n', ' ').strip()
        if is_ok:
            interesting.append((cmd, detail))
        print(f"  {status} {cmd:30s} → {detail[:80] if detail else 'OK' if is_ok else 'ERROR'}")

    # ═══════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════
    print(f"\n{'=' * 60}")
    print(f"SUMMARY: {len(interesting)} interesting responses")
    print("=" * 60)
    for cmd, detail in interesting:
        print(f"  🎯 {cmd}: {detail[:100]}")

    ser.close()
    print("\n[+] Done. Modem left in CFUN=0 (safe).")

if __name__ == '__main__':
    main()
