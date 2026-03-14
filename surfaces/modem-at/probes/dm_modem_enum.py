#!/usr/bin/env python3
"""
Deep modem command enumeration via DM protocol.
Probes Shannon 308 modem commands to find:
- NV read/write access
- EFS operations  
- Debug/dump commands
- Samsung IPC commands
- Any privileged operations

Samsung Shannon IPC format (based on libsamsung-ipc):
  [main_cmd:1] [sub_cmd:1] [type:1] [data...]
  
type: 0x01=SET, 0x02=GET, 0x03=RESP, 0x04=NOTI, 0x05=EXEC
main_cmd categories (Samsung IPC):
  0x01 = PWR (power)
  0x02 = CALL
  0x03 = SMS
  0x04 = SEC (security - SIM PIN/PUK!)
  0x05 = PB (phonebook)
  0x06 = DISP (display)
  0x07 = NET (network)
  0x08 = SND (sound)
  0x09 = MISC
  0x0A = SVC
  0x0B = SS (supplementary service)
  0x0C = GPRS
  0x0D = SAT
  0x0E = CFG
  0x0F = IMEI
  0x10 = GPS
  0x11 = SAP
  0x14 = RFS (Remote File System!)
  0x15 = GEN
"""
import serial
import time
import subprocess
import datetime
import sys

COM_PORT = "COM11"
BAUD_RATE = 115200

DM_START = 0x7F
DM_END = 0x7E

def check_diagexe():
    r = subprocess.run(["adb", "shell", "ps | grep diagexe"], capture_output=True, text=True, timeout=5)
    lines = [l for l in r.stdout.strip().split('\n') if 'diagexe' in l and 'grep' not in l]
    if lines:
        return int(lines[0].split()[1])
    return None

def send_recv(ser, data, wait=0.5):
    ser.reset_input_buffer()
    ser.write(data)
    ser.flush()
    time.sleep(wait)
    resp = b""
    attempts = 0
    while attempts < 3:
        if ser.in_waiting:
            resp += ser.read(ser.in_waiting)
            time.sleep(0.05)
            attempts = 0
        else:
            attempts += 1
            time.sleep(0.05)
    return resp

def make_frame(payload):
    return bytes([DM_START]) + payload + bytes([DM_END])

def fmt_resp(resp, max_bytes=32):
    if not resp:
        return "NONE"
    h = resp[:max_bytes].hex()
    if len(resp) > max_bytes:
        h += f"... ({len(resp)}b total)"
    return h

def main():
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] Shannon 308 Modem Command Enumeration")
    
    pid = check_diagexe()
    print(f"diagexe PID: {pid}")
    
    logfile = f"work/dm_fuzz_logs/modem_enum_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log = open(logfile, "w")
    
    ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1.0)
    
    # Flush any buffered data
    ser.write(b"\r\n")
    time.sleep(0.5)
    ser.read(ser.in_waiting)
    
    def log_print(msg):
        print(msg)
        log.write(msg + "\n")
        log.flush()
    
    # ===== Test 1: Samsung IPC format (main_cmd, sub_cmd, type) =====
    log_print("\n=== TEST 1: Samsung IPC Command Enumeration ===")
    log_print("Format: [main_cmd] [sub_cmd=0x01] [type=0x02(GET)]")
    
    IPC_CATEGORIES = {
        0x01: "PWR", 0x02: "CALL", 0x03: "SMS", 0x04: "SEC",
        0x05: "PB", 0x06: "DISP", 0x07: "NET", 0x08: "SND",
        0x09: "MISC", 0x0A: "SVC", 0x0B: "SS", 0x0C: "GPRS",
        0x0D: "SAT", 0x0E: "CFG", 0x0F: "IMEI", 0x10: "GPS",
        0x11: "SAP", 0x14: "RFS", 0x15: "GEN",
    }
    
    interesting = []
    for main_cmd, name in IPC_CATEGORIES.items():
        # Try GET (0x02) with sub_cmd=0x01
        payload = bytes([main_cmd, 0x01, 0x02])
        resp = send_recv(ser, make_frame(payload), 0.3)
        if resp and resp != bytes([DM_END]):
            resp_hex = fmt_resp(resp)
            log_print(f"  0x{main_cmd:02x} ({name:5s}) GET sub=1: {resp_hex}")
            interesting.append((main_cmd, name, resp))
        
        # Try EXEC (0x05) with sub_cmd=0x01
        payload = bytes([main_cmd, 0x01, 0x05])
        resp = send_recv(ser, make_frame(payload), 0.3)
        if resp and resp != bytes([DM_END]):
            resp_hex = fmt_resp(resp)
            log_print(f"  0x{main_cmd:02x} ({name:5s}) EXEC sub=1: {resp_hex}")
            interesting.append((main_cmd, name, resp))
    
    # ===== Test 2: Qualcomm DIAG commands (diagexe may translate) =====
    log_print("\n=== TEST 2: Qualcomm DIAG Commands ===")
    
    DIAG_CMDS = {
        0x00: "Version info",
        0x0C: "Status query",
        0x1C: "ESN read",
        0x26: "NV read",
        0x27: "NV write",
        0x29: "Modem status",
        0x35: "NV peek 16",
        0x36: "NV peek 32",
        0x37: "NV poke 16",
        0x38: "NV poke 32",
        0x39: "Bad SPC mode",
        0x40: "DIAG version",
        0x41: "Timestamp",
        0x44: "HS key",
        0x46: "SPC",
        0x48: "Password",
        0x4B: "Subsys dispatch",
        0x4C: "Feature query",
        0x55: "Security mode",
        0x60: "Log config",
        0x63: "Extended msg config",
        0x7C: "Extended build ID",
        0x7D: "Extended status",
        0x7E: "Event report",
    }
    
    for cmd, name in DIAG_CMDS.items():
        # Minimal payload
        payload = bytes([cmd])
        resp = send_recv(ser, make_frame(payload), 0.3)
        if resp:
            resp_hex = fmt_resp(resp)
            log_print(f"  0x{cmd:02x} ({name:20s}): {resp_hex}")
        
        # With 4 bytes of zeros (sub-command + padding)
        payload = bytes([cmd, 0x00, 0x00, 0x00])
        resp = send_recv(ser, make_frame(payload), 0.3)
        if resp and len(resp) > 2:  # More than just echo
            resp_hex = fmt_resp(resp)
            log_print(f"  0x{cmd:02x} ({name:20s}) +data: {resp_hex}")
    
    # ===== Test 3: NV item read attempts =====
    log_print("\n=== TEST 3: NV Item Read Attempts ===")
    
    NV_ITEMS = {
        0: "ESN",
        10: "IMEI",
        71: "SPC (Service Programming Code)",
        85: "Roaming list",
        176: "MIN1",
        177: "MIN2",
        262: "PRL version",
        550: "OTKSL",
        906: "RF Cal",
        1192: "Phone model",
        4102: "GPS security",
        4398: "Vocoder",
        6853: "Data roaming",
    }
    
    for nv_id, name in NV_ITEMS.items():
        # DIAG NV read: cmd=0x26, NV item (2 bytes LE), 128 bytes data space
        payload = bytes([0x26]) + nv_id.to_bytes(2, 'little') + b"\x00" * 128
        resp = send_recv(ser, make_frame(payload), 0.3)
        if resp and len(resp) > 3:
            resp_hex = fmt_resp(resp, 48)
            log_print(f"  NV {nv_id:5d} ({name:25s}): {resp_hex}")
        elif resp:
            log_print(f"  NV {nv_id:5d} ({name:25s}): {fmt_resp(resp)}")
    
    # ===== Test 4: SPC unlock attempt =====
    log_print("\n=== TEST 4: SPC/Password Unlock Attempts ===")
    
    # Default SPC "000000"
    spc_payload = bytes([0x46]) + b"000000"
    resp = send_recv(ser, make_frame(spc_payload), 0.5)
    log_print(f"  SPC '000000': {fmt_resp(resp)}")
    
    # Samsung default SPC
    spc_payload = bytes([0x46]) + b"303030303030"  # hex encoded
    resp = send_recv(ser, make_frame(spc_payload), 0.5)
    log_print(f"  SPC '303030...' (hex): {fmt_resp(resp)}")
    
    # DIAG password cmd
    pwd_payload = bytes([0x48]) + b"\x00" * 8
    resp = send_recv(ser, make_frame(pwd_payload), 0.5)
    log_print(f"  Password zeros: {fmt_resp(resp)}")
    
    # ===== Test 5: Subsystem dispatch enumeration =====
    log_print("\n=== TEST 5: Subsystem Dispatch (0x4B) ===")
    
    SUBSYS_IDS = {
        0: "ZREX", 1: "runtime", 2: "HS", 3: "MC", 4: "FS",
        5: "GPS", 8: "UMTS", 9: "GSM", 10: "WCDMA",
        11: "HDR", 12: "DIAG", 13: "Technology", 14: "BREW",
        15: "SD", 17: "MMCP", 18: "DCVS", 19: "RRC",
        21: "QSC", 25: "LTE", 41: "SENSOR", 51: "APR",
        64: "SAMSUNG_EFS", 65: "SAMSUNG_NV", 80: "SAMSUNG_IPC",
        100: "VENDOR1", 200: "VENDOR2", 250: "VENDOR3",
    }
    
    for sub_id, name in SUBSYS_IDS.items():
        # Subsystem dispatch: 0x4B, subsys_id (2 bytes LE), sub_cmd (2 bytes LE)
        payload = bytes([0x4B]) + sub_id.to_bytes(2, 'little') + b"\x01\x00"
        resp = send_recv(ser, make_frame(payload), 0.3)
        if resp and len(resp) > 2:
            resp_hex = fmt_resp(resp)
            log_print(f"  Subsys {sub_id:3d} ({name:15s}) cmd=1: {resp_hex}")
    
    # ===== Test 6: AT command injection via DM frame =====
    log_print("\n=== TEST 6: AT Command Injection via DM ===")
    
    at_commands = [
        b"AT+CLAC\r",         # List all AT commands
        b"AT+CGMM\r",         # Model
        b"AT+CGMR\r",         # Revision
        b"AT+CGSN\r",         # IMEI
        b"AT$QCVERSN\r",      # Qualcomm version
        b"AT%SYSINFO\r",      # System info
        b"AT+CKPD=\"P\"\r",   # Key press
        b"AT+CFUN?\r",        # Phone functionality
        b"AT+COPS?\r",        # Operator selection
        b"AT+CSCA?\r",        # Service center address
        b"AT#MODEMRESET\r",   # Modem reset (careful!)
        b"ATI\r",             # Product info
        b"AT^VERSION\r",      # Version
        b"AT+DEVCONINFO\r",   # Device connection info
        b"AT+CGDCONT?\r",     # PDP context
    ]
    
    for at_cmd in at_commands:
        # Send as raw DM frame (payload is AT command)
        resp = send_recv(ser, make_frame(at_cmd), 0.5)
        cmd_str = at_cmd.decode('ascii', errors='replace').strip()
        if resp:
            # Try to decode as ASCII
            try:
                resp_text = resp.decode('ascii', errors='replace')
                if any(c in resp_text for c in ['OK', 'ERROR', 'CME', '+', '^']):
                    log_print(f"  {cmd_str}: {resp_text.strip()}")
                else:
                    log_print(f"  {cmd_str}: {fmt_resp(resp)}")
            except:
                log_print(f"  {cmd_str}: {fmt_resp(resp)}")
    
    # Also try AT commands raw (NOT in DM frame) 
    log_print("\n=== TEST 7: Raw AT Commands (no DM framing) ===")
    for at_cmd in [b"AT\r\n", b"ATI\r\n", b"AT+CLAC\r\n", b"AT+CGMM\r\n", b"AT+CGSN\r\n"]:
        resp = send_recv(ser, at_cmd, 0.5)
        cmd_str = at_cmd.decode('ascii', errors='replace').strip()
        if resp:
            try:
                log_print(f"  {cmd_str}: {resp.decode('ascii', errors='replace').strip()}")
            except:
                log_print(f"  {cmd_str}: {fmt_resp(resp)}")
    
    # ===== Test 8: Samsung-specific DM commands =====
    log_print("\n=== TEST 8: Samsung DM Protocol Commands ===")
    
    samsung_cmds = [
        (b"\x11\x00", "SDM Start"),
        (b"\x11\x01", "SDM Stop"),  
        (b"\x11\x06", "SDM Config"),
        (b"\x11\x0B", "SDM CP Info"),
        (b"\x11\x0C", "SDM AP Info"),
        (b"\x12\x00", "Log Start"),
        (b"\x12\x01", "Log Stop"),
        (b"\x13\x00", "Silent Log Start"),
        (b"\x13\x01", "Silent Log Stop"),
        (b"\x21\x00", "RIL IPC START"),
        (b"\x31\x00", "NVRAM Read"),
        (b"\x31\x01", "NVRAM Write"),
        (b"\x32\x00", "EFS Read"),
        (b"\x32\x01", "EFS Write"),
        (b"\x33\x00", "Diag Start"),
        (b"\x41\x00", "CP Crash"),
        (b"\x42\x00", "CP Version"),
        (b"\x51\x00", "RF Cal"),
        (b"\x61\x00", "Test Mode"),
        (b"\x62\x00", "Factory Mode"),
        (b"\x70\x00", "Debug Level"),
        (b"\x71\x00", "Kernel Log"),
        (b"\x80\x01\x00\x00", "IPC PWR GET"),
        (b"\x80\x04\x01\x02", "IPC SEC GET SIM"),
        (b"\x80\x0F\x01\x02", "IPC IMEI GET"),
        (b"\x80\x14\x01\x02", "IPC RFS GET"),
        (b"\x80\x15\x01\x02", "IPC GEN GET"),
    ]
    
    for payload, name in samsung_cmds:
        resp = send_recv(ser, make_frame(payload), 0.3)
        if resp:
            log_print(f"  {name:20s}: {fmt_resp(resp, 48)}")
    
    # Health check
    new_pid = check_diagexe()
    log_print(f"\nFinal diagexe PID: {new_pid} {'(CHANGED!)' if new_pid != pid else '(same)'}")
    
    ser.close()
    log.close()
    print(f"\nLog saved to: {logfile}")

main()
