#!/usr/bin/env python3
"""
diagexe DM Protocol Fuzzer - Samsung SM-T377A
==============================================
Target: diagexe (PID 2209, UID 1000, CAP_SYS_ADMIN)
Path: USB COM11 -> ttyGS1 -> diagexe -> /dev/umts_dm0

Protocol: Samsung DM/HDLC variant
  Start flag: 0x7F
  End flag:   0x7E
  Escape:     0x7D (next byte XOR 0x20)
  Message:    [0x7F] [cmd] [payload...] [crc16?] [0x7E]

Buffer size: DR_SMD_XFER_BUF_SIZE (unknown, probed here)

Strategy: Progressive fuzzing in phases:
  Phase 0: Baseline - verify COM port works, diagexe alive
  Phase 1: Size probing - find DR_SMD_XFER_BUF_SIZE boundary
  Phase 2: Delimiter fuzzing - missing/extra/nested delimiters
  Phase 3: Escape sequence abuse - malformed escape patterns
  Phase 4: Command code spray - all 256 cmd bytes
  Phase 5: Format string injection - %s %x %n patterns
  Phase 6: Deep structure fuzzing - SDM-specific message types
"""

import serial
import time
import struct
import subprocess
import sys
import os
import threading
import datetime

# ==================== Configuration ====================
COM_PORT = "COM18"  # DM port
BAUD_RATE = 115200
TIMEOUT = 1.0

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dm_fuzz_logs")
os.makedirs(LOG_DIR, exist_ok=True)

# DM Protocol constants
DM_START = 0x7F
DM_END = 0x7E
DM_ESCAPE = 0x7D
DM_XOR = 0x20

# ==================== Logging ====================
log_file = None

def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()

def log_hex(prefix, data):
    if len(data) <= 64:
        hex_str = " ".join(f"{b:02x}" for b in data)
    else:
        hex_str = " ".join(f"{b:02x}" for b in data[:32]) + f" ... ({len(data)} bytes total) ... " + " ".join(f"{b:02x}" for b in data[-8:])
    log(f"{prefix}: {hex_str}")

# ==================== Health Monitor ====================
diagexe_alive = True
diagexe_pid = None
crash_detected = False

def check_diagexe_health():
    """Check if diagexe is running via ADB"""
    global diagexe_alive, diagexe_pid, crash_detected
    try:
        result = subprocess.run(
            ["adb", "shell", "ps | grep diagexe"],
            capture_output=True, text=True, timeout=5
        )
        lines = [l for l in result.stdout.strip().split('\n') if 'diagexe' in l and 'grep' not in l]
        if lines:
            parts = lines[0].split()
            new_pid = int(parts[1]) if len(parts) > 1 else None
            if diagexe_pid and new_pid != diagexe_pid:
                log(f"!!! DIAGEXE RESTARTED! Old PID={diagexe_pid}, New PID={new_pid} !!!")
                crash_detected = True
            diagexe_pid = new_pid
            diagexe_alive = True
            return True
        else:
            log("!!! DIAGEXE NOT FOUND IN PROCESS LIST !!!")
            diagexe_alive = False
            crash_detected = True
            return False
    except Exception as e:
        log(f"Health check error: {e}")
        return True  # assume alive if check fails

def health_monitor_thread():
    """Background thread to monitor diagexe"""
    while not stop_monitor.is_set():
        check_diagexe_health()
        stop_monitor.wait(3.0)

stop_monitor = threading.Event()

# ==================== DM Frame Helpers ====================

def make_dm_frame(payload):
    """Wrap payload in DM frame: 0x7F [payload] 0x7E"""
    return bytes([DM_START]) + payload + bytes([DM_END])

def make_dm_frame_escaped(payload):
    """Wrap payload with HDLC escape encoding"""
    escaped = bytearray()
    for b in payload:
        if b in (DM_START, DM_END, DM_ESCAPE):
            escaped.append(DM_ESCAPE)
            escaped.append(b ^ DM_XOR)
        else:
            escaped.append(b)
    return bytes([DM_START]) + bytes(escaped) + bytes([DM_END])

def send_and_recv(ser, data, recv_timeout=0.5):
    """Send data and read any response"""
    ser.reset_input_buffer()
    ser.write(data)
    ser.flush()
    time.sleep(recv_timeout)
    response = b""
    while ser.in_waiting:
        response += ser.read(ser.in_waiting)
        time.sleep(0.05)
    return response

# ==================== PHASE 0: Baseline ====================

def phase0_baseline(ser):
    """Verify COM port works and diagexe responds"""
    log("=" * 60)
    log("PHASE 0: Baseline verification")
    log("=" * 60)

    # Test AT command (should work via AT mux)
    log("Test 1: AT command")
    resp = send_and_recv(ser, b"AT\r\n", 1.0)
    if resp:
        log_hex("  Response", resp)
        log("  AT interface ACTIVE")
    else:
        log("  No AT response (may need DM mode)")

    # Test minimal DM frame
    log("Test 2: Minimal DM frame (empty)")
    frame = make_dm_frame(b"")
    log_hex("  Sending", frame)
    resp = send_and_recv(ser, frame, 1.0)
    if resp:
        log_hex("  Response", resp)
    else:
        log("  No response to empty frame")

    # Test DM frame with single byte cmd
    log("Test 3: DM frame with cmd=0x00")
    frame = make_dm_frame(b"\x00")
    log_hex("  Sending", frame)
    resp = send_and_recv(ser, frame, 1.0)
    if resp:
        log_hex("  Response", resp)
    else:
        log("  No response")

    # Test known DM command (version info = 0x00 in DIAG protocol)
    log("Test 4: DIAG version request (cmd=0x00)")
    frame = make_dm_frame(b"\x00")
    log_hex("  Sending", frame)
    resp = send_and_recv(ser, frame, 1.0)
    if resp:
        log_hex("  Response", resp)

    # Test DIAG_LOG_CONFIG (cmd=0x73)
    log("Test 5: DIAG log config (cmd=0x73)")
    frame = make_dm_frame(b"\x73\x00")
    log_hex("  Sending", frame)
    resp = send_and_recv(ser, frame, 1.0)
    if resp:
        log_hex("  Response", resp)

    check_diagexe_health()
    log(f"  diagexe PID={diagexe_pid}, alive={diagexe_alive}")
    return True

# ==================== PHASE 1: Size Probing ====================

def phase1_size_probe(ser):
    """Find DR_SMD_XFER_BUF_SIZE by sending increasing payload sizes"""
    log("=" * 60)
    log("PHASE 1: Buffer size probing")
    log("=" * 60)

    # Common buffer sizes to test: 256, 512, 1024, 2048, 4096, 8192, 16384
    # Also test around page boundaries
    test_sizes = [
        64, 128, 200, 252, 254, 255, 256, 257, 258,
        500, 510, 511, 512, 513, 514,
        1000, 1022, 1023, 1024, 1025, 1026,
        2000, 2046, 2047, 2048, 2049, 2050,
        4000, 4092, 4093, 4094, 4095, 4096, 4097, 4098,
        8000, 8190, 8191, 8192, 8193, 8194,
        16000, 16382, 16383, 16384, 16385, 16386,
        32000, 32766, 32767, 32768, 32769,
        65534, 65535
    ]

    results = []
    for size in test_sizes:
        if crash_detected:
            log("!!! Crash detected, stopping size probe !!!")
            break

        # Create payload of given size (use 0x41 'A' as fill)
        payload = bytes([0x01]) + b"\x41" * (size - 1)  # cmd=0x01 + filler
        frame = make_dm_frame(payload)

        log(f"  Size {size}: sending {len(frame)} byte frame...")
        resp = send_and_recv(ser, frame, 0.3)
        status = f"resp={len(resp)}b" if resp else "no_resp"
        results.append((size, len(frame), status))
        log(f"  Size {size}: {status}")

        if resp:
            log_hex(f"    Response", resp[:32])

        # Brief pause between tests
        time.sleep(0.1)

        # Health check every 10 sizes
        if size > 4096 and test_sizes.index(size) % 5 == 0:
            check_diagexe_health()
            if not diagexe_alive:
                log(f"!!! diagexe died after size {size} !!!")
                break

    log("\nSize probe summary:")
    for size, frame_len, status in results:
        log(f"  payload={size:6d} frame={frame_len:6d} -> {status}")

    return results

# ==================== PHASE 2: Delimiter Fuzzing ====================

def phase2_delimiter_fuzz(ser):
    """Test malformed delimiter patterns"""
    log("=" * 60)
    log("PHASE 2: Delimiter fuzzing")
    log("=" * 60)

    tests = [
        ("no_start", b"\x00\x01\x02" + bytes([DM_END])),
        ("no_end", bytes([DM_START]) + b"\x00\x01\x02"),
        ("no_delimiters", b"\x00\x01\x02\x03"),
        ("double_start", bytes([DM_START, DM_START]) + b"\x00" + bytes([DM_END])),
        ("triple_start", bytes([DM_START]*3) + b"\x00" + bytes([DM_END])),
        ("double_end", bytes([DM_START]) + b"\x00" + bytes([DM_END, DM_END])),
        ("start_only", bytes([DM_START])),
        ("end_only", bytes([DM_END])),
        ("reversed", bytes([DM_END]) + b"\x00" + bytes([DM_START])),
        ("nested", bytes([DM_START]) + b"\x00" + bytes([DM_START]) + b"\x01" + bytes([DM_END]) + bytes([DM_END])),
        ("interleaved", bytes([DM_START]) + b"\x00" + bytes([DM_END]) + bytes([DM_START]) + b"\x01" + bytes([DM_END])),
        ("many_starts", bytes([DM_START]*256) + bytes([DM_END])),
        ("many_ends", bytes([DM_START]) + bytes([DM_END]*256)),
        ("alternating", bytes([DM_START, DM_END]*128)),
        ("start_flood", bytes([DM_START]*4096)),
        ("end_flood", bytes([DM_END]*4096)),
        ("all_7F", b"\x7F" * 1024),
        ("all_7E", b"\x7E" * 1024),
        ("no_end_large", bytes([DM_START]) + b"\x41" * 8192),
    ]

    for name, data in tests:
        if crash_detected:
            log("!!! Crash detected, stopping !!!")
            break

        log(f"  Test '{name}' ({len(data)} bytes)")
        log_hex(f"    Data", data[:32])
        resp = send_and_recv(ser, data, 0.3)
        if resp:
            log_hex(f"    Response", resp[:32])
        else:
            log(f"    No response")
        time.sleep(0.1)

    check_diagexe_health()
    log(f"  diagexe alive={diagexe_alive}, PID={diagexe_pid}")

# ==================== PHASE 3: Escape Sequence Abuse ====================

def phase3_escape_fuzz(ser):
    """Test HDLC escape sequence handling"""
    log("=" * 60)
    log("PHASE 3: Escape sequence fuzzing")
    log("=" * 60)

    tests = [
        ("escape_at_end", bytes([DM_START]) + b"\x00" + bytes([DM_ESCAPE]) + bytes([DM_END])),
        ("escape_escape", bytes([DM_START]) + bytes([DM_ESCAPE, DM_ESCAPE]) + bytes([DM_END])),
        ("escape_start", bytes([DM_START]) + bytes([DM_ESCAPE, DM_START ^ DM_XOR]) + bytes([DM_END])),
        ("escape_end", bytes([DM_START]) + bytes([DM_ESCAPE, DM_END ^ DM_XOR]) + bytes([DM_END])),
        ("escape_self", bytes([DM_START]) + bytes([DM_ESCAPE, DM_ESCAPE ^ DM_XOR]) + bytes([DM_END])),
        ("double_escape", bytes([DM_START]) + bytes([DM_ESCAPE, DM_ESCAPE, DM_ESCAPE, DM_ESCAPE]) + bytes([DM_END])),
        ("escape_flood", bytes([DM_START]) + bytes([DM_ESCAPE]*512) + bytes([DM_END])),
        ("escape_all_bytes", bytes([DM_START]) + bytes(sum([[DM_ESCAPE, i] for i in range(256)], [])) + bytes([DM_END])),
        ("truncated_escape", bytes([DM_START]) + b"\x00" + bytes([DM_ESCAPE])),
        ("escape_00", bytes([DM_START]) + bytes([DM_ESCAPE, 0x00]) + bytes([DM_END])),
        ("escape_ff", bytes([DM_START]) + bytes([DM_ESCAPE, 0xFF]) + bytes([DM_END])),
        # Escaped payload that expands to > buffer size
        ("escape_expand_4k", bytes([DM_START]) + bytes([DM_ESCAPE, 0x5F]*2048) + bytes([DM_END])),
        ("escape_expand_8k", bytes([DM_START]) + bytes([DM_ESCAPE, 0x5F]*4096) + bytes([DM_END])),
    ]

    for name, data in tests:
        if crash_detected:
            log("!!! Crash detected, stopping !!!")
            break

        log(f"  Test '{name}' ({len(data)} bytes)")
        resp = send_and_recv(ser, data, 0.3)
        if resp:
            log_hex(f"    Response", resp[:32])
        else:
            log(f"    No response")
        time.sleep(0.1)

    check_diagexe_health()
    log(f"  diagexe alive={diagexe_alive}, PID={diagexe_pid}")

# ==================== PHASE 4: Command Code Spray ====================

def phase4_cmd_spray(ser):
    """Send all 256 possible command codes"""
    log("=" * 60)
    log("PHASE 4: Command code spray (0x00-0xFF)")
    log("=" * 60)

    responding_cmds = []
    for cmd in range(256):
        if crash_detected:
            break

        frame = make_dm_frame(bytes([cmd]))
        resp = send_and_recv(ser, frame, 0.2)
        if resp:
            responding_cmds.append(cmd)
            log(f"  cmd=0x{cmd:02x}: RESPONSE ({len(resp)} bytes)")
            log_hex(f"    Data", resp[:16])
        # Don't log non-responding cmds to avoid spam

        if cmd % 64 == 63:
            check_diagexe_health()
            log(f"  Progress: {cmd+1}/256, diagexe alive={diagexe_alive}")

    log(f"\nResponding commands ({len(responding_cmds)}):")
    for cmd in responding_cmds:
        log(f"  0x{cmd:02x}")

# ==================== PHASE 5: Format String ====================

def phase5_format_string(ser):
    """Test format string vulnerabilities in log paths"""
    log("=" * 60)
    log("PHASE 5: Format string injection")
    log("=" * 60)

    payloads = [
        b"%s%s%s%s%s%s%s%s%s%s",
        b"%x%x%x%x%x%x%x%x",
        b"%08x.%08x.%08x.%08x.%08x.%08x",
        b"AAAA%08x.%08x.%08x.%08x",
        b"%p%p%p%p%p%p%p%p",
        b"%.999999d",
        b"%99999s",
        b"\x00\x00\x00\x00%08x.%08x.%08x.%08x",
        b"A" * 100 + b"%x" * 50,
        b"%n%n%n%n",  # WARNING: %n can crash if format string vuln exists
    ]

    for i, payload in enumerate(payloads):
        if crash_detected:
            break

        # Send as raw (AT-like)
        log(f"  Test {i}: format string ({len(payload)} bytes)")
        frame = make_dm_frame(payload)
        resp = send_and_recv(ser, frame, 0.3)
        if resp:
            log_hex(f"    DM response", resp[:32])

        time.sleep(0.1)

    check_diagexe_health()
    log(f"  diagexe alive={diagexe_alive}, PID={diagexe_pid}")

# ==================== PHASE 6: Deep Structure Fuzzing ====================

def phase6_deep_structure(ser):
    """Fuzz SDM-specific message structures"""
    log("=" * 60)
    log("PHASE 6: Deep SDM structure fuzzing")
    log("=" * 60)

    # Samsung DIAG command categories:
    # 0x00-0x0F: Version/status
    # 0x10-0x1F: NV read/write
    # 0x26: NV item read
    # 0x27: NV item write
    # 0x29: Status
    # 0x41: Log config
    # 0x60: Event report
    # 0x63: Feature query
    # 0x73: Extended build/log
    # 0x7C-0x7F: Subsystem dispatch
    # 0x80-0xFF: Samsung proprietary

    # Test each category with various payload lengths
    categories = [
        (0x00, "Version"),
        (0x0C, "Status query"),
        (0x26, "NV read"),
        (0x27, "NV write"),
        (0x29, "Status"),
        (0x41, "Log config"),
        (0x60, "Event report"),
        (0x63, "Feature query"),
        (0x73, "Extended"),
        (0x7C, "Subsys dispatch"),
        (0x7D, "Subsys dispatch 2"),
        (0x80, "Samsung cmd 0"),
        (0xA0, "Samsung cmd 32"),
        (0xC0, "Samsung cmd 64"),
        (0xE0, "Samsung cmd 96"),
        (0xFF, "Samsung max"),
    ]

    for cmd, name in categories:
        if crash_detected:
            break
        log(f"  Category 0x{cmd:02x} ({name}):")

        # Minimal
        frame = make_dm_frame(bytes([cmd]))
        resp = send_and_recv(ser, frame, 0.2)
        s1 = f"resp={len(resp)}b" if resp else "no_resp"

        # With subcmd
        frame = make_dm_frame(bytes([cmd, 0x00, 0x00, 0x00]))
        resp = send_and_recv(ser, frame, 0.2)
        s2 = f"resp={len(resp)}b" if resp else "no_resp"

        # With larger payload
        frame = make_dm_frame(bytes([cmd]) + b"\x00" * 64)
        resp = send_and_recv(ser, frame, 0.2)
        s3 = f"resp={len(resp)}b" if resp else "no_resp"

        # With max-ish payload
        frame = make_dm_frame(bytes([cmd]) + b"\x41" * 1024)
        resp = send_and_recv(ser, frame, 0.2)
        s4 = f"resp={len(resp)}b" if resp else "no_resp"

        log(f"    min={s1}  sub={s2}  med={s3}  large={s4}")

        if resp:
            log_hex(f"    Last response", resp[:32])

    # Subsystem dispatch with all sub-IDs
    log("\n  Subsystem dispatch (0x4B) sub-ID sweep:")
    for sub_id in range(64):
        if crash_detected:
            break
        # Qualcomm DIAG subsystem format: [0x4B][subsys_id_lo][subsys_id_hi][sub_cmd_lo][sub_cmd_hi][payload...]
        payload = struct.pack("<BBHH", 0x4B, sub_id, 0, 0)
        frame = make_dm_frame(payload)
        resp = send_and_recv(ser, frame, 0.15)
        if resp and len(resp) > 4:
            log(f"    SubID={sub_id}: RESPONSE ({len(resp)} bytes)")
            log_hex(f"      Data", resp[:16])

    check_diagexe_health()
    log(f"  diagexe alive={diagexe_alive}, PID={diagexe_pid}")

# ==================== Main ====================

def main():
    global log_file, diagexe_pid

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOG_DIR, f"dm_fuzz_{timestamp}.log")
    log_file = open(log_path, "w")

    log(f"DM Protocol Fuzzer - Samsung SM-T377A")
    log(f"Target: diagexe via {COM_PORT} @ {BAUD_RATE}")
    log(f"Log: {log_path}")
    log("")

    # Initial health check
    check_diagexe_health()
    log(f"Initial diagexe PID: {diagexe_pid}")

    # Start health monitor
    monitor = threading.Thread(target=health_monitor_thread, daemon=True)
    monitor.start()

    try:
        ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=TIMEOUT)
        log(f"Serial port {COM_PORT} opened")

        # Select which phases to run
        phases = sys.argv[1:] if len(sys.argv) > 1 else ["0"]

        for phase in phases:
            if crash_detected:
                log(f"\n!!! CRASH DETECTED - diagexe may have died !!!")
                log(f"!!! Stopping fuzzer for analysis !!!")
                break

            if phase == "0":
                phase0_baseline(ser)
            elif phase == "1":
                phase1_size_probe(ser)
            elif phase == "2":
                phase2_delimiter_fuzz(ser)
            elif phase == "3":
                phase3_escape_fuzz(ser)
            elif phase == "4":
                phase4_cmd_spray(ser)
            elif phase == "5":
                phase5_format_string(ser)
            elif phase == "6":
                phase6_deep_structure(ser)
            elif phase == "all":
                phase0_baseline(ser)
                phase1_size_probe(ser)
                phase2_delimiter_fuzz(ser)
                phase3_escape_fuzz(ser)
                phase4_cmd_spray(ser)
                phase5_format_string(ser)
                phase6_deep_structure(ser)
            else:
                log(f"Unknown phase: {phase}")

        ser.close()
        log(f"\nSerial port closed")

    except serial.SerialException as e:
        log(f"Serial error: {e}")
    except KeyboardInterrupt:
        log(f"\nInterrupted by user")
    finally:
        stop_monitor.set()
        # Final health check
        check_diagexe_health()
        log(f"\nFinal diagexe PID: {diagexe_pid}, alive={diagexe_alive}")
        log(f"Crash detected: {crash_detected}")

        if crash_detected:
            log("\n!!! COLLECTING CRASH DATA !!!")
            try:
                result = subprocess.run(["adb", "shell", "dmesg | tail -50"], capture_output=True, text=True, timeout=10)
                log(f"Last dmesg:\n{result.stdout}")
            except:
                pass

        log_file.close()
        print(f"\nLog saved to: {log_path}")

if __name__ == "__main__":
    main()
