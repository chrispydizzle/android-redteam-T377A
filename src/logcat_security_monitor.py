#!/usr/bin/env python3
"""
logcat_security_monitor.py -- Real-time ADB logcat security analysis pipeline.

Streams logcat from attached device, parses into structured records, applies
security-focused detection rules, and outputs annotated findings. Designed
for the SM-T377A (Android 6.0.1, Exynos 3475) privilege escalation research.

Usage:
    python logcat_security_monitor.py                # live stream, all buffers
    python logcat_security_monitor.py --buffers main system  # specific buffers
    python logcat_security_monitor.py --replay work/logcat_full.txt  # offline
    python logcat_security_monitor.py --dmesg         # include kernel dmesg polling
    python logcat_security_monitor.py --json           # JSON output per finding
    python logcat_security_monitor.py --output findings.log  # log findings to file
"""

import argparse
import io
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

# Force UTF-8 on Windows to handle ANSI and special chars
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# --- ANSI colors ---------------------------------------------------------------
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
DIM     = "\033[2m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# --- Logcat line parser ----------------------------------------------------
# Format: MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: MESSAGE
LOGCAT_RE = re.compile(
    r'^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'
    r'(\d+)\s+(\d+)\s+'
    r'([VDIWEF])\s+'
    r'(\S+)\s*:\s*(.*)'
)

# Kernel dmesg line: [seconds.usecs] optional_prefix message
DMESG_RE = re.compile(
    r'^\[\s*(\d+\.\d+)\]\s*(.*)'
)


def parse_logcat_line(line):
    """Parse a standard logcat line into a dict, or None if unparseable."""
    m = LOGCAT_RE.match(line.strip())
    if not m:
        return None
    return {
        "timestamp": m.group(1),
        "pid": int(m.group(2)),
        "tid": int(m.group(3)),
        "level": m.group(4),
        "tag": m.group(5),
        "message": m.group(6),
        "raw": line.strip(),
        "source": "logcat",
    }


def parse_dmesg_line(line):
    """Parse a kernel dmesg line into a dict."""
    m = DMESG_RE.match(line.strip())
    if not m:
        return None
    return {
        "timestamp": m.group(1),
        "pid": 0,
        "tid": 0,
        "level": "K",
        "tag": "kernel",
        "message": m.group(2),
        "raw": line.strip(),
        "source": "dmesg",
    }


# --- Security detection rules ----------------------------------------------
class SecurityRule:
    def __init__(self, name, severity, pattern, description, tags=None):
        self.name = name
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.pattern = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
        self.description = description
        self.tags = tags or []

    def match(self, record):
        text = record.get("message", "") + " " + record.get("tag", "")
        return self.pattern.search(text)


RULES = [
    # -- Kernel panics / crashes --
    SecurityRule("KERNEL_PANIC", "CRITICAL",
        r"kernel\s*panic|BUG:|Oops:|Unable to handle kernel",
        "Kernel panic or oops detected -- potential exploit trigger",
        ["kernel", "crash"]),
    SecurityRule("KERNEL_NULL_DEREF", "CRITICAL",
        r"NULL pointer dereference|unable to handle kernel NULL",
        "Kernel NULL pointer dereference -- possible UAF/race condition",
        ["kernel", "vuln"]),
    SecurityRule("TIMA_ALERT", "HIGH",
        r"\bTIMA\b|tz_iccc|trustzone.*integrity|\bRKP\b",
        "Samsung TIMA/TrustZone integrity check event",
        ["samsung", "tima"]),
    SecurityRule("KERNEL_UAF", "CRITICAL",
        r"use.after.free|double.free|slab.*corrupt|heap.*corrupt",
        "Potential use-after-free or heap corruption in kernel",
        ["kernel", "vuln"]),

    # -- SELinux --
    SecurityRule("SELINUX_DENIAL", "HIGH",
        r"avc:\s*denied|selinux.*denied",
        "SELinux access denial -- blocked operation",
        ["selinux"]),
    SecurityRule("SELINUX_PERMISSIVE", "CRITICAL",
        r"selinux.*(?:set|switch|change).*permissive|setenforce\s+0|enforcing.*(?:disabled|off|false)",
        "SELinux mode change detected -- possible bypass",
        ["selinux", "escalation"]),
    SecurityRule("SELINUX_CONTEXT", "MEDIUM",
        r"scontext=u:r:(\w+):s0.*tcontext=u:r:(\w+):s0",
        "SELinux domain transition or cross-domain access",
        ["selinux"]),

    # -- Privilege escalation indicators --
    SecurityRule("UID_CHANGE", "CRITICAL",
        r"uid\s*=\s*0[^0-9]|setuid.*0|capability.*changed|cap_setuid",
        "UID changed to root or capability elevation",
        ["escalation"]),
    SecurityRule("PROCESS_PRIVESC", "HIGH",
        r"commit_creds|prepare_kernel_cred|addr_limit|KERNEL_DS",
        "Kernel credential manipulation reference",
        ["escalation", "kernel"]),
    SecurityRule("SU_ATTEMPT", "HIGH",
        r"\bsu\b.*root|/system/xbin/su|/sbin/su|daemonsu",
        "su binary execution attempt",
        ["escalation"]),

    # -- Binder / IPC --
    SecurityRule("BINDER_DEATH", "MEDIUM",
        r"binder.*died|BinderProxy.*finalize|DeathRecipient",
        "Binder death notification -- service crash or restart",
        ["binder"]),
    SecurityRule("BINDER_FAILED", "MEDIUM",
        r"binder.*failed|BINDER_WRITE_READ.*error|BR_DEAD_REPLY",
        "Binder transaction failure",
        ["binder"]),
    SecurityRule("SERVICEMANAGER", "LOW",
        r"ServiceManager.*add.*service|find_svc|svc_can_register",
        "Service registration/lookup via ServiceManager",
        ["binder", "services"]),

    # -- Process crashes --
    SecurityRule("NATIVE_CRASH", "HIGH",
        r"Fatal signal|SIGSEGV|SIGBUS|SIGABRT|tombstone",
        "Native process crash -- possible exploit side-effect",
        ["crash"]),
    SecurityRule("ANR", "MEDIUM",
        r"ANR in|Input dispatching timed out",
        "Application Not Responding -- possible DoS or resource exhaustion",
        ["crash"]),
    SecurityRule("WATCHDOG", "MEDIUM",
        r"(?<!\w)Watchdog(?!\w)|SWT:|(?<!\w)WDOG(?!\w)",
        "System watchdog event -- potential system hang",
        ["crash", "stability"]),
    SecurityRule("WATCHDOG_SYNC", "LOW",
        r"!@Sync \d+",
        "System watchdog sync heartbeat (routine)",
        ["stability"]),

    # -- Samsung-specific --
    SecurityRule("CP_CRASH", "CRITICAL",
        r"CP\s*Crash|UNTS.*Reset|modem.*crash|CP\s*WDOG",
        "Cellular Processor crash -- modem watchdog or fatal error",
        ["samsung", "modem"]),
    SecurityRule("KNOX_EVENT", "HIGH",
        r"KNOX|knox|WARRANTY_BIT|KnoxGuard",
        "Samsung Knox security event",
        ["samsung", "knox"]),
    SecurityRule("SYSDUMP", "MEDIUM",
        r"SysDump|dumpstate|bugreport|ramdump",
        "System dump initiated -- debug data collection",
        ["samsung", "debug"]),
    SecurityRule("SMARTCOM_ROOT", "MEDIUM",
        r"smartcom|APNWidget|SmartcomRoot",
        "SmartcomRoot service activity (UID 1000)",
        ["samsung", "services"]),

    # -- Mali GPU --
    SecurityRule("MALI_BAD_FLAGS", "HIGH",
        r"kbase_mem_alloc.*bad flags",
        "Mali driver rejected allocation flags -- exploit attempt detected",
        ["mali", "kernel"]),
    SecurityRule("MALI_GPU_FAULT", "CRITICAL",
        r"GPU fault|gpu.*fault|mali.*fault|MMU.*fault|kbase.*fault",
        "Mali GPU/MMU fault -- possible exploit success or crash",
        ["mali", "kernel", "crash"]),
    SecurityRule("MALI_ALLOC", "LOW",
        r"kbase_mem_alloc|kbase_mem_free|kbase_mem_commit",
        "Mali memory operation (alloc/free/commit)",
        ["mali", "kernel"]),

    # -- DRParser / SecretCode --
    SecurityRule("DRPARSER_ACTIVITY", "HIGH",
        r"SecretCodeIME|DRParser|ParseService|keystring|KeyStringUpdate",
        "DRParser/SecretCodeIME activity -- potential secret code exploitation",
        ["drparser", "escalation"]),
    SecurityRule("SECRET_CODE", "HIGH",
        r"android\.provider\.Telephony\.SECRET_CODE|secret_code",
        "Secret code broadcast dispatched",
        ["drparser", "escalation"]),

    # -- Modem / AT / NV --
    SecurityRule("AT_COMMAND", "MEDIUM",
        r"ATD.*Send Msg|HandleMessageFromClients.*AT\+|AT\+DEVCONINFO|AT\+CLAC",
        "AT command sent to modem via ATD",
        ["modem", "at"]),
    SecurityRule("NV_WRITE", "MEDIUM",
        r"Nv::ProcessNvWrite|Nv::ProcessRfsMessage|RFS.*frame received",
        "Modem NV/EFS write operation via RILD RFS",
        ["modem", "nv"]),

    # -- Network/Bluetooth --
    SecurityRule("BT_L2CAP", "MEDIUM",
        r"l2cap|L2CAP|bt_l2cap|L2C_",
        "Bluetooth L2CAP activity -- relevant for BlueBorne research",
        ["bluetooth"]),
    SecurityRule("BT_BNEP", "HIGH",
        r"BNEP|bnep|BluetoothPan",
        "Bluetooth BNEP activity -- CVE-2017-0781/0782 surface",
        ["bluetooth", "vuln"]),
    SecurityRule("NETLINK_EVENT", "LOW",
        r"NETLINK|netlinkEvent|netlink_route",
        "Netlink event -- network subsystem activity",
        ["network"]),

    # -- Exploit tooling output --
    SecurityRule("EXPLOIT_OUTPUT", "INFO",
        r"\[PROBE\]|\[FUZZ\]|\[EXPLOIT\]|\[PRIVESC\]|\[RESULT\]",
        "Output from our exploit/fuzzer tooling",
        ["tooling"]),
    SecurityRule("PRIVESC_AGENT", "INFO",
        r"com\.privesc\.agent|PrivescAgent|AgentAccessibility|CommandReceiver",
        "Privesc agent APK activity",
        ["tooling", "agent"]),

    # -- Memory / ION --
    SecurityRule("ION_ALLOC", "MEDIUM",
        r"(?<![Ll]i-)\bION\b(?![-_]?[Pp]owered)|ion_alloc|ion_heap|ion_client|/dev/ion",
        "ION memory allocator activity -- potential attack surface",
        ["memory", "kernel"]),
    SecurityRule("ASHMEM", "LOW",
        r"\bashmem\b|\bASHMEM\b|/dev/ashmem",
        "Anonymous shared memory activity",
        ["memory"]),

    # -- Filesystem / Mount --
    SecurityRule("MOUNT_CHANGE", "HIGH",
        r"mount.*remount|mount.*rw|/system.*remount",
        "Filesystem remount detected -- possible write access gained",
        ["filesystem", "escalation"]),
    SecurityRule("PROC_ACCESS", "LOW",
        r"/proc/\w+/mem|/proc/\w+/maps|/proc/kallsyms",
        "Process memory or kernel symbols access",
        ["kernel", "recon"]),
]


class SecurityAnalyzer:
    """Applies rules to parsed log records and tracks statistics."""

    def __init__(self, rules=None):
        self.rules = rules or RULES
        self.stats = defaultdict(int)
        self.severity_counts = defaultdict(int)
        self.findings = []
        self.start_time = time.time()
        self.lines_processed = 0
        self.lock = threading.Lock()

    def analyze(self, record):
        """Check a parsed record against all rules. Returns list of matches."""
        if record is None:
            return []
        self.lines_processed += 1
        matches = []
        for rule in self.rules:
            m = rule.match(record)
            if m:
                finding = {
                    "rule": rule.name,
                    "severity": rule.severity,
                    "description": rule.description,
                    "tags": rule.tags,
                    "record": record,
                    "match": m.group(0),
                    "time": datetime.now().isoformat(),
                }
                with self.lock:
                    self.stats[rule.name] += 1
                    self.severity_counts[rule.severity] += 1
                    self.findings.append(finding)
                matches.append(finding)
        return matches

    def get_summary(self):
        elapsed = time.time() - self.start_time
        return {
            "elapsed_seconds": round(elapsed, 1),
            "lines_processed": self.lines_processed,
            "total_findings": len(self.findings),
            "by_severity": dict(self.severity_counts),
            "by_rule": dict(self.stats),
            "lines_per_second": round(self.lines_processed / max(elapsed, 0.1), 1),
        }


# --- Output formatters -----------------------------------------------------
SEVERITY_COLORS = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     DIM,
}


def format_finding_console(finding):
    sev = finding["severity"]
    color = SEVERITY_COLORS.get(sev, WHITE)
    rec = finding["record"]
    ts = rec.get("timestamp", "?")
    tag = rec.get("tag", "?")
    pid = rec.get("pid", "?")
    msg = rec.get("message", "")[:120]
    rule = finding["rule"]
    return (
        f"{color}[{sev:8s}]{RESET} "
        f"{DIM}{ts}{RESET} "
        f"{MAGENTA}{rule}{RESET} "
        f"{WHITE}{tag}{RESET}({pid}) "
        f"{msg}"
    )


def format_finding_json(finding):
    out = {
        "severity": finding["severity"],
        "rule": finding["rule"],
        "description": finding["description"],
        "tags": finding["tags"],
        "match": finding["match"],
        "timestamp": finding["record"].get("timestamp"),
        "pid": finding["record"].get("pid"),
        "tag": finding["record"].get("tag"),
        "message": finding["record"].get("message"),
        "source": finding["record"].get("source"),
    }
    return json.dumps(out)


# --- Stream handlers -------------------------------------------------------
def stream_logcat(analyzer, buffers, output_file, json_mode, quiet):
    """Stream live logcat and analyze in real-time."""
    buf_args = []
    for b in buffers:
        buf_args.extend(["-b", b])
    cmd = ["adb", "logcat"] + buf_args
    print(f"{GREEN}[*] Starting logcat stream: {' '.join(cmd)}{RESET}")
    sys.stdout.flush()

    # CREATE_NEW_PROCESS_GROUP prevents parent signal delivery from killing adb
    creationflags = 0
    if sys.platform == "win32":
        creationflags = 0x00000200  # CREATE_NEW_PROCESS_GROUP

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0, creationflags=creationflags
    )

    try:
        while True:
            raw = proc.stdout.readline()
            if not raw:
                rc = proc.poll()
                if rc is not None:
                    print(f"{RED}[!] adb logcat exited with code {rc}{RESET}")
                    sys.stdout.flush()
                    break
                continue
            line = raw.decode("utf-8", errors="replace")
            record = parse_logcat_line(line)
            if record is None:
                continue
            matches = analyzer.analyze(record)
            for finding in matches:
                if json_mode:
                    out = format_finding_json(finding)
                else:
                    out = format_finding_console(finding)
                print(out)
                sys.stdout.flush()
                if output_file:
                    output_file.write(format_finding_json(finding) + "\n")
                    output_file.flush()

            # Passthrough non-matched lines in verbose mode
            if not matches and not quiet:
                lvl = record.get("level", "?")
                if lvl in ("E", "W"):
                    color = RED if lvl == "E" else YELLOW
                    print(f"{DIM}{record['timestamp']}{RESET} "
                          f"{color}{lvl}{RESET} "
                          f"{record['tag']}({record['pid']}): "
                          f"{DIM}{record['message'][:100]}{RESET}")
                    sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def stream_dmesg(analyzer, output_file, json_mode):
    """Poll dmesg for new kernel messages (runs in background thread)."""
    last_ts = "0.0"
    while True:
        try:
            result = subprocess.run(
                ["adb", "shell", "dmesg"], capture_output=True,
                text=True, timeout=10, encoding="utf-8", errors="replace"
            )
            for line in result.stdout.splitlines():
                record = parse_dmesg_line(line)
                if record is None:
                    continue
                if record["timestamp"] <= last_ts:
                    continue
                last_ts = record["timestamp"]
                matches = analyzer.analyze(record)
                for finding in matches:
                    if json_mode:
                        out = format_finding_json(finding)
                    else:
                        out = format_finding_console(finding)
                    print(out)
                    if output_file:
                        output_file.write(format_finding_json(finding) + "\n")
                        output_file.flush()
        except (subprocess.TimeoutExpired, Exception):
            pass
        time.sleep(5)


def replay_file(analyzer, filepath, output_file, json_mode):
    """Analyze an existing logcat dump file."""
    print(f"{GREEN}[*] Replaying log file: {filepath}{RESET}")
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            record = parse_logcat_line(line)
            if record is None:
                record = parse_dmesg_line(line)
            if record is None:
                continue
            matches = analyzer.analyze(record)
            for finding in matches:
                if json_mode:
                    out = format_finding_json(finding)
                else:
                    out = format_finding_console(finding)
                print(out)
                if output_file:
                    output_file.write(format_finding_json(finding) + "\n")
                    output_file.flush()


def print_summary(analyzer):
    summary = analyzer.get_summary()
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Security Log Analysis Summary{RESET}")
    print(f"{'='*60}")
    print(f"  Lines processed:  {summary['lines_processed']:,}")
    print(f"  Total findings:   {summary['total_findings']:,}")
    print(f"  Duration:         {summary['elapsed_seconds']}s")
    print(f"  Throughput:       {summary['lines_per_second']:,} lines/sec")
    print()
    print(f"  {BOLD}By Severity:{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary["by_severity"].get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, WHITE)
            bar = "#" * min(count, 40)
            print(f"    {color}{sev:10s}{RESET}  {count:4d}  {color}{bar}{RESET}")
    print()
    if summary["by_rule"]:
        print(f"  {BOLD}Top Rules:{RESET}")
        sorted_rules = sorted(summary["by_rule"].items(), key=lambda x: -x[1])
        for rule, count in sorted_rules[:15]:
            print(f"    {rule:30s}  {count}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Real-time ADB logcat security analysis pipeline"
    )
    parser.add_argument("--buffers", nargs="+",
        default=["main", "system", "events", "radio"],
        help="Logcat buffers to monitor (default: main system events radio). "
             "Note: 'crash' buffer not supported on Android 6.0.1")
    parser.add_argument("--replay", type=str, default=None,
        help="Replay/analyze an existing logcat dump file instead of live stream")
    parser.add_argument("--dmesg", action="store_true",
        help="Also poll kernel dmesg for messages (every 5s)")
    parser.add_argument("--json", action="store_true",
        help="Output findings as JSON lines")
    parser.add_argument("--output", type=str, default=None,
        help="Write findings (JSON) to this file")
    parser.add_argument("--quiet", action="store_true",
        help="Only show security findings, suppress non-matching lines")
    parser.add_argument("--summary-interval", type=int, default=60,
        help="Print summary every N seconds (0=disable, default=60)")
    args = parser.parse_args()

    analyzer = SecurityAnalyzer()
    output_file = None
    if args.output:
        output_file = open(args.output, "a", encoding="utf-8")

    # Graceful shutdown
    def signal_handler(sig, frame):
        print(f"\n{YELLOW}[!] Interrupted -- printing summary...{RESET}")
        print_summary(analyzer)
        if output_file:
            output_file.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    # Periodic summary thread
    if args.summary_interval > 0:
        def periodic_summary():
            while True:
                time.sleep(args.summary_interval)
                print_summary(analyzer)
        t = threading.Thread(target=periodic_summary, daemon=True)
        t.start()

    print(f"{BOLD}{GREEN}")
    print("  +==================================================+")
    print("  |   Logcat Security Monitor -- SM-T377A Research   |")
    print("  |   Press Ctrl+C for summary and exit              |")
    print("  +==================================================+")
    print(f"{RESET}")
    print(f"  Rules loaded: {len(RULES)}")
    print(f"  Mode: {'replay' if args.replay else 'live'}")
    if not args.replay:
        print(f"  Buffers: {', '.join(args.buffers)}")
        print(f"  Dmesg polling: {'enabled' if args.dmesg else 'disabled'}")
    print(f"  Output file: {args.output or 'none'}")
    print(f"  Quiet mode: {args.quiet}")
    print()

    if args.replay:
        replay_file(analyzer, args.replay, output_file, args.json)
        print_summary(analyzer)
    else:
        if args.dmesg:
            dmesg_thread = threading.Thread(
                target=stream_dmesg, args=(analyzer, output_file, args.json),
                daemon=True
            )
            dmesg_thread.start()
        stream_logcat(analyzer, args.buffers, output_file, args.json, args.quiet)

    if output_file:
        output_file.close()


if __name__ == "__main__":
    main()
