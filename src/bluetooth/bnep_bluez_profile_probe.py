#!/usr/bin/env python3
"""Own the host NAP socket via BlueZ Profile1 and dump inbound BNEP setup traffic.

This is the host-side replacement for temporary `NetworkServer1.Register("nap", ...)`
helpers when we need the live inbound BNEP socket delivered to our code.

Important:
  * Run this on the Linux Bluetooth host, not on Windows.
  * BlueZ's stock network plugin must be disabled first (for example by running a
    custom `bluetoothd -n -d -P network`) or the standard NAP UUID/PSM will
    already be owned by bluetoothd.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from bnep_harness import (
    build_extension_tail,
    make_setup_request,
    make_setup_response,
    parse_setup_request,
    parse_setup_response,
    parse_uuid_pair,
)


NAP_UUID = "00001116-0000-1000-8000-00805f9b34fb"
PROFILE_PATH = "/com/androidredteam/bnepnapprobe"

RESPONSE_MODES = {
    "success": 0,
    "invalid-dst": 1,
    "invalid-src": 2,
    "invalid-uuid-size": 3,
    "conn-not-allowed": 4,
    "none": None,
}


def describe_setup_request(payload):
    parsed = parse_setup_request(payload)
    if not parsed:
        return None
    if "src_uuid" not in parsed or "dst_uuid" not in parsed:
        return "setup-req uuid_size=%d unsupported/raw=%s" % (
            parsed["uuid_size"],
            parsed["raw"].hex(),
        )
    return "setup-req uuid_size=%d src=0x%04x dst=0x%04x tail=%s" % (
        parsed["uuid_size"],
        parsed["src_uuid"],
        parsed["dst_uuid"],
        parsed["tail"].hex(),
    )


def describe_setup_response(payload):
    parsed = parse_setup_response(payload)
    if not parsed:
        return None
    code, label = parsed
    return "setup-rsp code=%d %s raw=%s" % (code, label, payload.hex())


class BnepConnection:
    def __init__(self, fd, args):
        self._fd = fd
        self._args = args
        self._sock = None
        self._responded = False

    def _ensure_socket(self):
        if self._sock is not None:
            return
        self._sock = socket.fromfd(
            self._fd,
            socket.AF_BLUETOOTH,
            socket.SOCK_SEQPACKET,
            socket.BTPROTO_L2CAP,
        )
        os.close(self._fd)
        self._fd = -1

    def _probe_frame(self, uuid_pair, tail_bytes):
        extension_tail = build_extension_tail(tail_bytes) if tail_bytes > 0 else b""
        return make_setup_request(uuid_pair[0], uuid_pair[1], extension_tail=extension_tail)

    def _send_probe_requests(self):
        if self._args.setup_a is None:
            return False

        if self._args.send_after_ms > 0:
            time.sleep(self._args.send_after_ms / 1000.0)

        frame_a = self._probe_frame(self._args.setup_a, self._args.setup_a_tail_bytes)
        self._sock.sendall(frame_a)
        print(
            "[->] probe setup A src=0x%04x dst=0x%04x tail_len=%d raw=%s"
            % (
                self._args.setup_a[0],
                self._args.setup_a[1],
                max(0, len(frame_a) - 7),
                frame_a.hex(),
            ),
            flush=True,
        )

        if self._args.setup_b is None:
            return True

        if self._args.setup_delay_ms > 0:
            time.sleep(self._args.setup_delay_ms / 1000.0)

        frame_b = self._probe_frame(self._args.setup_b, self._args.setup_b_tail_bytes)
        self._sock.sendall(frame_b)
        print(
            "[->] probe setup B src=0x%04x dst=0x%04x tail_len=%d raw=%s"
            % (
                self._args.setup_b[0],
                self._args.setup_b[1],
                max(0, len(frame_b) - 7),
                frame_b.hex(),
            ),
            flush=True,
        )
        return True

    def handle(self):
        self._ensure_socket()
        deadline = time.monotonic() + self._args.window
        probe_close_deadline = None
        frame_index = 0
        probe_sent = False

        while frame_index < self._args.max_frames and time.monotonic() < deadline:
            remaining_window = deadline - time.monotonic()
            if probe_close_deadline is not None:
                remaining_window = min(remaining_window, probe_close_deadline - time.monotonic())
                if remaining_window <= 0:
                    print("[*] Probe close deadline reached", flush=True)
                    break
            self._sock.settimeout(max(0.05, min(self._args.recv_timeout, remaining_window)))
            try:
                payload = self._sock.recv(4096)
            except socket.timeout:
                break

            if not payload:
                print("[*] Peer closed the BNEP socket", flush=True)
                break

            frame_index += 1
            print(
                "[<-] frame %d len=%d raw=%s" % (frame_index, len(payload), payload.hex()),
                flush=True,
            )
            setup_desc = describe_setup_request(payload)
            if setup_desc:
                print("     %s" % setup_desc, flush=True)
                if not self._responded:
                    response_code = RESPONSE_MODES[self._args.response]
                    if response_code is not None:
                        frame = make_setup_response(response_code)
                        self._sock.sendall(frame)
                        print(
                            "[->] setup-rsp code=%d raw=%s" % (response_code, frame.hex()),
                            flush=True,
                        )
                    self._responded = True
                    if not probe_sent:
                        probe_sent = self._send_probe_requests()
                        if probe_sent and self._args.close_after_probe_ms > 0:
                            probe_close_deadline = (
                                time.monotonic() + (self._args.close_after_probe_ms / 1000.0)
                            )

            response_desc = describe_setup_response(payload)
            if response_desc:
                print("     %s" % response_desc, flush=True)

        if self._args.hold_seconds > 0:
            print("[*] Holding socket open for %.2fs" % self._args.hold_seconds, flush=True)
            time.sleep(self._args.hold_seconds)

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        elif self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1


class NapProfile(dbus.service.Object):
    def __init__(self, bus, path, args, loop):
        super().__init__(bus, path)
        self._args = args
        self._loop = loop

    @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
    def Release(self):
        print("[*] BlueZ released the profile", flush=True)
        self._loop.quit()

    @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
    def Cancel(self):
        print("[*] BlueZ canceled the profile", flush=True)
        self._loop.quit()

    @dbus.service.method("org.bluez.Profile1", in_signature="oha{sv}", out_signature="")
    def NewConnection(self, path, fd, properties):
        taken_fd = fd.take()
        print("[+] NewConnection path=%s fd=%d" % (path, taken_fd), flush=True)
        print("[*] Properties=%r" % dict(properties), flush=True)

        conn = BnepConnection(taken_fd, self._args)
        try:
            conn.handle()
        finally:
            conn.close()

        if self._args.quit_after_connection:
            self._loop.quit()

    @dbus.service.method("org.bluez.Profile1", in_signature="o", out_signature="")
    def RequestDisconnection(self, path):
        print("[*] RequestDisconnection path=%s" % path, flush=True)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--response",
        choices=sorted(RESPONSE_MODES),
        default="success",
        help="Optional Setup Conn Response code to send after the first setup request",
    )
    parser.add_argument(
        "--recv-timeout",
        type=float,
        default=5.0,
        help="Seconds to wait per recv() before ending the capture window",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=10.0,
        help="Overall seconds to keep collecting BNEP frames on one connection",
    )
    parser.add_argument(
        "--hold-seconds",
        type=float,
        default=0.0,
        help="Keep the accepted socket open for extra time after frame capture",
    )
    parser.add_argument(
        "--max-frames",
        type=int,
        default=8,
        help="Maximum number of inbound BNEP frames to print per connection",
    )
    parser.add_argument(
        "--quit-after-connection",
        action="store_true",
        help="Exit after the first accepted connection instead of waiting for more",
    )
    parser.add_argument(
        "--setup-a",
        type=parse_uuid_pair,
        help="After answering the tablet's setup request, send one host-initiated setup request (hex src:dst)",
    )
    parser.add_argument(
        "--setup-a-tail-bytes",
        type=int,
        default=0,
        help="Append an approximate deferred-extension tail of this size to host probe setup A",
    )
    parser.add_argument(
        "--setup-b",
        type=parse_uuid_pair,
        help="Optional second host-initiated setup request (hex src:dst)",
    )
    parser.add_argument(
        "--setup-b-tail-bytes",
        type=int,
        default=0,
        help="Append an approximate deferred-extension tail of this size to host probe setup B",
    )
    parser.add_argument(
        "--send-after-ms",
        type=int,
        default=100,
        help="Delay after the initial setup response before sending host probe setup A",
    )
    parser.add_argument(
        "--setup-delay-ms",
        type=int,
        default=0,
        help="Delay between host probe setup A and setup B",
    )
    parser.add_argument(
        "--close-after-probe-ms",
        type=int,
        default=0,
        help="Close the accepted socket this many milliseconds after sending host probe traffic",
    )
    return parser


def main():
    args = build_parser().parse_args()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    loop = GLib.MainLoop()
    manager = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"), "org.bluez.ProfileManager1")
    profile = NapProfile(bus, PROFILE_PATH, args, loop)
    options = {
        "Name": "android-redteam BNEP NAP probe",
        "Role": "server",
        "PSM": dbus.UInt16(0x000F),
        "RequireAuthentication": True,
    }

    try:
        manager.RegisterProfile(PROFILE_PATH, NAP_UUID, options)
    except dbus.exceptions.DBusException as exc:
        print("[-] RegisterProfile failed: %s" % exc, file=sys.stderr, flush=True)
        print(
            "    Hint: stop the stock bluetooth service and run a custom bluetoothd with '-P network' first.",
            file=sys.stderr,
            flush=True,
        )
        return 1

    print("[*] Registered NAP profile on PSM 0x000f", flush=True)
    print("[*] Response mode: %s" % args.response, flush=True)
    if args.setup_a:
        print(
            "[*] Host probe setup A: src=0x%04x dst=0x%04x tail=%d after %dms"
            % (args.setup_a[0], args.setup_a[1], args.setup_a_tail_bytes, args.send_after_ms),
            flush=True,
        )
    if args.setup_b:
        print(
            "[*] Host probe setup B: src=0x%04x dst=0x%04x tail=%d after +%dms"
            % (args.setup_b[0], args.setup_b[1], args.setup_b_tail_bytes, args.setup_delay_ms),
            flush=True,
        )
    if args.close_after_probe_ms > 0:
        print("[*] Close after probe: %dms" % args.close_after_probe_ms, flush=True)
    try:
        loop.run()
    finally:
        try:
            manager.UnregisterProfile(PROFILE_PATH)
        except dbus.exceptions.DBusException:
            pass
        del profile
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
