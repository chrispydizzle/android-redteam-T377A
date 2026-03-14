#!/usr/bin/env python3
"""
Samsung Odin/LOKE protocol client over serial (COM port).
Talks to devices in Download Mode via the Samsung USB CDC modem interface.

Target: SM-T377A on COM13 (VID_04E8&PID_685D)
"""

import serial
import struct
import sys
import os
import time
import argparse

# Protocol constants
ODIN_HANDSHAKE = b"ODIN"
LOKE_RESPONSE = b"LOKE"

# Request types (first byte of command packet)
SESSION_START = 0x64
PIT_XFER = 0x65
FILE_XFER = 0x66
SESSION_END = 0x67

# Session subtypes
SESSION_BEGIN = 0x00
SESSION_DEVICE_TYPE = 0x01
SESSION_TOTAL_BYTES = 0x02
SESSION_FILE_PART_SIZE = 0x05
SESSION_TFLASH = 0x08

# PIT subtypes
PIT_REQUEST = 0x01
PIT_DUMP_BLOCK = 0x02
PIT_END = 0x03

# Session end subtypes
END_NO_REBOOT = 0x00
END_REBOOT = 0x01

# PIT block size
PIT_BLOCK_SIZE = 500

# PIT entry structure (132 bytes per entry in v2 PIT)
PIT_ENTRY_SIZE = 132
PIT_HEADER_SIZE = 28

# Protocol versions
PROTO_V3 = 0x03
PROTO_V4 = 0x04

# Timeouts
DEFAULT_TIMEOUT = 10
HANDSHAKE_TIMEOUT = 5


class OdinProtocol:
    """Low-level Odin/LOKE protocol implementation over serial."""

    def __init__(self, port, baudrate=115200, timeout=DEFAULT_TIMEOUT, verbose=False):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.verbose = verbose
        self.ser = None
        self.session_active = False
        self.protocol_version = PROTO_V3

    def log(self, msg):
        if self.verbose:
            print(f"[ODIN] {msg}")

    def hexdump(self, data, prefix=""):
        """Print hex dump of data."""
        if not self.verbose or not data:
            return
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{prefix}{i:04x}: {hex_str:<48s} {ascii_str}")

    def connect(self):
        """Open serial port."""
        self.log(f"Opening {self.port} at {self.baudrate} baud")
        self.ser = serial.Serial(
            port=self.port,
            baudrate=self.baudrate,
            timeout=self.timeout,
            write_timeout=self.timeout,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            rtscts=False,
            dsrdtr=False,
        )
        # Flush any stale data
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        self.log(f"Port opened: {self.ser.name}")
        return True

    def close(self):
        """Close serial port."""
        if self.ser and self.ser.is_open:
            self.ser.close()
            self.log("Port closed")

    def send(self, data):
        """Send raw data."""
        self.log(f"TX ({len(data)} bytes):")
        self.hexdump(data, "  TX ")
        self.ser.write(data)
        self.ser.flush()

    def recv(self, size, timeout=None):
        """Receive exact number of bytes."""
        old_timeout = self.ser.timeout
        if timeout is not None:
            self.ser.timeout = timeout
        try:
            data = self.ser.read(size)
            self.log(f"RX ({len(data)}/{size} bytes):")
            self.hexdump(data, "  RX ")
            return data
        finally:
            self.ser.timeout = old_timeout

    def recv_available(self, timeout=2):
        """Read whatever is available."""
        old_timeout = self.ser.timeout
        self.ser.timeout = timeout
        try:
            data = b""
            while True:
                chunk = self.ser.read(1024)
                if not chunk:
                    break
                data += chunk
            self.log(f"RX available ({len(data)} bytes):")
            self.hexdump(data, "  RX ")
            return data
        finally:
            self.ser.timeout = old_timeout

    def send_packet(self, *args):
        """Send a command packet as a sequence of 32-bit LE integers."""
        packet = b""
        for val in args:
            packet += struct.pack("<I", val)
        self.send(packet)

    def recv_int(self, count=1, timeout=None):
        """Receive one or more 32-bit LE integers."""
        data = self.recv(4 * count, timeout=timeout)
        if len(data) < 4 * count:
            return None
        if count == 1:
            return struct.unpack("<I", data[:4])[0]
        return struct.unpack(f"<{count}I", data[:4*count])

    # ── Handshake ──

    def handshake(self):
        """Perform ODIN/LOKE handshake."""
        print("[*] Sending ODIN handshake...")
        self.send(ODIN_HANDSHAKE)
        resp = self.recv(4, timeout=HANDSHAKE_TIMEOUT)
        if resp == LOKE_RESPONSE:
            print("[+] Received LOKE response — device is in Download Mode!")
            return True
        elif resp:
            print(f"[-] Unexpected handshake response: {resp!r}")
            # Try reading more
            extra = self.recv_available(timeout=2)
            if extra:
                print(f"    Additional data: {extra!r}")
            return False
        else:
            print("[-] No handshake response (timeout)")
            return False

    # ── Session management ──

    def begin_session(self, protocol_version=PROTO_V3):
        """Begin Odin session."""
        print(f"[*] Beginning session (protocol v{protocol_version})...")
        self.send_packet(SESSION_START, SESSION_BEGIN, protocol_version)
        resp = self.recv(8, timeout=5)
        if resp and len(resp) >= 4:
            val = struct.unpack("<I", resp[:4])[0]
            if val == SESSION_START:
                print("[+] Session started")
                self.session_active = True
                self.protocol_version = protocol_version
                if len(resp) >= 8:
                    param = struct.unpack("<I", resp[4:8])[0]
                    self.log(f"  Session param: 0x{param:08x}")
                return True
            else:
                print(f"[-] Unexpected session response: 0x{val:08x}")
                self.hexdump(resp, "  ")
        else:
            print(f"[-] Session begin failed, got {len(resp) if resp else 0} bytes")
            if resp:
                self.hexdump(resp, "  ")
        return False

    def end_session(self, reboot=False):
        """End Odin session."""
        subtype = END_REBOOT if reboot else END_NO_REBOOT
        action = "reboot" if reboot else "no-reboot"
        print(f"[*] Ending session ({action})...")
        self.send_packet(SESSION_END, subtype)
        resp = self.recv(8, timeout=5)
        if resp and len(resp) >= 4:
            val = struct.unpack("<I", resp[:4])[0]
            if val == SESSION_END:
                print("[+] Session ended")
                self.session_active = False
                return True
        print("[-] Session end — no clean response")
        self.session_active = False
        return False

    def get_device_type(self):
        """Query device type."""
        self.log("Querying device type...")
        self.send_packet(SESSION_START, SESSION_DEVICE_TYPE)
        resp = self.recv(8, timeout=5)
        if resp and len(resp) >= 8:
            cmd, dtype = struct.unpack("<II", resp[:8])
            if cmd == SESSION_START:
                print(f"[+] Device type: {dtype}")
                return dtype
        return None

    # ── PIT operations ──

    def download_pit(self):
        """Download PIT (Partition Information Table) from device."""
        print("[*] Requesting PIT file...")

        # Request PIT
        self.send_packet(PIT_XFER, PIT_REQUEST)
        resp = self.recv(8, timeout=10)

        if not resp or len(resp) < 8:
            print(f"[-] PIT request failed — got {len(resp) if resp else 0} bytes")
            if resp:
                self.hexdump(resp, "  ")
            return None

        cmd, pit_size = struct.unpack("<II", resp[:8])
        if cmd != PIT_XFER:
            print(f"[-] Unexpected PIT response cmd: 0x{cmd:08x}")
            return None

        print(f"[+] PIT file size: {pit_size} bytes")

        if pit_size == 0 or pit_size > 65536:
            print(f"[-] Suspicious PIT size: {pit_size}")
            return None

        # Calculate blocks
        num_blocks = (pit_size + PIT_BLOCK_SIZE - 1) // PIT_BLOCK_SIZE
        print(f"[*] Downloading {num_blocks} blocks ({PIT_BLOCK_SIZE} bytes each)...")

        pit_data = b""
        for block_idx in range(num_blocks):
            self.send_packet(PIT_XFER, PIT_DUMP_BLOCK, block_idx)
            block = self.recv(PIT_BLOCK_SIZE, timeout=5)
            if not block:
                print(f"[-] Failed to receive block {block_idx}")
                return None
            pit_data += block
            if self.verbose:
                print(f"  Block {block_idx}/{num_blocks}: {len(block)} bytes")

        # Trim to actual size
        pit_data = pit_data[:pit_size]

        # End PIT transfer
        self.send_packet(PIT_XFER, PIT_END)
        resp = self.recv(8, timeout=5)
        if resp and len(resp) >= 4:
            val = struct.unpack("<I", resp[:4])[0]
            if val == PIT_XFER:
                print("[+] PIT transfer complete")

        return pit_data

    # ── PIT parsing ──

    @staticmethod
    def parse_pit(data):
        """Parse PIT binary data into structured partition info."""
        if len(data) < PIT_HEADER_SIZE:
            print(f"[-] PIT data too small: {len(data)} bytes")
            return None

        # PIT header (28 bytes)
        magic = struct.unpack("<I", data[0:4])[0]
        entry_count = struct.unpack("<I", data[4:8])[0]

        # Rest of header bytes (unknown/reserved)
        gang_name = data[8:16].split(b'\x00')[0].decode('ascii', errors='replace')
        project_name = data[16:24].split(b'\x00')[0].decode('ascii', errors='replace')

        print(f"\n{'='*70}")
        print(f"PIT Header")
        print(f"{'='*70}")
        print(f"  Magic:        0x{magic:08X}")
        print(f"  Entry count:  {entry_count}")
        print(f"  Gang name:    '{gang_name}'")
        print(f"  Project name: '{project_name}'")
        print(f"{'='*70}\n")

        partitions = []
        offset = PIT_HEADER_SIZE

        for i in range(entry_count):
            if offset + PIT_ENTRY_SIZE > len(data):
                print(f"[-] Truncated at entry {i}")
                break

            entry = data[offset:offset + PIT_ENTRY_SIZE]

            # Parse PIT entry (v2 format, 132 bytes)
            (binary_type, device_type, identifier, attributes,
             update_attributes, block_size_or_offset, block_count,
             file_offset, file_size) = struct.unpack("<9I", entry[0:36])

            partition_name = entry[36:68].split(b'\x00')[0].decode('ascii', errors='replace')
            flash_filename = entry[68:100].split(b'\x00')[0].decode('ascii', errors='replace')
            fota_filename = entry[100:132].split(b'\x00')[0].decode('ascii', errors='replace')

            part = {
                'index': i,
                'binary_type': binary_type,  # 0=AP, 1=CP
                'device_type': device_type,  # 0=OneNAND, 1=NAND, 2=MMC
                'identifier': identifier,
                'attributes': attributes,
                'update_attributes': update_attributes,
                'block_offset': block_size_or_offset,
                'block_count': block_count,
                'file_offset': file_offset,
                'file_size': file_size,
                'partition_name': partition_name,
                'flash_filename': flash_filename,
                'fota_filename': fota_filename,
            }
            partitions.append(part)
            offset += PIT_ENTRY_SIZE

        return {
            'magic': magic,
            'entry_count': entry_count,
            'gang_name': gang_name,
            'project_name': project_name,
            'partitions': partitions,
        }

    @staticmethod
    def print_pit(pit_info):
        """Pretty-print parsed PIT information."""
        if not pit_info:
            return

        binary_types = {0: "AP", 1: "CP"}
        device_types = {0: "OneNAND", 1: "NAND", 2: "eMMC"}

        print(f"{'#':>3} {'Name':<20} {'Type':>4} {'Dev':>6} {'ID':>5} "
              f"{'Offset':>12} {'Blocks':>12} {'Size(MB)':>10} {'Flash File':<24} {'FOTA File'}")
        print("-" * 130)

        for p in pit_info['partitions']:
            bt = binary_types.get(p['binary_type'], f"?{p['binary_type']}")
            dt = device_types.get(p['device_type'], f"?{p['device_type']}")
            size_mb = (p['block_count'] * 512) / (1024 * 1024) if p['block_count'] else 0

            print(f"{p['index']:>3} {p['partition_name']:<20} {bt:>4} {dt:>6} {p['identifier']:>5} "
                  f"{p['block_offset']:>12} {p['block_count']:>12} {size_mb:>10.1f} "
                  f"{p['flash_filename']:<24} {p['fota_filename']}")


def probe_port(port, verbose=False):
    """Quick probe — try handshake only."""
    odin = OdinProtocol(port, verbose=verbose)
    try:
        odin.connect()

        # Try multiple handshake approaches
        # Approach 1: Standard ODIN handshake
        if odin.handshake():
            return odin

        # Approach 2: Some devices need DTR/RTS toggling
        print("[*] Trying with DTR/RTS toggle...")
        odin.ser.dtr = True
        odin.ser.rts = True
        time.sleep(0.5)
        odin.ser.dtr = False
        odin.ser.rts = False
        time.sleep(0.5)
        odin.ser.reset_input_buffer()
        if odin.handshake():
            return odin

        # Approach 3: Read what the device sends on connect
        print("[*] Listening for device data...")
        odin.ser.reset_input_buffer()
        data = odin.recv_available(timeout=3)
        if data:
            print(f"[*] Device sent {len(data)} bytes on connect")

        odin.close()
        return None
    except serial.SerialException as e:
        print(f"[-] Serial error: {e}")
        odin.close()
        return None


def download_pit_file(port, output_path, verbose=False):
    """Full PIT download sequence."""
    odin = probe_port(port, verbose=verbose)
    if not odin:
        print("[-] Handshake failed — cannot proceed")
        return False

    try:
        # Begin session
        if not odin.begin_session(PROTO_V3):
            # Try v4
            print("[*] Retrying with protocol v4...")
            odin.ser.reset_input_buffer()
            if not odin.handshake():
                return False
            if not odin.begin_session(PROTO_V4):
                return False

        # Get device type
        odin.get_device_type()

        # Download PIT
        pit_data = odin.download_pit()
        if pit_data:
            # Save raw PIT
            with open(output_path, 'wb') as f:
                f.write(pit_data)
            print(f"[+] PIT saved to {output_path} ({len(pit_data)} bytes)")

            # Parse and display
            pit_info = OdinProtocol.parse_pit(pit_data)
            if pit_info:
                OdinProtocol.print_pit(pit_info)

            # End session without reboot
            odin.end_session(reboot=False)
            return True
        else:
            print("[-] PIT download failed")
            odin.end_session(reboot=False)
            return False

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        try:
            odin.end_session(reboot=False)
        except:
            pass
        return False
    finally:
        odin.close()


def probe_only(port, verbose=False):
    """Just test connectivity and handshake."""
    odin = probe_port(port, verbose=verbose)
    if odin:
        print("\n[+] Device is responsive!")
        # Try session
        if odin.begin_session():
            odin.get_device_type()
            odin.end_session(reboot=False)
        odin.close()
        return True
    return False


def parse_pit_file(path):
    """Parse and display an existing PIT file."""
    with open(path, 'rb') as f:
        data = f.read()
    print(f"[*] Parsing PIT file: {path} ({len(data)} bytes)")
    pit_info = OdinProtocol.parse_pit(data)
    if pit_info:
        OdinProtocol.print_pit(pit_info)
    return pit_info


def main():
    parser = argparse.ArgumentParser(description="Samsung Odin/LOKE protocol client")
    parser.add_argument("action", choices=["probe", "pit", "parse-pit"],
                       help="Action: probe=test connection, pit=download PIT, parse-pit=parse local PIT file")
    parser.add_argument("--port", default="COM13", help="Serial port (default: COM13)")
    parser.add_argument("--output", default=None, help="Output file for PIT download")
    parser.add_argument("--input", default=None, help="Input PIT file for parse-pit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output with hex dumps")
    args = parser.parse_args()

    if args.action == "probe":
        probe_only(args.port, verbose=args.verbose)

    elif args.action == "pit":
        output = args.output or os.path.join("data", "sm-t377a.pit")
        download_pit_file(args.port, output, verbose=args.verbose)

    elif args.action == "parse-pit":
        path = args.input
        if not path:
            print("[-] --input required for parse-pit")
            sys.exit(1)
        parse_pit_file(path)


if __name__ == "__main__":
    main()
