#!/usr/bin/env python3
"""Common raw-HCI BNEP harness helpers for userspace Bluetooth probes."""

import argparse
import configparser
import glob
import socket
import struct
import subprocess
import time

try:
    from scapy.layers.bluetooth import (
        BluetoothUserSocket,
        HCI_ACL_Hdr,
        HCI_Command_Hdr,
        HCI_Event_Hdr,
        HCI_Hdr,
        L2CAP_Hdr,
    )
    from scapy.packet import Raw
except Exception:
    BluetoothUserSocket = None
    HCI_ACL_Hdr = None
    HCI_Command_Hdr = None
    HCI_Event_Hdr = None
    HCI_Hdr = None
    L2CAP_Hdr = None
    Raw = None

DEFAULT_TARGET = "02:00:00:00:00:21"
CID_SIG = 0x0001
DEFAULT_SCID = 0x0040
PSM_BNEP = 0x000F

SETUP_RESPONSE_CODES = {
    0: "SUCCESS",
    1: "INVALID_DST_UUID",
    2: "INVALID_SRC_UUID",
    3: "INVALID_UUID_SIZE",
    4: "CONN_NOT_ALLOWED",
}


def l2cmd(code, ident, data):
    return struct.pack("<BBH", code, ident, len(data)) + data


def parse_uuid_pair(text):
    parts = text.replace(",", ":").split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("UUID pair must look like 1115:1116")
    try:
        return tuple(int(part, 16) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def normalize_bdaddr(addr):
    return ":".join(part.upper() for part in addr.split(":"))


def bdaddr_to_bytes(addr):
    return bytes.fromhex(addr.replace(":", ""))[::-1]


def bdaddr_from_hci(raw_addr):
    return ":".join("%02X" % byte for byte in raw_addr[::-1])


def load_bluez_link_key(target, base_dir="/var/lib/bluetooth"):
    target = normalize_bdaddr(target)
    matches = glob.glob("%s/*/%s/info" % (base_dir, target))
    parser = configparser.ConfigParser()
    for path in matches:
        try:
            parser.read(path)
            key = parser.get("LinkKey", "Key")
        except Exception:
            continue
        key = key.strip().replace(" ", "")
        if len(key) == 32:
            return bytes.fromhex(key)
    return None


def bt_recv(bt, timeout_s=0.5):
    bt.ins.settimeout(timeout_s)
    try:
        return bt.recv()
    except (socket.timeout, BlockingIOError, OSError):
        return None


def scapy_available():
    return BluetoothUserSocket is not None


def require_scapy():
    if not scapy_available():
        raise RuntimeError("scapy Bluetooth support is unavailable; use --transport l2cap or install scapy")


def l2cap_available():
    return getattr(socket, "AF_BLUETOOTH", None) is not None and getattr(socket, "BTPROTO_L2CAP", None) is not None


def open_l2cap_socket(target, timeout_s=15.0, psm=PSM_BNEP):
    if not l2cap_available():
        raise RuntimeError("AF_BLUETOOTH/BTPROTO_L2CAP is unavailable on this host")
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
    sock.settimeout(timeout_s)
    sock.connect((target, psm))
    return sock


def close_l2cap_socket(sock):
    try:
        sock.close()
    except Exception:
        pass


def collect_l2cap_payloads(sock, window_s, timeout_s=0.1):
    payloads = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        try:
            sock.settimeout(min(timeout_s, max(0.01, deadline - time.monotonic())))
            payload = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if not payload:
            break
        payloads.append({"kind": "data", "ts": time.monotonic(), "cid": None, "payload": payload})
    return payloads


def choose_transport(mode):
    if mode == "auto":
        if l2cap_available():
            return "l2cap"
        if scapy_available():
            return "raw-hci"
        raise RuntimeError("no usable Bluetooth transport found (need L2CAP socket support or scapy raw-HCI support)")
    if mode == "l2cap":
        if not l2cap_available():
            raise RuntimeError("L2CAP socket support is unavailable on this host")
        return "l2cap"
    if mode == "raw-hci":
        require_scapy()
        return "raw-hci"
    raise ValueError("unknown transport mode %r" % (mode,))


def stop_host_bluetooth():
    subprocess.run(["systemctl", "stop", "bluetooth"], capture_output=True, check=False)
    subprocess.run(["hciconfig", "hci0", "down"], capture_output=True, check=False)
    time.sleep(0.5)


def open_user_socket():
    require_scapy()
    stop_host_bluetooth()
    bt = BluetoothUserSocket(0)

    bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x0003))
    time.sleep(1.0)
    for _ in range(10):
        bt_recv(bt, 0.3)

    bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x03, ocf=0x001A, len=1) / Raw(b"\x03"))
    time.sleep(0.3)
    for _ in range(5):
        bt_recv(bt, 0.3)

    return bt


def connect_acl(bt, target, timeout_s=60.0):
    addr = bdaddr_to_bytes(target)
    params = addr + struct.pack("<HBBHB", 0xCC18, 0x02, 0x00, 0x0000, 0x01)
    bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0005, len=len(params)) / Raw(params))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pkt = bt_recv(bt, 1.0)
        if pkt is None:
            continue
        if HCI_Event_Hdr not in pkt:
            continue
        evt = pkt[HCI_Event_Hdr]
        raw_evt = bytes(evt.payload)
        if evt.code != 0x03 or len(raw_evt) < 3:
            continue
        status = raw_evt[0]
        if status != 0:
            raise RuntimeError("ACL connection failed with status 0x%02x" % status)
        return struct.unpack("<H", raw_evt[1:3])[0]

    raise RuntimeError("timed out waiting for ACL connection complete")


def close_acl(bt, handle):
    try:
        bt.send(
            HCI_Hdr(type=1)
            / HCI_Command_Hdr(ogf=0x01, ocf=0x0006, len=3)
            / Raw(struct.pack("<HB", handle, 0x13))
        )
    except Exception:
        pass
    time.sleep(0.3)
    try:
        bt.close()
    except Exception:
        pass


def send_sig(bt, handle, data):
    require_scapy()
    pkt = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0, BC=0) / L2CAP_Hdr(cid=CID_SIG) / Raw(data)
    bt.send(pkt)


def send_data(bt, handle, cid, data):
    require_scapy()
    pkt = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0, BC=0) / L2CAP_Hdr(cid=cid) / Raw(data)
    bt.send(pkt)


def iter_packet_l2cap_records(pkt):
    if pkt is not None and HCI_ACL_Hdr in pkt and L2CAP_Hdr in pkt:
        l2cap = pkt[L2CAP_Hdr]
        yield l2cap.cid, bytes(l2cap.payload)
        return
    yield from iter_l2cap_records(bytes(pkt))


def iter_l2cap_records(raw_bytes):
    for idx in range(max(0, len(raw_bytes) - 7)):
        try:
            length, cid = struct.unpack("<HH", raw_bytes[idx : idx + 4])
        except struct.error:
            continue
        if length < 4 or length > 4096 or idx + 4 + length > len(raw_bytes):
            continue
        payload = raw_bytes[idx + 4 : idx + 4 + length]
        yield cid, payload


def parse_sig_payload(payload):
    if len(payload) < 4:
        return None
    code = payload[0]
    ident = payload[1]
    slen = struct.unpack("<H", payload[2:4])[0]
    if 4 + slen > len(payload):
        return None
    return code, ident, payload[4 : 4 + slen]


def wait_for_incoming_acl_connection(bt, target, timeout_s=60.0, role=0x00):
    target = normalize_bdaddr(target)
    accepted = False
    request_addr = None
    events = []
    deadline = time.monotonic() + timeout_s

    while time.monotonic() < deadline:
        pkt = bt_recv(bt, 1.0)
        if pkt is None or HCI_Event_Hdr not in pkt:
            continue

        evt = pkt[HCI_Event_Hdr]
        raw_evt = bytes(evt.payload)
        now = time.monotonic()

        if evt.code == 0x04 and len(raw_evt) >= 10:
            peer = bdaddr_from_hci(raw_evt[:6])
            link_type = raw_evt[9]
            events.append({"kind": "hci", "ts": now, "event": "conn_req", "peer": peer, "link_type": link_type})
            if peer != target or link_type != 0x01:
                continue
            request_addr = raw_evt[:6]
            params = request_addr + bytes([role])
            bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x0009, len=len(params)) / Raw(params))
            accepted = True
            events.append({"kind": "hci", "ts": time.monotonic(), "event": "accept_sent", "peer": peer, "role": role})
            continue

        if evt.code == 0x03 and len(raw_evt) >= 11:
            status = raw_evt[0]
            handle = struct.unpack("<H", raw_evt[1:3])[0]
            peer = bdaddr_from_hci(raw_evt[3:9])
            link_type = raw_evt[9]
            events.append(
                {
                    "kind": "hci",
                    "ts": now,
                    "event": "conn_complete",
                    "peer": peer,
                    "status": status,
                    "handle": handle,
                    "link_type": link_type,
                }
            )
            if not accepted or peer != target or link_type != 0x01:
                continue
            if status != 0:
                raise RuntimeError("incoming ACL connection failed with status 0x%02x" % status)
            return {"handle": handle, "events": events}

    raise RuntimeError("timed out waiting for incoming ACL connection from %s" % target)


def open_bnep_server_channel(
    bt,
    handle,
    our_scid=DEFAULT_SCID,
    timeout_s=20.0,
    data_window_s=1.0,
    target=None,
    link_key=None,
):
    next_ident = 1
    remote_scid = None
    config_sent = False
    remote_configured = False
    local_configured = False
    open_deadline = time.monotonic() + timeout_s
    payload_deadline = None
    events = []
    payloads = []
    info_req_sent = False
    target = normalize_bdaddr(target) if target else None

    def send_info_request(info_type):
        nonlocal next_ident
        send_sig(bt, handle, l2cmd(0x0A, next_ident, struct.pack("<H", info_type)))
        events.append(
            {
                "kind": "sig-tx",
                "ts": time.monotonic(),
                "code": 0x0A,
                "ident": next_ident,
                "info_type": info_type,
            }
        )
        next_ident += 1

    while time.monotonic() < open_deadline:
        if not info_req_sent:
            send_info_request(2)
            send_info_request(3)
            info_req_sent = True

        timeout_left = open_deadline - time.monotonic()
        if payload_deadline is not None:
            timeout_left = min(timeout_left, payload_deadline - time.monotonic())
            if timeout_left <= 0:
                break
        pkt = bt_recv(bt, min(0.5, max(0.05, timeout_left)))
        if pkt is None:
            continue

        timestamp = time.monotonic()
        if HCI_Event_Hdr in pkt:
            evt = pkt[HCI_Event_Hdr]
            raw_evt = bytes(evt.payload)
            if evt.code == 0x17 and len(raw_evt) >= 6:
                peer = bdaddr_from_hci(raw_evt[:6])
                events.append({"kind": "hci", "ts": timestamp, "event": "link_key_req", "peer": peer})
                if target is None or peer == target:
                    if link_key is not None and len(link_key) == 16:
                        params = raw_evt[:6] + link_key
                        bt.send(
                            HCI_Hdr(type=1)
                            / HCI_Command_Hdr(ogf=0x01, ocf=0x000B, len=len(params))
                            / Raw(params)
                        )
                        events.append({"kind": "hci", "ts": time.monotonic(), "event": "link_key_reply", "peer": peer})
                    else:
                        bt.send(
                            HCI_Hdr(type=1)
                            / HCI_Command_Hdr(ogf=0x01, ocf=0x000C, len=6)
                            / Raw(raw_evt[:6])
                        )
                        events.append(
                            {
                                "kind": "hci",
                                "ts": time.monotonic(),
                                "event": "link_key_negative_reply",
                                "peer": peer,
                            }
                        )
                continue
            if evt.code == 0x16 and len(raw_evt) >= 6:
                peer = bdaddr_from_hci(raw_evt[:6])
                events.append({"kind": "hci", "ts": timestamp, "event": "pin_req", "peer": peer})
                bt.send(HCI_Hdr(type=1) / HCI_Command_Hdr(ogf=0x01, ocf=0x000E, len=6) / Raw(raw_evt[:6]))
                events.append({"kind": "hci", "ts": time.monotonic(), "event": "pin_negative_reply", "peer": peer})
                continue
            if evt.code == 0x05 and len(raw_evt) >= 4:
                status = raw_evt[0]
                disc_handle = struct.unpack("<H", raw_evt[1:3])[0]
                reason = raw_evt[3]
                events.append(
                    {
                        "kind": "hci",
                        "ts": timestamp,
                        "event": "disconn_complete",
                        "status": status,
                        "handle": disc_handle,
                        "reason": reason,
                    }
                )
                if disc_handle == handle:
                    raise RuntimeError("ACL disconnected during inbound BNEP setup (reason 0x%02x)" % reason)

        for cid, payload in iter_packet_l2cap_records(pkt):
            if cid == CID_SIG:
                parsed = parse_sig_payload(payload)
                if not parsed:
                    continue
                code, ident, data = parsed
                event = {"kind": "sig", "ts": timestamp, "code": code, "ident": ident, "data": data}
                events.append(event)

                if code == 0x0A and len(data) >= 2:
                    info_type = struct.unpack("<H", data[:2])[0]
                    event["info_type"] = info_type
                    if info_type == 2:
                        send_sig(bt, handle, l2cmd(0x0B, ident, struct.pack("<HHI", 2, 0, 0xB8)))
                    elif info_type == 3:
                        send_sig(bt, handle, l2cmd(0x0B, ident, struct.pack("<HH", 3, 0) + b"\x02" + (b"\x00" * 7)))
                    else:
                        send_sig(bt, handle, l2cmd(0x0B, ident, struct.pack("<HH", info_type, 1)))
                    events.append({"kind": "sig-tx", "ts": time.monotonic(), "code": 0x0B, "ident": ident})

                elif code == 0x02 and len(data) >= 4:
                    psm, peer_scid = struct.unpack("<HH", data[:4])
                    event["psm"] = psm
                    event["remote_scid"] = peer_scid
                    if psm != PSM_BNEP:
                        send_sig(bt, handle, l2cmd(0x03, ident, struct.pack("<HHHH", 0, peer_scid, 2, 0)))
                        events.append(
                            {
                                "kind": "sig-tx",
                                "ts": time.monotonic(),
                                "code": 0x03,
                                "ident": ident,
                                "result": 2,
                                "remote_scid": peer_scid,
                            }
                        )
                        continue
                    remote_scid = peer_scid
                    send_sig(bt, handle, l2cmd(0x03, ident, struct.pack("<HHHH", our_scid, remote_scid, 0, 0)))
                    events.append(
                        {
                            "kind": "sig-tx",
                            "ts": time.monotonic(),
                            "code": 0x03,
                            "ident": ident,
                            "result": 0,
                            "local_cid": our_scid,
                            "remote_cid": remote_scid,
                        }
                    )
                    if not config_sent:
                        send_sig(
                            bt,
                            handle,
                            l2cmd(0x04, next_ident, struct.pack("<HH", remote_scid, 0) + bytes([1, 2, 0x00, 0x02])),
                        )
                        events.append(
                            {
                                "kind": "sig-tx",
                                "ts": time.monotonic(),
                                "code": 0x04,
                                "ident": next_ident,
                                "dcid": remote_scid,
                            }
                        )
                        next_ident += 1
                        config_sent = True

                elif code == 0x04 and len(data) >= 4:
                    dcid, flags = struct.unpack("<HH", data[:4])
                    event["dcid"] = dcid
                    event["flags"] = flags
                    if dcid != our_scid:
                        continue
                    send_sig(bt, handle, l2cmd(0x05, ident, struct.pack("<HHH", dcid, flags, 0)))
                    events.append(
                        {
                            "kind": "sig-tx",
                            "ts": time.monotonic(),
                            "code": 0x05,
                            "ident": ident,
                            "dcid": dcid,
                            "flags": flags,
                            "result": 0,
                        }
                    )
                    remote_configured = True
                    if remote_scid is not None and not config_sent:
                        send_sig(
                            bt,
                            handle,
                            l2cmd(0x04, next_ident, struct.pack("<HH", remote_scid, 0) + bytes([1, 2, 0x00, 0x02])),
                        )
                        events.append(
                            {
                                "kind": "sig-tx",
                                "ts": time.monotonic(),
                                "code": 0x04,
                                "ident": next_ident,
                                "dcid": remote_scid,
                            }
                        )
                        next_ident += 1
                        config_sent = True

                elif code == 0x05 and len(data) >= 6:
                    scid, flags, result = struct.unpack("<HHH", data[:6])
                    event["scid"] = scid
                    event["flags"] = flags
                    event["result"] = result
                    if remote_scid is not None and scid == remote_scid and result == 0:
                        local_configured = True

                elif code == 0x06 and len(data) >= 4:
                    dcid, scid = struct.unpack("<HH", data[:4])
                    event["dcid"] = dcid
                    event["scid"] = scid
                    send_sig(bt, handle, l2cmd(0x07, ident, struct.pack("<HH", dcid, scid)))
                    events.append(
                        {"kind": "sig-tx", "ts": time.monotonic(), "code": 0x07, "ident": ident, "dcid": dcid, "scid": scid}
                    )

                elif code == 0x08:
                    send_sig(bt, handle, l2cmd(0x09, ident, data))
                    events.append({"kind": "sig-tx", "ts": time.monotonic(), "code": 0x09, "ident": ident, "data": data})

            elif cid == our_scid:
                payloads.append({"kind": "data", "ts": timestamp, "cid": cid, "payload": payload})

        if remote_scid is not None and remote_configured and local_configured and payload_deadline is None:
            payload_deadline = min(open_deadline, time.monotonic() + data_window_s)

    if remote_scid is None or not remote_configured or not local_configured:
        raise RuntimeError("timed out waiting for inbound BNEP channel to open")

    return {
        "local_cid": our_scid,
        "remote_cid": remote_scid,
        "events": events,
        "payloads": payloads,
    }


def open_bnep_channel(bt, handle, our_scid=DEFAULT_SCID, timeout_s=20.0):
    next_ident = 2
    target_dcid = None
    send_sig(bt, handle, l2cmd(0x02, 1, struct.pack("<HH", 0x000F, our_scid)))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pkt = bt_recv(bt, 0.5)
        if pkt is None:
            continue
        raw_pkt = bytes(pkt)

        for cid, payload in iter_packet_l2cap_records(pkt):
            if cid != CID_SIG:
                continue
            parsed = parse_sig_payload(payload)
            if not parsed:
                continue
            code, ident, data = parsed

            if code == 0x0A and len(data) >= 2:
                info_type = struct.unpack("<H", data[:2])[0]
                if info_type == 2:
                    send_sig(bt, handle, l2cmd(0x0B, ident, struct.pack("<HHI", 2, 0, 0xB8)))
                elif info_type == 3:
                    send_sig(bt, handle, l2cmd(0x0B, ident, struct.pack("<HH", 3, 0) + b"\x02" + (b"\x00" * 7)))
                else:
                    send_sig(bt, handle, l2cmd(0x0B, ident, struct.pack("<HH", info_type, 1)))
                if target_dcid is None:
                    send_sig(bt, handle, l2cmd(0x02, next_ident, struct.pack("<HH", 0x000F, our_scid)))
                    next_ident += 1

            elif code == 0x03 and len(data) >= 8:
                dcid, _scid, result, _status = struct.unpack("<HHHH", data[:8])
                if result == 0:
                    target_dcid = dcid

            elif code == 0x04 and len(data) >= 4:
                remote_dcid = struct.unpack("<H", data[:2])[0]
                send_sig(bt, handle, l2cmd(0x05, ident, struct.pack("<HHH", remote_dcid, 0, 0)))
                if target_dcid is not None:
                    send_sig(
                        bt,
                        handle,
                        l2cmd(0x04, next_ident, struct.pack("<HH", target_dcid, 0) + bytes([1, 2, 0x00, 0x02])),
                    )
                    next_ident += 1

            elif code == 0x05 and len(data) >= 6:
                _remote_scid, _flags, result = struct.unpack("<HHH", data[:6])
                if result == 0 and target_dcid is not None:
                    return target_dcid

    raise RuntimeError("timed out waiting for BNEP channel to open")


def collect_events(bt, our_scid, window_s, timeout_s=0.1):
    events = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        pkt = bt_recv(bt, min(timeout_s, max(0.01, deadline - time.monotonic())))
        if pkt is None:
            continue
        raw_pkt = bytes(pkt)
        timestamp = time.monotonic()

        for cid, payload in iter_packet_l2cap_records(pkt):
            if cid == CID_SIG:
                parsed = parse_sig_payload(payload)
                if parsed:
                    code, ident, data = parsed
                    events.append(
                        {
                            "kind": "sig",
                            "ts": timestamp,
                            "cid": cid,
                            "code": code,
                            "ident": ident,
                            "data": data,
                            "raw": payload,
                        }
                    )
            elif cid == our_scid:
                events.append(
                    {
                        "kind": "data",
                        "ts": timestamp,
                        "cid": cid,
                        "payload": payload,
                    }
                )
    return events


def mac_range(start_suffix):
    start = bytes([0x01, 0x00, 0x5E, 0x00, 0x00, start_suffix & 0xFF])
    end = bytes([0x01, 0x00, 0x5E, 0x00, 0x00, (start_suffix + 1) & 0xFF])
    return start + end


def build_multicast_chunk(index_base, has_next):
    payload = b"".join(mac_range(index_base + (idx * 2)) for idx in range(5))
    header = 0x80 if has_next else 0x00
    return bytes([header, 0x05, 0x00, len(payload)]) + payload


def build_protocol_chunk(index_base, has_next):
    ranges = []
    for idx in range(5):
        start = (index_base + idx * 2) & 0xFFFF
        end = (start + 1) & 0xFFFF
        ranges.append(struct.pack(">HH", start, end))
    payload = b"".join(ranges)
    header = 0x80 if has_next else 0x00
    return bytes([header, 0x03, 0x00, len(payload)]) + payload


def build_extension_tail(target_tail_bytes):
    chunks = []
    remaining = max(target_tail_bytes, 64)
    next_index = 0

    while remaining >= 64:
        chunks.append(build_multicast_chunk(next_index, True))
        remaining -= 64
        next_index += 0x10

    if remaining >= 24:
        chunks.append(build_protocol_chunk(next_index, False))
    elif chunks:
        chunks[-1] = bytes([chunks[-1][0] & 0x7F]) + chunks[-1][1:]

    if not chunks:
        chunks.append(build_multicast_chunk(0, False))
    else:
        chunks[-1] = bytes([chunks[-1][0] & 0x7F]) + chunks[-1][1:]

    return b"".join(chunks)


def make_setup_request(src_uuid, dst_uuid, uuid_size=2, extension_tail=b""):
    if uuid_size != 2:
        raise ValueError("only uuid_size=2 is currently supported")
    frame_type = 0x81 if extension_tail else 0x01
    return bytes([frame_type, 0x01, uuid_size]) + struct.pack(">HH", src_uuid, dst_uuid) + extension_tail


def make_setup_response(result_code):
    return bytes([0x01, 0x02]) + struct.pack(">H", result_code)


def parse_setup_request(payload):
    if len(payload) < 3:
        return None
    if (payload[0] & 0x7F) != 0x01 or payload[1] != 0x01:
        return None
    uuid_size = payload[2]
    if uuid_size != 2 or len(payload) < 7:
        return {"frame_type": payload[0], "uuid_size": uuid_size, "raw": payload}
    src_uuid, dst_uuid = struct.unpack(">HH", payload[3:7])
    return {
        "frame_type": payload[0],
        "uuid_size": uuid_size,
        "src_uuid": src_uuid,
        "dst_uuid": dst_uuid,
        "tail": payload[7:],
        "raw": payload,
    }


def parse_setup_response(payload):
    if len(payload) < 4:
        return None
    if (payload[0] & 0x7F) != 0x01 or payload[1] != 0x02:
        return None
    code = struct.unpack(">H", payload[2:4])[0]
    return code, SETUP_RESPONSE_CODES.get(code, "unknown(%d)" % code)
