#!/usr/bin/env python3
"""Accept one inbound raw-HCI BNEP connection and optionally answer setup."""

import argparse
import time

from bnep_harness import (
    DEFAULT_SCID,
    load_bluez_link_key,
    make_setup_response,
    normalize_bdaddr,
    open_bnep_server_channel,
    open_user_socket,
    parse_setup_request,
    send_data,
    wait_for_incoming_acl_connection,
    close_acl,
)


DEFAULT_TARGET = "BC:76:5E:57:44:EC"
RESPONSE_MODES = {
    "success": 0,
    "conn-not-allowed": 1,
    "invalid-dst": 2,
    "invalid-src": 3,
    "none": None,
}


def format_offset_ms(ts, start_ts):
    return int((ts - start_ts) * 1000)


def format_sig_event(event):
    code = event.get("code")
    if code == 0x0A:
        return "INFO_REQ type=0x%04x" % event.get("info_type", -1)
    if code == 0x02:
        return "CONN_REQ psm=0x%04x remote_scid=0x%04x" % (event.get("psm", 0), event.get("remote_scid", 0))
    if code == 0x03:
        return "CONN_RSP result=%s local_cid=0x%04x remote_cid=0x%04x" % (
            event.get("result", "?"),
            event.get("local_cid", 0),
            event.get("remote_cid", 0),
        )
    if code == 0x04:
        return "CONF_REQ dcid=0x%04x flags=0x%04x" % (event.get("dcid", 0), event.get("flags", 0))
    if code == 0x05:
        return "CONF_RSP scid=0x%04x flags=0x%04x result=%s" % (
            event.get("scid", event.get("dcid", 0)),
            event.get("flags", 0),
            event.get("result", "?"),
        )
    if code == 0x07:
        return "DISCONN_RSP dcid=0x%04x scid=0x%04x" % (event.get("dcid", 0), event.get("scid", 0))
    if code == 0x09:
        return "ECHO_RSP"
    if code == 0x0B:
        return "INFO_RSP"
    return "SIG code=0x%02x" % (code if code is not None else 0)


def print_timeline(start_ts, acl_events, l2cap_events):
    print("[*] Handshake timeline:")
    for event in sorted(acl_events + l2cap_events, key=lambda item: item["ts"]):
        offset_ms = format_offset_ms(event["ts"], start_ts)
        if event["kind"] == "hci":
            name = event["event"]
            if name == "conn_req":
                detail = "ACL conn request from %s link_type=0x%02x" % (event["peer"], event["link_type"])
            elif name == "accept_sent":
                detail = "Accept Connection Request sent to %s role=0x%02x" % (event["peer"], event["role"])
            elif name == "conn_complete":
                detail = "ACL connected peer=%s handle=0x%04x status=0x%02x" % (
                    event["peer"],
                    event["handle"],
                    event["status"],
                )
            elif name == "disconn_complete":
                detail = "ACL disconnected handle=0x%04x reason=0x%02x" % (event["handle"], event["reason"])
            elif name == "link_key_req":
                detail = "Link key request from %s" % (event["peer"],)
            elif name == "link_key_reply":
                detail = "Link key reply sent to %s" % (event["peer"],)
            elif name == "link_key_negative_reply":
                detail = "Link key negative reply sent to %s" % (event["peer"],)
            elif name == "pin_req":
                detail = "PIN request from %s" % (event["peer"],)
            elif name == "pin_negative_reply":
                detail = "PIN negative reply sent to %s" % (event["peer"],)
            else:
                detail = name
        elif event["kind"] in {"sig", "sig-tx"}:
            direction = "<-" if event["kind"] == "sig" else "->"
            detail = "%s %s" % (direction, format_sig_event(event))
        else:
            detail = repr(event)
        print("    +%4d ms  %s" % (offset_ms, detail))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET, help="Target tablet MAC address")
    parser.add_argument("--acl-timeout", type=float, default=30.0, help="Seconds to wait for inbound ACL connect")
    parser.add_argument("--l2cap-timeout", type=float, default=10.0, help="Seconds to finish inbound BNEP signaling")
    parser.add_argument(
        "--payload-window",
        type=float,
        default=1.0,
        help="Seconds to keep collecting inbound BNEP payloads after channel open",
    )
    parser.add_argument(
        "--response",
        choices=sorted(RESPONSE_MODES),
        default="none",
        help="Optional BNEP Setup Conn Response mode",
    )
    args = parser.parse_args()

    target = normalize_bdaddr(args.target)
    bt = open_user_socket()
    handle = None
    started = time.monotonic()

    print("[*] Target: %s" % target)
    print("[*] Local server CID: 0x%04x" % DEFAULT_SCID)
    print("[*] Waiting for one inbound PANU connection over raw HCI")
    print("[*] Response mode: %s" % args.response)
    link_key = load_bluez_link_key(target)
    print("[*] BlueZ link key: %s" % ("loaded" if link_key is not None else "missing"))

    try:
        acl_info = wait_for_incoming_acl_connection(bt, target, timeout_s=args.acl_timeout)
        handle = acl_info["handle"]
        print("[+] Accepted inbound ACL handle=0x%04x" % handle)

        channel = open_bnep_server_channel(
            bt,
            handle,
            our_scid=DEFAULT_SCID,
            timeout_s=args.l2cap_timeout,
            data_window_s=args.payload_window,
            target=target,
            link_key=link_key,
        )
        print(
            "[+] BNEP channel open local_cid=0x%04x remote_cid=0x%04x"
            % (channel["local_cid"], channel["remote_cid"])
        )
        print_timeline(started, acl_info["events"], channel["events"])

        if channel["payloads"]:
            print("[*] Inbound BNEP payloads:")
        else:
            print("[*] Inbound BNEP payloads: none observed in %.2fs window" % args.payload_window)

        setup_request = None
        for index, payload_event in enumerate(channel["payloads"], 1):
            offset_ms = format_offset_ms(payload_event["ts"], started)
            payload = payload_event["payload"]
            print("    %d. +%d ms cid=0x%04x len=%d raw=%s" % (index, offset_ms, payload_event["cid"], len(payload), payload.hex()))
            parsed = parse_setup_request(payload)
            if parsed:
                if "src_uuid" in parsed and "dst_uuid" in parsed:
                    print(
                        "       setup-req uuid_size=%d src=0x%04x dst=0x%04x tail=%s"
                        % (parsed["uuid_size"], parsed["src_uuid"], parsed["dst_uuid"], parsed["tail"].hex())
                    )
                else:
                    print(
                        "       setup-req uuid_size=%d unsupported/raw=%s"
                        % (parsed["uuid_size"], parsed["raw"].hex())
                    )
                if setup_request is None:
                    setup_request = parsed

        response_code = RESPONSE_MODES[args.response]
        if response_code is not None and setup_request is not None:
            frame = make_setup_response(response_code)
            send_data(bt, handle, channel["remote_cid"], frame)
            print("[->] Sent BNEP Setup Conn Response code=%d raw=%s" % (response_code, frame.hex()))
        elif response_code is not None:
            print("[*] Response requested, but no inbound BNEP setup request was observed")

    finally:
        if handle is not None:
            close_acl(bt, handle)
        else:
            try:
                bt.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
