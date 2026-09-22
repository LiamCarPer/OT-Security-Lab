#!/usr/bin/env python3
"""C2 beacon emulation - periodic callbacks from a compromised OT host.

Runs inside a compromised host (default: the insider/EWS in the Operations
zone) and opens a TCP connection to a C2 address in the enterprise zone at a
near-constant interval. There is no OT -> Enterprise conduit, so the zone
firewall denies every callback; the gateway observes the repeated denied flows
as a regular-interval (beaconing) pattern, which
``detection/rules/firewall_events.py`` flags as ``C2_BEACON``.

This models C2 *detection* (the egress is blocked and the pattern is caught),
not a successful command-and-control channel.
"""
from __future__ import annotations

import argparse
import random
import socket
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="172.24.0.10", help="C2 address")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--jitter", type=float, default=0.2)
    parser.add_argument("--count", type=int, default=6)
    args = parser.parse_args()

    print(f"[C2] beaconing to {args.host}:{args.port} every ~{args.interval}s x{args.count}")
    for beacon in range(1, args.count + 1):
        try:
            with socket.create_connection((args.host, args.port), timeout=1.5):
                print(f"[C2] beacon {beacon}: connected")
        except OSError as error:
            print(f"[C2] beacon {beacon}: no response ({error})")
        if beacon < args.count:
            time.sleep(max(0.1, args.interval + random.uniform(-args.jitter, args.jitter)))
    print("[C2] beaconing complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
