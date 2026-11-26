#!/usr/bin/env python3
"""Capture 24 hours of benign lab traffic at the gateway.

The gateway is the only multi-homed container, so a capture on its zone
interfaces sees every inter-zone flow. This is deliberately separate from the
IDS producers: it writes a PCAP for offline false-positive analysis and does not
ship anything to Loki.

Run:
    docker exec -d ot_gateway python3 -u /scripts/benign_capture.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, "/detection/rules")

from otdpi import common  # noqa: E402
from scapy.all import AsyncSniffer, PcapWriter  # noqa: E402

OUT = os.getenv("OT_CAPTURE_PATH", "/detection/logs/benign-24h.pcap")
SECONDS = int(os.getenv("OT_CAPTURE_SECONDS", "86400"))


def main() -> None:
    interfaces = common.capture_interfaces()
    writer = PcapWriter(OUT, append=False, sync=True)
    print(
        f"[CAPTURE] {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
        f"{SECONDS}s on {interfaces} -> {OUT}",
        flush=True,
    )
    # ``sniff(timeout=...)`` with several interfaces did not stop: a 24-hour run
    # was still writing at 25 hours. Drive the sniffer explicitly and enforce a
    # wall-clock deadline so a capture cannot outlive its window.
    sniffer = AsyncSniffer(
        iface=interfaces, filter="ip", prn=writer.write, store=0
    )
    sniffer.start()
    try:
        deadline = time.time() + SECONDS
        while sniffer.running and time.time() < deadline:
            time.sleep(1)
    finally:
        if sniffer.running:
            sniffer.stop()
        writer.close()
        print(
            f"[CAPTURE] stopped {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
            flush=True,
        )


if __name__ == "__main__":
    main()
