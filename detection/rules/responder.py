#!/usr/bin/env python3
"""Gateway-side responder (SOAR containment).

Watches the centralized alert log and, when a source exceeds the unauthorized-
write threshold, applies a gateway-local ``iptables`` DROP for that source.
Runs inside the gateway (which already holds NET_ADMIN), so containment needs no
Docker socket and is fully reversed by a gateway restart.

Safety: **dry-run by default**. Set ``OT_RESPONDER_ENFORCE=1`` to arm it. The
block is applied to the FORWARD chain, is logged, and is reversible with
``--unblock <ip>``.
"""
import argparse
import ipaddress
import json
import os
import subprocess  # nosec B404 - fixed-argv iptables calls, no shell
import sys
import time
from collections import defaultdict
from datetime import datetime

ALERT_LOG = os.getenv("OT_ALERT_LOG", "/detection/logs/alerts.json")
WATCH_TYPES = {
    "UNAUTHORIZED_MODBUS_WRITE",
    "DNP3_WRITE_UNAUTHORIZED",
    "DNP3_UNAUTHORIZED_CONTROL",
}
WINDOW = int(os.getenv("OT_RESPONDER_WINDOW", "300"))
THRESHOLD = int(os.getenv("OT_RESPONDER_THRESHOLD", "3"))
ENFORCE = os.getenv("OT_RESPONDER_ENFORCE", "0") == "1"


def record(state: dict, source_ip: str, now: float, window: int, threshold: int) -> bool:
    """Record an offence and return True when the source crosses the threshold."""
    timestamps = [t for t in state.get(source_ip, []) if t > now - window]
    timestamps.append(now)
    state[source_ip] = timestamps
    return len(timestamps) >= threshold


def apply_drop(source_ip: str, enforce: bool) -> str:
    command = ["iptables", "-I", "FORWARD", "-s", source_ip, "-j", "DROP"]
    if not enforce:
        return "dry-run"
    result = subprocess.run(command, capture_output=True, text=True)  # nosec B603 - fixed argv
    return "blocked" if result.returncode == 0 else f"error: {result.stderr.strip()}"


def revert_drop(source_ip: str) -> bool:
    command = ["iptables", "-D", "FORWARD", "-s", source_ip, "-j", "DROP"]
    return subprocess.run(command, capture_output=True, text=True).returncode == 0  # nosec B603


def log(message: str) -> None:
    print(f"[RESPONDER] {datetime.now().isoformat()} {message}", flush=True)


def process_line(line: str, state: dict, blocked: set) -> None:
    try:
        alert = json.loads(line)
    except json.JSONDecodeError:
        return
    if alert.get("alert_type") not in WATCH_TYPES:
        return
    source_ip = alert.get("source_ip")
    if not source_ip or source_ip in blocked:
        return
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return
    if record(state, source_ip, time.time(), WINDOW, THRESHOLD):
        status = apply_drop(source_ip, ENFORCE)
        blocked.add(source_ip)
        log(f"threshold reached for {source_ip}: {status} "
            f"(enforce={'on' if ENFORCE else 'off'})")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Gateway-side SOAR responder")
    parser.add_argument("--unblock", metavar="IP", help="remove a DROP and exit")
    args = parser.parse_args(argv)

    if args.unblock:
        ok = revert_drop(args.unblock)
        log(f"unblock {args.unblock}: {'ok' if ok else 'failed'}")
        return 0 if ok else 1

    log(f"watching {ALERT_LOG} ({THRESHOLD} offences / {WINDOW}s; "
        f"enforce={'on' if ENFORCE else 'off (dry-run)'})")
    state: dict = defaultdict(list)
    blocked: set = set()
    while True:
        if not os.path.exists(ALERT_LOG):
            time.sleep(2)
            continue
        with open(ALERT_LOG, encoding="utf-8") as handle:
            handle.seek(0, os.SEEK_END)
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(2)
                    continue
                process_line(line, state, blocked)


if __name__ == "__main__":
    sys.exit(main())
