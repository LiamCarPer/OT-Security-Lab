#!/usr/bin/env python3
"""SOAR-lite playbook: automatically block repeat Modbus write offenders.

Detection is only the first half of the job; this playbook closes the loop by
enforcing a network-level containment action (an iptables DROP on the zone
gateway) when a source exceeds the unauthorized-write threshold within the
lookback window. Offenders are handled in a safety-first manner: the block is
gateway-local and reversible (unblock command provided).
"""
import argparse
import json
import shlex
import subprocess  # nosec B404 - orchestration tool; input validated via shlex, no shell=True
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_LOG = REPO_ROOT / "detection" / "logs" / "alerts.json"
WRITE_ALERT = "UNAUTHORIZED_MODBUS_WRITE"
WINDOW_SECONDS = 300
TRIGGER_COUNT = 3

def load_alerts(path=None):
    log_path = Path(path) if path else ALERT_LOG
    if not log_path.exists():
        return []
    alerts = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts

def _to_epoch(iso):
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None

def find_offenders(alerts, window=WINDOW_SECONDS, trigger=TRIGGER_COUNT):
    """Return {ip: count} for sources exceeding the write threshold in the window."""
    offenders = defaultdict(int)
    for alert in alerts:
        if alert.get("alert_type") != WRITE_ALERT:
            continue
        ts = _to_epoch(alert.get("timestamp"))
        if ts is None:
            continue
        offenders[alert["source_ip"]] += 1
    return {ip: count for ip, count in offenders.items() if count >= trigger}

def block_ip(ip, gateway="ot_gateway", dry_run=False):
    command = f"docker exec {gateway} iptables -A FORWARD -s {ip} -j DROP"
    if dry_run:
        print(f"[DRY-RUN] Would execute: {command}")
        return True
    # Command is built from our own alert log and tokenized via shlex.split
    # (no shell interpolation); production would use API-based containment.
    result = subprocess.run(  # nosec B603 - input tokenized, no shell=True
        shlex.split(command), capture_output=True, text=True, check=False
    )
    if result.returncode == 0:
        print(f"[BLOCKED] {ip} on gateway {gateway}")
    else:
        print(f"[ERROR] Could not block {ip}: {result.stderr.strip()}")
    return result.returncode == 0

def unblock_ip(ip, gateway="ot_gateway", dry_run=False):
    command = f"docker exec {gateway} iptables -D FORWARD -s {ip} -j DROP"
    if dry_run:
        print(f"[DRY-RUN] Would execute: {command}")
        return True
    result = subprocess.run(  # nosec B603 - input tokenized, no shell=True
        shlex.split(command), capture_output=True, text=True, check=False
    )
    if result.returncode == 0:
        print(f"[UNBLOCKED] {ip} on gateway {gateway}")
    else:
        print(f"[ERROR] Could not unblock {ip}: {result.stderr.strip()}")
    return result.returncode == 0

def main():
    parser = argparse.ArgumentParser(description="Auto-block repeat Modbus write offenders")
    parser.add_argument("--input", default=str(ALERT_LOG))
    parser.add_argument("--dry-run", action="store_true", help="Only print actions")
    parser.add_argument("--unblock", action="store_true", help="Remove DROP rules instead of adding them")
    args = parser.parse_args()

    alerts = load_alerts(args.input)
    offenders = find_offenders(alerts)

    if not offenders:
        print(f"No offenders above threshold ({TRIGGER_COUNT} writes / {WINDOW_SECONDS}s window).")
        return 0

    for ip, _count in sorted(offenders.items(), key=lambda item: item[1], reverse=True):
        if args.unblock:
            unblock_ip(ip, dry_run=args.dry_run)
        else:
            block_ip(ip, dry_run=args.dry_run)
    return 0

if __name__ == "__main__":
    sys.exit(main())
