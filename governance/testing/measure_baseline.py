#!/usr/bin/env python3
"""Measure the lab's benign steady state (false-positive check).

The lab continuously performs legitimate work even with no attack running: the
L2 collector polls the controllers over C1, Scada-LTS polls as a real Modbus
master, and the watchdog checks producer liveness. This samples the alert log
over a quiet window and reports the alert rate.

In steady state an OT alert is a false positive, so the exit status is non-zero
if the window produced more than ``OT_BASELINE_MAX_ALERTS`` (default 0) alerts.

Usage:
    python3 governance/testing/measure_baseline.py [--seconds 45]
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_LOG = Path(os.getenv("OT_ALERT_LOG", REPO_ROOT / "detection" / "logs" / "alerts.json"))


def counts_since(offset: int) -> dict:
    counts: dict = {}
    if not ALERT_LOG.exists():
        return counts
    with ALERT_LOG.open(encoding="utf-8") as handle:
        handle.seek(offset)
        for line in handle:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = alert.get("alert_type")
            counts[name] = counts.get(name, 0) + 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=int(os.getenv("OT_BASELINE_SECONDS", "45")))
    args = parser.parse_args()

    offset = ALERT_LOG.stat().st_size if ALERT_LOG.exists() else 0
    print(f"[baseline] sampling {args.seconds}s of benign steady state...", flush=True)
    time.sleep(args.seconds)

    alerts = counts_since(offset)
    total = sum(alerts.values())
    per_minute = total * 60 / args.seconds if args.seconds else 0.0
    limit = int(os.getenv("OT_BASELINE_MAX_ALERTS", "0"))

    print(f"[baseline] window={args.seconds}s alerts={total} alerts_per_min={per_minute:.1f}")
    if alerts:
        print(f"[baseline] alerts observed: {alerts}")
    print(
        json.dumps(
            {
                "window_seconds": args.seconds,
                "alerts": total,
                "alerts_per_minute": round(per_minute, 2),
                "by_type": alerts,
            }
        )
    )

    if total > limit:
        print(f"[FAIL] {total} alerts during the benign window (limit {limit})")
        return 1
    print("[PASS] benign steady state produced no OT alerts (no false positives observed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
