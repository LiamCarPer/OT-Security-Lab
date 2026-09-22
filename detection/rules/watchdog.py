#!/usr/bin/env python3
"""Detection-availability watchdog (Inhibit Response Function).

Continuously verifies that every other detection producer is still running. A
producer that dies - from a crash, an OOM kill, or an attacker with host access
stopping the sensor - leaves the plant blind. This raises
``DETECTION_SERVICE_DOWN`` so the gap is detected rather than silent, and
``start_ids.sh`` alone only checks liveness once at boot.

MITRE ATT&CK for ICS: T0881 (Service Stop) under Inhibit Response Function.
"""
from __future__ import annotations

import glob
import os
import subprocess  # nosec B404 - fixed-argv pgrep calls, no shell
import time

from otdpi import common

RULE_DIR = os.path.dirname(os.path.abspath(__file__))
SELF = os.path.basename(os.path.abspath(__file__))
INTERVAL = int(os.getenv("OT_WATCHDOG_INTERVAL", "10"))
REPEAT_SECONDS = int(os.getenv("OT_WATCHDOG_REPEAT", "300"))
# Give every producer time to start before the first check (avoid boot-race
# false positives while start_ids.sh is still launching the others).
GRACE_SECONDS = int(os.getenv("OT_WATCHDOG_GRACE", "30"))
_last_alerted: dict = {}


def producers() -> list:
    """Every producer script except this watchdog."""
    return sorted(
        os.path.basename(path)
        for path in glob.glob(os.path.join(RULE_DIR, "*.py"))
        if os.path.basename(path) != SELF
    )


def running(script: str) -> bool:
    result = subprocess.run(  # nosec B603 B607 - fixed argv, pgrep resolved from PATH
        ["pgrep", "-f", script], capture_output=True, text=True
    )
    return result.returncode == 0


def check(scripts: list, now: float) -> None:
    for script in scripts:
        if running(script):
            _last_alerted.pop(script, None)
            continue
        if now - _last_alerted.get(script, 0) < REPEAT_SECONDS:
            continue
        _last_alerted[script] = now
        fields = {"alert_type": "DETECTION_SERVICE_DOWN", "service": script}
        common.push_to_loki("watchdog", fields)
        common.write_alert(
            {
                **fields,
                "mitre_id": "T0881",
                "description": (
                    f"Detection producer {script} is not running: the sensor has "
                    "been stopped or crashed (Inhibit Response Function)."
                ),
            }
        )


def main() -> None:
    scripts = producers()
    print(f"[watchdog] monitoring {len(scripts)} detection producers every {INTERVAL}s", flush=True)
    time.sleep(GRACE_SECONDS)
    while True:
        check(scripts, time.time())
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
