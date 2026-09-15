#!/usr/bin/env python3
"""Detect failed Scada-LTS logins from the DMZ reverse-proxy access log.

The HMI itself does not log authentication failures, so login-failure detection
(HMI-3.3) is done at the DMZ reverse proxy: every authentication through the
corporate access path appears in nginx's structured access log, and a failed
login redirects back to ``login.htm``. Sources exceeding the threshold produce an
``HMI_LOGIN_FAILURE`` alert in the centralized alert log (ingested by the SIEM).
"""
import json
import os
import time
from collections import defaultdict
from datetime import datetime

ACCESS_LOG = os.getenv("OT_PROXY_ACCESS_LOG", "/var/log/otproxy/access.log")
ALERT_LOG = os.getenv("OT_ALERT_LOG", "/logs/alerts.json")
WINDOW = int(os.getenv("OT_LOGIN_WINDOW", "300"))
THRESHOLD = int(os.getenv("OT_LOGIN_THRESHOLD", "3"))
MITRE = os.getenv("OT_LOGIN_MITRE", "T0859")


def is_login_failure(entry: dict) -> bool:
    """A failed Scada-LTS login redirects back to the login page."""
    request = entry.get("request", "")
    location = entry.get("location", "")
    return request.startswith("POST ") and "login.htm" in request and "login.htm" in location


def record(state: dict, source_ip: str, now: float, window: int, threshold: int) -> bool:
    timestamps = [t for t in state.get(source_ip, []) if t > now - window]
    timestamps.append(now)
    state[source_ip] = timestamps
    return len(timestamps) >= threshold


def write_alert(source_ip: str, count: int) -> None:
    alert = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": "HMI_LOGIN_FAILURE",
        "source_ip": source_ip,
        "attempt_count": count,
        "mitre_id": MITRE,
        "description": "Repeated failed Scada-LTS logins from a single source.",
    }
    with open(ALERT_LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert) + "\n")
    print(f"[LOGIN-MONITOR] HMI_LOGIN_FAILURE {source_ip} ({count} attempts)", flush=True)


def process_line(line: str, state: dict, alerted: set) -> None:
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return
    if not is_login_failure(entry):
        return
    source_ip = entry.get("remote_addr")
    if not source_ip:
        return
    if record(state, source_ip, time.time(), WINDOW, THRESHOLD):
        write_alert(source_ip, len(state[source_ip]))
        alerted.add(source_ip)


def tail(state: dict, alerted: set) -> None:
    print(f"[LOGIN-MONITOR] watching {ACCESS_LOG} ({THRESHOLD}/{WINDOW}s)", flush=True)
    handle = None
    while True:
        if not os.path.exists(ACCESS_LOG):
            time.sleep(2)
            continue
        if handle is None:
            handle = open(ACCESS_LOG, encoding="utf-8")
            handle.seek(0, os.SEEK_END)
        line = handle.readline()
        if not line:
            time.sleep(1)
            continue
        process_line(line, state, alerted)


def main() -> None:
    tail(defaultdict(list), set())


if __name__ == "__main__":
    main()
