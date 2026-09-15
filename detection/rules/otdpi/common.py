"""Shared helpers for the live telemetry producers.

Sinks mirror the two proven patterns in this lab:

* ``push_to_loki`` sends a normalized ``logfmt`` line straight to Loki, which is
  how the generated ruler rules receive their events (the gateway is multi-homed
  and does not resolve Docker service names, so a static address is used).
* ``write_alert`` appends an NDJSON ``alert_type`` record to ``alerts.json`` for
  evidence, unit tests and the compliance gate.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from datetime import datetime, timezone

LOKI_URL = os.getenv("OT_LOKI_URL", "http://172.24.0.20:3100/loki/api/v1/push")
LOG_FILE = os.getenv(
    "OT_ALERT_LOG",
    os.path.join(
        # otdpi/ lives one level below the rule directory, so go up three
        # levels from this file to reach detection/ and then into logs/.
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "logs",
        "alerts.json",
    ),
)


def logfmt(fields: dict) -> str:
    """Render ``key=value`` pairs as a logfmt line, quoting where required."""
    parts = []
    for key, value in fields.items():
        if value is None:
            continue
        text = str(value)
        if text == "" or any(ch in text for ch in ' "=\n'):
            text = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
        parts.append(f"{key}={text}")
    return " ".join(parts)


def push_to_loki(service: str, fields: dict, job: str = "ot_ndr") -> bool:
    """Push one normalized event to Loki and return whether the push succeeded."""
    timestamp = str(int(time.time() * 1_000_000_000))
    payload = {
        "streams": [
            {"stream": {"job": job, "service": service}, "values": [[timestamp, logfmt(fields)]]}
        ]
    }
    request = urllib.request.Request(
        LOKI_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        # Fixed internal Loki URL, not user input.
        urllib.request.urlopen(request, timeout=3).read()  # nosec B310
        return True
    except OSError as error:
        print(f"[{service}] loki push failed: {error}", flush=True)
        return False


def write_alert(alert: dict) -> None:
    """Append a lab alert (with ``alert_type``) to the evidence log."""
    record = {"timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}
    record.update(alert)
    with open(LOG_FILE, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    print(f"[ALERT] {record.get('alert_type')} | {record}", flush=True)


def capture_interfaces() -> list:
    """Return every non-loopback interface for passive capture.

    Scapy's ``sniff(iface=None)`` only binds the default-route interface, so a
    multi-homed gateway would miss traffic arriving on other zones' interfaces.
    """
    from scapy.all import get_if_list

    return [name for name in get_if_list() if name != "lo"]

