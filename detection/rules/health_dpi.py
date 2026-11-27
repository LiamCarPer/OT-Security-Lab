#!/usr/bin/env python3
"""Ship detection-health events to Loki as ``job=ot_detection_health``.

The watchdog writes ``DETECTION_SERVICE_DOWN`` to the alert log. The generated
sensor-health rule needs a normalized stream, so this producer tails the log and
pushes the health records with the health job/service labels.
"""
from __future__ import annotations

import json
import os
import time

from otdpi import common

ALERT_LOG = os.getenv("OT_ALERT_LOG", common.LOG_FILE)
HEALTH = {
    "DETECTION_SERVICE_DOWN": "detection_service_down",
    "DETECTION_SERVICE_UP": "detection_service_up",
}


def process_line(line: str) -> None:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return
    alert_type = str(record.get("alert_type") or record.get("event_type") or "").upper()
    event_type = HEALTH.get(alert_type)
    if event_type is None:
        return
    common.push_to_loki(
        "watchdog",
        {
            "event_type": event_type,
            "producer": record.get("service") or record.get("producer"),
            "severity": record.get("severity") or "critical",
            "description": record.get("description"),
        },
        job="ot_detection_health",
    )


def main() -> None:
    print(f"[HEALTH] tailing {ALERT_LOG}", flush=True)
    handle = None
    while True:
        if not os.path.exists(ALERT_LOG):
            time.sleep(2)
            continue
        if handle is None:
            handle = open(ALERT_LOG, encoding="utf-8")
            handle.seek(0, os.SEEK_END)
        line = handle.readline()
        if not line:
            time.sleep(1)
            continue
        process_line(line)


if __name__ == "__main__":
    main()
