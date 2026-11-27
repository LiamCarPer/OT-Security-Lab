#!/usr/bin/env python3
"""Ship PLC integrity events to Loki as ``job=ot_plc``.

The integrity check appends ``PLC_LOGIC_TAMPERED`` to the alert log. This
producer tails that log and pushes the normalized diagnostics event so the
repository's program-integrity rule can fire live.
"""
from __future__ import annotations

import json
import os
import time

from otdpi import common

ALERT_LOG = os.getenv("OT_ALERT_LOG", common.LOG_FILE)


def process_line(line: str) -> None:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return
    if record.get("alert_type") != "PLC_LOGIC_TAMPERED":
        return
    common.push_to_loki(
        "diagnostics",
        {
            "event_type": "logic_tampered",
            "plc": record.get("plc"),
            "status": record.get("status"),
            "severity": record.get("severity") or "critical",
            "description": record.get("description"),
        },
        job="ot_plc",
    )


def main() -> None:
    print(f"[PLC] tailing {ALERT_LOG}", flush=True)
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
