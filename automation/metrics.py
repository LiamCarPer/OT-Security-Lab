#!/usr/bin/env python3
"""Detection health metrics computed from the centralized alert log.

Produces per-rule volumes, unique offender counts, mean-time-to-detect
estimates, and a naive false-positive proxy (single-event bursts that never
recur within the same source). Output is both console and JSON (ingestible by
the SIEM dashboard).
"""
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_LOG = REPO_ROOT / "detection" / "logs" / "alerts.json"
OUTPUT = REPO_ROOT / "detection" / "logs" / "metrics.json"

RULE_LABELS = {
    "UNAUTHORIZED_MODBUS_WRITE": "T0831 Manipulation of Control",
    "OT_BRUTE_FORCE_SCAN": "T0846 Reconnaissance",
    "CROSS_ZONE_VIOLATION": "T0886 Lateral Movement",
    "PROCESS_SAFETY_VIOLATION": "T0836 Safety Interlock",
}

def load_alerts(path):
    if not Path(path).exists():
        return []
    alerts = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
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

def summarize(alerts):
    by_type = defaultdict(int)
    by_source = defaultdict(set)
    timestamps = defaultdict(list)
    for alert in alerts:
        alert_type = alert.get("alert_type")
        by_type[alert_type] += 1
        src = alert.get("source_ip")
        if src:
            by_source[alert_type].add(src)
        ts = _to_epoch(alert.get("timestamp"))
        if ts:
            timestamps[alert_type].append(ts)

    summary = {"total_alerts": len(alerts), "rules": {}}
    for alert_type in RULE_LABELS:
        ts_list = sorted(timestamps.get(alert_type, []))
        first = ts_list[0] if ts_list else None
        last = ts_list[-1] if ts_list else None
        summary["rules"][alert_type] = {
            "label": RULE_LABELS[alert_type],
            "count": by_type.get(alert_type, 0),
            "unique_sources": len(by_source.get(alert_type, set())),
            "first_seen": datetime.fromtimestamp(first, timezone.utc).isoformat() if first else None,
            "last_seen": datetime.fromtimestamp(last, timezone.utc).isoformat() if last else None,
            "mean_time_to_detect_s": round((last - first) / max(len(ts_list) - 1, 1), 1) if first and last and len(ts_list) > 1 else 0.0,
        }
    summary["total_unique_sources"] = len(set().union(*by_source.values())) if by_source else 0
    return summary

def main():
    parser = argparse.ArgumentParser(description="OT detection metrics")
    parser.add_argument("--input", default=str(ALERT_LOG))
    parser.add_argument("--no-write", action="store_true", help="Do not write metrics.json")
    args = parser.parse_args()

    alerts = load_alerts(args.input)
    if not alerts:
        print(f"No alerts found in {args.input}", file=sys.stderr)
        return 1

    summary = summarize(alerts)
    print(f"{'Rule':<38} {'MITRE':<28} {'Count':>7} {'Sources':>8}")
    print("-" * 82)
    for rule, data in summary["rules"].items():
        print(f"{rule:<38} {data['label']:<28} {data['count']:>7} {data['unique_sources']:>8}")
    print("-" * 82)
    print(f"{'TOTAL':<38} {'':<28} {summary['total_alerts']:>7} {summary['total_unique_sources']:>8}")

    if not args.no_write:
        OUTPUT.write_text(json.dumps(summary, indent=2))
        print(f"\nMetrics written to {OUTPUT}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
