#!/usr/bin/env python3
"""Capture machine-generated runtime evidence from the running lab.

Unlike screenshots, this evidence is reproducible: it queries Loki (alert
streams and ruler rule states), Grafana (datasources) and InfluxDB (last process
values) and writes a single JSON artifact under `evidence/`.

Usage (lab must be running):
    python3 governance/testing/capture_evidence.py
"""
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "evidence" / "runtime_evidence.json"
LOKI = "http://localhost:3100"
GRAFANA = "http://localhost:3000"
INFLUX_CONTAINER = "ot_historian"
WINDOW_SECONDS = 3600


def http_get_json(url: str):
    with urllib.request.urlopen(url, timeout=10) as response:  # nosec B310
        return json.loads(response.read().decode("utf-8"))


def alert_summary() -> dict:
    end = int(time.time())
    params = urllib.parse.urlencode(
        {
            "query": '{job="ot_alerts"}',
            "start": f"{end - WINDOW_SECONDS}000000000",
            "end": f"{end}000000000",
            "limit": "5000",
        }
    )
    payload = http_get_json(f"{LOKI}/loki/api/v1/query_range?{params}")
    types, sources = Counter(), set()
    for stream in payload["data"]["result"]:
        for _ts, line in stream["values"]:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert_type = alert.get("alert_type")
            if not alert_type:
                continue
            types[alert_type] += 1
            if alert.get("source_ip"):
                sources.add(alert["source_ip"])
    return {"alert_counts": dict(types.most_common()), "distinct_sources": sorted(sources)}


def ruler_states() -> dict:
    payload = http_get_json(f"{LOKI}/prometheus/api/v1/rules")
    states = {}
    for group in payload.get("data", {}).get("groups", []):
        for rule in group.get("rules", []):
            states[rule.get("name")] = {"state": rule.get("state"), "health": rule.get("health")}
    return states


def grafana_datasources() -> list:
    return [ds["name"] for ds in http_get_json(f"{GRAFANA}/api/datasources")]


def historian_last_values() -> dict:
    out = {}
    for asset, field in (
        ("plc_intake", "level"),
        ("plc_treatment", "chlorine"),
        ("plc_distribution", "pressure"),
    ):
        query = f'SELECT last("{field}") FROM "process_state" WHERE "asset"=\'{asset}\''
        result = subprocess.run(
            ["docker", "exec", INFLUX_CONTAINER, "influx", "-database", "ot_data",
             "-execute", query, "-format", "json"],
            capture_output=True,
            text=True,
        )
        try:
            values = json.loads(result.stdout)["results"][0]["series"][0]["values"][0]
            out[asset] = {field: values[1]}
        except (KeyError, IndexError, json.JSONDecodeError):
            out[asset] = None
    return out


def main() -> None:
    evidence = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "window_seconds": WINDOW_SECONDS,
        "alerts": alert_summary(),
        "ruler_rules": ruler_states(),
        "grafana_datasources": grafana_datasources(),
        "historian_last_values": historian_last_values(),
    }
    OUTPUT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
