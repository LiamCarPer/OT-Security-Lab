#!/usr/bin/env python3
"""Verify the L2/L3 data path: (stand-in|OpenPLC) -> poller -> InfluxDB -> Grafana.

The OT zones are Docker `internal` networks, so their ports are not published on
the host; InfluxDB and Scada-LTS are queried with ``docker exec`` instead.
Grafana lives on the IT network and is queried over HTTP, which also proves the
Grafana -> InfluxDB path traverses the gateway (conduit C4).
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_GRAFANA = "http://localhost:3000"
ASSETS = ("plc_intake", "plc_treatment", "plc_distribution")
PRIMARY_FIELD = {"plc_intake": "level", "plc_treatment": "chlorine", "plc_distribution": "pressure"}
FRESHNESS_SECONDS = 60
HISTORY_XID = "DP_DS_PLC1_HR5"
INFLUX_CONTAINER = "ot_historian"
SCADA_CONTAINER = "ot_scada_provisioner"


def docker_exec(container: str, command: str) -> str:
    result = subprocess.run(
        ["docker", "exec", container, "sh", "-c", command],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise OSError(result.stderr.strip() or f"docker exec {container} failed")
    return result.stdout


def influx_query(query: str):
    output = docker_exec(
        INFLUX_CONTAINER, f"influx -database ot_data -execute {json.dumps(query)} -format json"
    )
    return json.loads(output)


def check_historian() -> list:
    results = []
    try:
        payload = influx_query('SELECT last("level") FROM "process_state" WHERE "asset"=\'plc_intake\'')
        values = payload["results"][0]["series"][0]["values"][0]
        timestamp = values[0]
        level = values[1]
        age = abs(time.time() - timestamp / 1_000_000_000)
        results.append(("InfluxDB intake level is fresh", age < FRESHNESS_SECONDS, f"age={age:.0f}s level={level}"))
        results.append(("InfluxDB intake level in range", 0 <= level <= 100, f"level={level}"))
    except (OSError, KeyError, IndexError, TypeError, ValueError) as error:
        results.append(("InfluxDB intake level is fresh", False, f"error: {error}"))

    for asset in ASSETS:
        field = PRIMARY_FIELD[asset]
        try:
            payload = influx_query(f'SELECT count("{field}") FROM "process_state" WHERE "asset"=\'{asset}\'')
            count = payload["results"][0]["series"][0]["values"][0][1]
            results.append((f"InfluxDB has points for {asset}", count > 0, f"{field} points={count}"))
        except (OSError, KeyError, IndexError, TypeError, ValueError) as error:
            results.append((f"InfluxDB has points for {asset}", False, f"error: {error}"))
    return results


def _grafana_post(url: str, payload: dict):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
        return json.loads(response.read().decode("utf-8"))


def check_grafana(grafana_url: str) -> list:
    results = []
    try:
        with urllib.request.urlopen(f"{grafana_url}/api/datasources", timeout=10) as response:  # nosec B310
            datasources = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError) as error:
        return [("Grafana has the InfluxDB historian datasource", False, f"error: {error}")]
    influx = next((ds for ds in datasources if ds.get("type") == "influxdb"), None)
    results.append(
        (
            "Grafana has the InfluxDB historian datasource",
            influx is not None,
            influx["name"] if influx else "absent",
        )
    )
    if influx is None:
        return results

    try:
        payload = _grafana_post(
            f"{grafana_url}/api/ds/query",
            {
                "queries": [
                    {
                        "refId": "A",
                        "datasource": {"type": "influxdb", "uid": influx.get("uid")},
                        "rawQuery": True,
                        "query": "SELECT last(\"level\") FROM \"process_state\" WHERE \"asset\"='plc_intake'",
                        "resultFormat": "time_series",
                    }
                ],
                "from": "now-5m",
                "to": "now",
            },
        )
        frames = payload["results"]["A"].get("frames", [])
        results.append(("Grafana queries the historian through the gateway", len(frames) > 0, f"frames={len(frames)}"))
    except (OSError, KeyError, TypeError, ValueError) as error:
        results.append(("Grafana queries the historian through the gateway", False, f"error: {error}"))
    return results


def check_scada_history() -> list:
    end = int(time.time() * 1000)
    start = end - 180_000
    command = (
        "B=http://hmi:8080/Scada-LTS; "
        'sid=$(curl -s -D - -o /dev/null "$B/api/auth/admin/admin" | tr -d "\\r" '
        "| sed -n 's/^Set-Cookie: JSESSIONID=\\([^;]*\\).*/\\1/p'); "
        f'curl -s -H "Cookie: JSESSIONID=$sid" "$B/api/point_value/getValuesFromTimePeriod/xid/{HISTORY_XID}/{start}/{end}"'
    )
    try:
        payload = json.loads(docker_exec(SCADA_CONTAINER, command))
        values = payload.get("values", [])
        return [("Scada-LTS records point history", len(values) > 0, f"samples={len(values)}")]
    except (OSError, ValueError) as error:
        return [("Scada-LTS records point history", False, f"error: {error}")]


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Historian data-path verification")
    parser.add_argument("--grafana-url", default=DEFAULT_GRAFANA)
    args = parser.parse_args(argv)

    results = check_historian() + check_grafana(args.grafana_url.rstrip("/")) + check_scada_history()
    failed = 0
    print("--- Historian data path ---")
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name} ({detail})")
        failed += 0 if ok else 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
