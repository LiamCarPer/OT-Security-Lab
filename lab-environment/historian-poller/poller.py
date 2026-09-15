#!/usr/bin/env python3
"""Historian collector: Modbus FC3 -> InfluxDB line protocol.

Runs in the Supervisory zone and reads the controllers over conduit C1
(Supervisory -> Control 502), then writes the process values northbound to the
Level 3 InfluxDB over conduit C3 (Supervisory -> Ops 8086). Prefers the real
OpenPLC targets and falls back to the Modbus process stand-in when the
controllers are not yet programmed.
"""
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from historian import choose_targets, decode_registers, line_protocol, parse_targets
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

INFLUX_URL = os.getenv("OT_INFLUX_URL", "http://172.23.0.10:8086").rstrip("/")
INFLUX_DB = os.getenv("OT_INFLUX_DB", "ot_data")
INFLUX_RP = os.getenv("OT_INFLUX_RP", "ot_30d")
POLL_INTERVAL = float(os.getenv("OT_POLL_INTERVAL", "5"))
UNIT_ID = int(os.getenv("OT_POLL_UNIT", "1"))
ZONE = os.getenv("OT_POLL_ZONE", "control")
HEALTH_FILE = os.getenv("OT_POLL_HEALTH_FILE", "/tmp/poller.ok")
PRIMARY = os.getenv(
    "OT_POLL_PRIMARY",
    "plc_intake=172.21.0.10:502,plc_treatment=172.21.0.11:502,plc_distribution=172.21.0.12:502",
)
FALLBACK = os.getenv(
    "OT_POLL_FALLBACK",
    "plc_intake=172.21.0.60:502,plc_treatment=172.21.0.61:502,plc_distribution=172.21.0.62:502",
)


def http_post(path: str, params: dict, body: bytes, content_type: str) -> bool:
    query = urllib.parse.urlencode(params)
    url = f"{INFLUX_URL}{path}"
    if query:
        url = f"{url}?{query}"
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": content_type}
    )
    try:
        # Fixed internal InfluxDB URL, not user input.
        urllib.request.urlopen(request, timeout=5).read()  # nosec B310
        return True
    except urllib.error.HTTPError as error:
        # 400 on CREATE ... already exists is expected and idempotent.
        if error.code == 400:
            return True
        print(f"[POLLER] influx error {error.code}: {error.reason}", flush=True)
        return False
    except OSError as error:
        print(f"[POLLER] influx unreachable: {error}", flush=True)
        return False


def ensure_schema() -> None:
    http_post("/query", {"q": f"CREATE DATABASE {INFLUX_DB}"}, b"", "text/plain")
    http_post(
        "/query",
        {"q": f"CREATE RETENTION POLICY {INFLUX_RP} ON {INFLUX_DB} DURATION 30d REPLICATION 1 DEFAULT"},
        b"",
        "text/plain",
    )


def write_points(lines: list) -> bool:
    if not lines:
        return True
    body = ("\n".join(lines) + "\n").encode("utf-8")
    return http_post("/write", {"db": INFLUX_DB, "precision": "s"}, body, "text/plain")


def poll_once(clients: dict, targets: list) -> bool:
    lines = []
    ok = True
    for asset, host, port in targets:
        client = clients.get(asset)
        if client is None or not client.connected:
            client = ModbusTcpClient(host, port=port, timeout=3)
            client.connect()
            clients[asset] = client
        try:
            response = client.read_holding_registers(0, count=7, slave=UNIT_ID)
        except (ModbusException, OSError) as error:
            print(f"[POLLER] {asset} connection error: {error}", flush=True)
            client.close()
            clients.pop(asset, None)
            ok = False
            continue
        if response.isError():
            print(f"[POLLER] {asset} read error: {response}", flush=True)
            client.close()
            clients.pop(asset, None)
            ok = False
            continue
        values = decode_registers(asset, response.registers)
        lines.append(line_protocol("process_state", {"asset": asset, "zone": ZONE}, values))
        print(f"[POLLER] {asset} {values}", flush=True)

    lines.append(
        line_protocol("poller_health", {"zone": ZONE}, {"points": len(lines), "ok": 1 if ok else 0})
    )
    if not write_points(lines):
        ok = False
    if ok:
        with open(HEALTH_FILE, "w", encoding="utf-8") as handle:
            handle.write(str(int(time.time())))
    return ok


def main() -> None:
    print(f"Historian poller -> {INFLUX_URL} db={INFLUX_DB} rp={INFLUX_RP}", flush=True)
    primary = parse_targets(PRIMARY)
    fallback = parse_targets(FALLBACK)
    ensure_schema()
    clients = {}
    while True:
        # Re-evaluate the source each cycle so the collector upgrades itself the
        # moment the OpenPLC program bundles are deployed.
        targets = choose_targets(primary, fallback)
        poll_once(clients, targets)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
