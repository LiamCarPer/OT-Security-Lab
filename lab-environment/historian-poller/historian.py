"""Pure helpers for the historian collector (no third-party imports).

Kept separate from ``poller.py`` so the parsing, decoding and line-protocol
logic can be unit tested without pymodbus installed.
"""
import socket

# Holding-register offsets -> field name per asset (plc/register-map.md).
FIELDS = {
    "plc_intake": {0: "valve", 1: "pump", 5: "level", 6: "alarm"},
    "plc_treatment": {0: "flow", 1: "dosing", 2: "rate", 5: "chlorine", 6: "alarm"},
    "plc_distribution": {0: "pump", 1: "pressure", 2: "speed", 5: "runtime", 6: "alarm"},
}
REGISTER_COUNT = 7


def parse_targets(value: str) -> list:
    """Parse ``asset=host:port,asset=host:port`` into ``[(asset, host, port)]``."""
    targets = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        asset, _, endpoint = item.partition("=")
        host, _, port = endpoint.partition(":")
        targets.append((asset.strip(), host.strip(), int(port or "502")))
    return targets


def decode_registers(asset: str, registers: list) -> dict:
    """Map raw holding registers to named fields for one asset."""
    return {
        name: int(registers[offset])
        for offset, name in FIELDS.get(asset, {}).items()
        if offset < len(registers)
    }


def line_protocol(measurement: str, tags: dict, fields: dict) -> str:
    """Render one InfluxDB line-protocol point (integer fields)."""
    tag_part = "".join(f",{key}={value}" for key, value in tags.items() if value is not None)
    field_part = ",".join(f"{key}={int(value)}i" for key, value in fields.items())
    return f"{measurement}{tag_part} {field_part}"


def reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((host, port)) == 0
    finally:
        sock.close()


def choose_targets(primary: list, fallback: list) -> list:
    """Return the primary target set if every controller answers, else fallback."""
    if primary and all(reachable(host, port) for _, host, port in primary):
        print("[POLLER] using primary targets (OpenPLC controllers)", flush=True)
        return primary
    print("[POLLER] primary controllers unavailable; using process stand-in", flush=True)
    return fallback
