#!/usr/bin/env python3
"""Ship normalized ``ot_firewall`` events for gateway cross-zone drops to Loki.

The gateway applies the zone firewall and logs denied traffic with the kernel
``FW_DROP:`` prefix, but those kernel messages cannot be read from inside the
container (``dmesg`` needs CAP_SYSLOG, which this least-privilege gateway does
not have). This process observes the packets the gateway forwards and, for the
new cross-zone flows the conduit policy denies, emits the same normalized
``ot_firewall`` event the generated detection rules consume.

It is launched automatically by ``lab-environment/scripts/start_ids.sh`` and
pushes to Loki's address on the lab's IT network (the multi-homed gateway does
not resolve Docker service names reliably, so the static address is used). The
rule that consumes it is
``Industrial_Protocol_Traffic_From_Enterprise_To_Control_Zone`` in
``siem/rules/ot_firewall_cross_zone_violation.yaml``.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.request
from collections import defaultdict, deque

from otdpi import common
from scapy.all import ICMP, IP, TCP, UDP, sniff

LOKI_URL = "http://172.24.0.20:3100/loki/api/v1/push"

# Beaconing detection (stateful): repeated denied egress from an OT host to the
# Enterprise/external address at a near-constant interval is a C2 pattern.
OT_ZONES = {"ops", "dmz", "supervisory", "control"}
BEACON_WINDOW = float(os.getenv("OT_BEACON_WINDOW", "60"))
BEACON_MIN_EVENTS = int(os.getenv("OT_BEACON_MIN_EVENTS", "5"))
BEACON_MIN_INTERVAL = float(os.getenv("OT_BEACON_MIN_INTERVAL", "0.5"))
BEACON_MAX_CV = float(os.getenv("OT_BEACON_MAX_CV", "0.35"))
# Collapse TCP SYN retransmissions (same beacon) into one event.
BEACON_DEBOUNCE = float(os.getenv("OT_BEACON_DEBOUNCE", "2.0"))
_beacon_times: dict = defaultdict(deque)

ZONES = {
    "it": ipaddress.ip_network("172.24.0.0/24"),
    "dmz": ipaddress.ip_network("172.25.0.0/24"),
    "ops": ipaddress.ip_network("172.23.0.0/24"),
    "supervisory": ipaddress.ip_network("172.22.0.0/24"),
    "control": ipaddress.ip_network("172.21.0.0/24"),
}

# The gateway's own addresses (one per zone); its traffic is not a forwarded flow.
GATEWAY_IPS = {"172.21.0.2", "172.22.0.2", "172.23.0.2", "172.24.0.2", "172.25.0.2"}

# Conduits allowed by lab-environment/network-config/firewall-rules.sh.
CONDUITS = (
    ("supervisory", "control", "TCP", 502),
    ("supervisory", "ops", "TCP", 8086),
    ("it", "ops", "TCP", 8086),
    ("ops", "control", "TCP", 8443),
    ("ops", "control", "TCP", 20000),
    ("ops", "control", "TCP", 4840),
    ("ops", "control", "TCP", 102),
    ("it", "dmz", "TCP", 80),
    ("it", "dmz", "TCP", 22),
    ("dmz", "supervisory", "TCP", 8080),
)


def zone_of(address: str) -> str:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    for name, network in ZONES.items():
        if addr in network:
            return name
    return "unknown"


def is_permitted(src_zone: str, dst_zone: str, proto: str, dst_port: int) -> bool:
    for conduit in CONDUITS:
        if conduit == (src_zone, dst_zone, proto, dst_port):
            return True
    return False


def push_to_loki(line: str) -> None:
    timestamp = str(int(time.time() * 1_000_000_000))
    payload = {
        "streams": [
            {"stream": {"job": "ot_firewall", "service": "iptables"}, "values": [[timestamp, line]]}
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
    except OSError as error:
        print(f"[firewall] loki push failed: {error}", flush=True)


def interval_regularity(times):
    """Return (coefficient_of_variation, mean_interval) for a timestamp list."""
    intervals = [later - earlier for earlier, later in zip(times, times[1:], strict=False)]
    mean = sum(intervals) / len(intervals)
    if mean < BEACON_MIN_INTERVAL:
        return 1.0, mean
    variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
    return (variance ** 0.5) / mean, mean


def check_beacon(src_ip: str, dst_ip: str, dst_port: int, proto: str, now: float) -> None:
    """Flag regular-interval denied egress (beaconing) from an OT host."""
    key = (src_ip, dst_ip, dst_port, proto)
    times = _beacon_times[key]
    # Ignore TCP SYN retransmissions so one beacon counts once.
    if times and now - times[-1] < BEACON_DEBOUNCE:
        return
    times.append(now)
    while times and times[0] < now - BEACON_WINDOW:
        times.popleft()
    if len(times) < BEACON_MIN_EVENTS:
        return

    coefficient, mean = interval_regularity(list(times))
    if coefficient > BEACON_MAX_CV:
        return

    fields = {
        "alert_type": "C2_BEACON",
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": proto,
        "beacon_count": len(times),
        "interval_seconds": round(mean, 2),
        "interval_cv": round(coefficient, 3),
    }
    common.push_to_loki("firewall", fields)
    common.write_alert(
        {
            **fields,
            "mitre_id": "T0869",
            "description": (
                "Regular-interval egress from an OT host to the enterprise/C2 "
                "address (denied by the zone firewall): C2 beaconing pattern."
            ),
        }
    )
    _beacon_times[key].clear()


def handle(packet) -> None:
    if IP not in packet or packet[IP].src in GATEWAY_IPS or packet[IP].dst in GATEWAY_IPS:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_zone = zone_of(src_ip)
    dst_zone = zone_of(dst_ip)
    if src_zone == dst_zone or "unknown" in (src_zone, dst_zone):
        return

    if TCP in packet:
        flags = int(packet[TCP].flags)
        # Only new connections, so return traffic on an allowed conduit is not a drop.
        if not flags & 0x02 or flags & 0x10:
            return
        proto, dst_port = "TCP", int(packet[TCP].dport)
    elif UDP in packet:
        proto, dst_port = "UDP", int(packet[UDP].dport)
    elif ICMP in packet:
        proto, dst_port = "ICMP", 0
    else:
        proto, dst_port = "IP", 0

    if is_permitted(src_zone, dst_zone, proto, dst_port):
        return

    line = (
        f"action=DROP src_zone={src_zone} dst_zone={dst_zone} "
        f"src_ip={src_ip} dst_ip={dst_ip} dst_port={dst_port} proto={proto}"
    )
    push_to_loki(line)
    print(f"[firewall] DROP {src_zone}->{dst_zone} {src_ip}->{dst_ip}:{dst_port} {proto}", flush=True)

    # Stateful: a denied OT -> Enterprise egress repeated at a regular interval
    # is beaconing, regardless of the individual drops.
    if dst_zone == "it" and src_zone in OT_ZONES:
        check_beacon(src_ip, dst_ip, dst_port, proto, time.time())


if __name__ == "__main__":
    print("[firewall] shipping normalized gateway drops to Loki", flush=True)
    sniff(iface=common.capture_interfaces(), filter="ip", prn=handle, store=0)
