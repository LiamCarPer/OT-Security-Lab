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
import time
import urllib.request

from scapy.all import ICMP, IP, TCP, UDP, sniff

LOKI_URL = "http://172.24.0.20:3100/loki/api/v1/push"

ZONES = {
    "it": ipaddress.ip_network("172.24.0.0/24"),
    "ops": ipaddress.ip_network("172.23.0.0/24"),
    "supervisory": ipaddress.ip_network("172.22.0.0/24"),
    "control": ipaddress.ip_network("172.21.0.0/24"),
}

# The gateway's own addresses (one per zone); its traffic is not a forwarded flow.
GATEWAY_IPS = {"172.21.0.2", "172.22.0.2", "172.23.0.2", "172.24.0.2"}

# Conduits allowed by lab-environment/network-config/firewall-rules.sh.
CONDUITS = (
    ("supervisory", "control", "TCP", 502),
    ("ops", "control", "TCP", 502),
    ("supervisory", "ops", "TCP", 8086),
    ("it", "ops", "TCP", 8086),
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


if __name__ == "__main__":
    print("[firewall] shipping normalized gateway drops to Loki", flush=True)
    sniff(iface=None, filter="ip", prn=handle, store=0)
