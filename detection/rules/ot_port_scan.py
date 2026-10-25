"""Stateful OT service-port scan detection (MITRE ATT&CK for ICS T0846).

A single SYN to one OT port is normal (the HMI polls Modbus every second). A
single source touching three or more distinct OT service ports inside the
window is service discovery, even when the zone firewall drops every probe.
The detector is passive: it observes the packets the gateway forwards and
writes the same ``OT_PORT_SCAN`` alert to the evidence log and Loki.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque

import scapy.all as scapy
from otdpi import common

OT_PORTS = {102, 502, 4840, 8443, 20000}
WINDOW_SECONDS = int(os.getenv("OT_PORT_SCAN_WINDOW", "60"))
MIN_PORTS = int(os.getenv("OT_PORT_SCAN_MIN_PORTS", "3"))
COOLDOWN_SECONDS = int(os.getenv("OT_PORT_SCAN_COOLDOWN", "300"))

_events: dict[str, deque] = defaultdict(deque)
_last_alert: dict[str, float] = {}


def reset_state() -> None:
    _events.clear()
    _last_alert.clear()


def process_packet(packet, now: float | None = None) -> None:
    if not (packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP)):
        return

    tcp = packet[scapy.TCP]
    flags = int(tcp.flags)
    # New connection attempts only: SYN without ACK.
    if not flags & 0x02 or flags & 0x10:
        return
    dst_port = int(tcp.dport)
    if dst_port not in OT_PORTS:
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    timestamp = time.time() if now is None else now
    if timestamp - _last_alert.get(src_ip, 0) < COOLDOWN_SECONDS:
        return
    events = _events[src_ip]
    events.append((timestamp, dst_ip, dst_port))
    while events and events[0][0] < timestamp - WINDOW_SECONDS:
        events.popleft()

    ports = {event[2] for event in events}
    if len(ports) < MIN_PORTS:
        return

    fields = {
        "alert_type": "OT_PORT_SCAN",
        "source_ip": src_ip,
        "dest_ips": ",".join(sorted({event[1] for event in events})),
        "dest_ports": ",".join(str(port) for port in sorted(ports)),
        "port_count": len(ports),
        "window_seconds": WINDOW_SECONDS,
    }
    common.push_to_loki("port_scan", fields)
    common.write_alert(
        {
            **fields,
            "mitre_id": "T0846",
            "description": (
                "A single source probed multiple OT service ports (Modbus, "
                "S7comm, DNP3, OPC UA or OpenPLC API): service discovery."
            ),
        }
    )
    events.clear()
    _last_alert[src_ip] = timestamp


def main() -> None:
    print(f"[port-scan] watching {sorted(OT_PORTS)} for >= {MIN_PORTS} ports / {WINDOW_SECONDS}s", flush=True)
    scapy.sniff(iface=common.capture_interfaces(), filter="tcp", prn=process_packet, store=0)


if __name__ == "__main__":
    main()
