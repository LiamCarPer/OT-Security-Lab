#!/usr/bin/env python3
"""Live OPC UA telemetry: decode OPC UA/TCP and ship the normalized contract.

Pushes every message to Loki for the generated ruler rules and writes the
service-level detections (Browse / Write / Call) to ``alerts.json``. Plaintext
(None/Sign) channels expose the service; SignAndEncrypt yields header-only
events.
"""
from __future__ import annotations

import os

from otdpi import common, opcua
from scapy.all import IP, TCP, Raw, sniff

PORT = int(os.getenv("OT_OPCUA_PORT", "4840"))

DETECTIONS = {
    "BrowseRequest": ("OPCUA_BROWSE_REQUEST", "T0888", "OPC UA address space browse."),
    "BrowseNextRequest": (
        "OPCUA_BROWSE_REQUEST",
        "T0888",
        "OPC UA address space browse.",
    ),
    "WriteRequest": ("OPCUA_WRITE_REQUEST", "T1692.001", "OPC UA write request."),
    "CallRequest": ("OPCUA_METHOD_CALL", "T0871", "OPC UA method call request."),
}


def process_packet(packet) -> None:
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return
    if packet[TCP].dport != PORT:
        return

    event = opcua.decode(bytes(packet[Raw].load))
    if event is None:
        return

    endpoint = {"src_ip": packet[IP].src, "dst_ip": packet[IP].dst}
    common.push_to_loki("opcua", {**event, **endpoint})

    if event.get("direction") != "request":
        return

    detection = DETECTIONS.get(event.get("opcua_service"))
    if not detection:
        return
    alert_type, mitre_id, description = detection
    common.write_alert(
        {
            "alert_type": alert_type,
            "mitre_id": mitre_id,
            "description": description,
            "protocol": "opcua",
            "opcua_service": event.get("opcua_service"),
            "service_id": event.get("service_id"),
            "secure_channel_id": event.get("secure_channel_id"),
            "request_id": event.get("request_id"),
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
        }
    )


def main() -> None:
    print(f"Starting OPC UA telemetry producer (tcp/{PORT})...", flush=True)
    sniff(iface=common.capture_interfaces(), filter=f"tcp port {PORT}", prn=process_packet, store=0)


if __name__ == "__main__":
    main()
