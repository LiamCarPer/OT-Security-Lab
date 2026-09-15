#!/usr/bin/env python3
"""Live DNP3 telemetry: decode DNP3/TCP and ship the normalized contract.

Every application message is pushed to Loki for the generated ruler rules; the
function-code detections are also written to ``alerts.json`` for evidence. This
is the live counterpart to the offline ``dnp3-dpi`` decoder.
"""
from __future__ import annotations

import os

from otdpi import common, dnp3
from scapy.all import IP, TCP, Raw, sniff

PORT = int(os.getenv("OT_DNP3_PORT", "20000"))


def process_packet(packet) -> None:
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return
    if packet[TCP].dport != PORT:
        return

    event = dnp3.decode(bytes(packet[Raw].load))
    if event is None:
        return

    endpoint = {"src_ip": packet[IP].src, "dst_ip": packet[IP].dst}
    common.push_to_loki("dnp3", {**event, **endpoint})

    if event["direction"] != "request":
        return

    function_code = event["function_code"]
    link_source = event["link_source"]
    base = {
        "protocol": "dnp3",
        "link_source": link_source,
        "link_destination": event["link_destination"],
        "function_code": function_code,
        "function_name": event["function_name"],
        "source_ip": packet[IP].src,
        "dest_ip": packet[IP].dst,
    }

    if function_code in dnp3.CONTROL_FUNCTIONS and link_source not in dnp3.AUTHORIZED_MASTERS:
        common.write_alert(
            {
                "alert_type": "DNP3_UNAUTHORIZED_CONTROL",
                "mitre_id": "T1692.001",
                "description": "DNP3 control operation from an unauthorized master.",
                **base,
            }
        )
    if function_code in dnp3.RESTART_FUNCTIONS:
        common.write_alert(
            {
                "alert_type": "DNP3_RESTART_COMMAND",
                "mitre_id": "T0816",
                "description": "DNP3 cold/warm restart requested.",
                **base,
            }
        )
    if function_code in dnp3.UNSOLICITED_DISABLE:
        common.write_alert(
            {
                "alert_type": "DNP3_UNSOLICITED_DISABLED",
                "mitre_id": "T0878",
                "description": "DNP3 unsolicited responses disabled.",
                **base,
            }
        )


def main() -> None:
    print(f"Starting DNP3 telemetry producer (tcp/{PORT})...", flush=True)
    sniff(iface=common.capture_interfaces(), filter=f"tcp port {PORT}", prn=process_packet, store=0)


if __name__ == "__main__":
    main()
