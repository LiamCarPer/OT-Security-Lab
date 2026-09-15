#!/usr/bin/env python3
"""Live S7comm telemetry: decode TPKT/COTP/S7comm and ship the normalized contract.

Pushes every S7 job/response to Loki for the generated ruler rules and writes the
protocol-intrinsic detections (program download/upload, PLC control/stop) to
``alerts.json``.
"""
from __future__ import annotations

import os

from otdpi import common, s7comm
from scapy.all import IP, TCP, Raw, sniff

PORT = int(os.getenv("OT_S7COMM_PORT", "102"))

PROGRAM_DOWNLOAD = {0x1A, 0x1B, 0x1C}
PROGRAM_UPLOAD = {0x1D, 0x1E, 0x1F}
CONTROL_OR_STOP = {0x28, 0x29}


def process_packet(packet) -> None:
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return
    if packet[TCP].dport != PORT:
        return

    event = s7comm.decode(bytes(packet[Raw].load))
    if event is None:
        return

    endpoint = {"src_ip": packet[IP].src, "dst_ip": packet[IP].dst}
    common.push_to_loki("s7comm", {**event, **endpoint})

    if event.get("direction") != "request" or "function_code" not in event:
        return

    function_code = event["function_code"]
    base = {
        "protocol": "s7comm",
        "function_code": function_code,
        "function_name": event.get("function_name"),
        "pdu_reference": event.get("pdu_reference"),
        "rosctr": event.get("rosctr"),
        "source_ip": packet[IP].src,
        "dest_ip": packet[IP].dst,
    }

    if function_code in PROGRAM_DOWNLOAD:
        common.write_alert(
            {
                "alert_type": "S7COMM_PROGRAM_DOWNLOAD",
                "mitre_id": "T0843",
                "description": "S7comm program block download to a controller.",
                **base,
            }
        )
    elif function_code in PROGRAM_UPLOAD:
        common.write_alert(
            {
                "alert_type": "S7COMM_PROGRAM_UPLOAD",
                "mitre_id": "T0845",
                "description": "S7comm program block upload from a controller.",
                **base,
            }
        )
    elif function_code in CONTROL_OR_STOP:
        common.write_alert(
            {
                "alert_type": "S7COMM_CHANGE_OPERATING_MODE",
                "mitre_id": "T0858",
                "description": "S7comm PLC Control or PLC Stop requested.",
                **base,
            }
        )


def main() -> None:
    print(f"Starting S7comm telemetry producer (tcp/{PORT})...", flush=True)
    sniff(iface=common.capture_interfaces(), filter=f"tcp port {PORT}", prn=process_packet, store=0)


if __name__ == "__main__":
    main()
