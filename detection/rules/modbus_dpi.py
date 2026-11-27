#!/usr/bin/env python3
"""Live Modbus/TCP telemetry: decode both directions and ship the contract.

The lab's ``modbus_anomaly.py`` only writes an alert for an unauthorized write;
it does not publish normalized ``ot_ndr/modbus`` events. The generated ruler
rules need those events, so this producer decodes the MBAP header and the PDU
for requests and responses and pushes one event per frame to Loki.

It deliberately does not duplicate the anomaly detector: the alert log remains
the ground-truth evidence, and the repo's Sigma rules are evaluated from the
normalized stream.
"""
from __future__ import annotations

from otdpi import common
from scapy.all import IP, TCP, Raw, sniff

PORT = 502
SERVICE = "modbus"


def _u16(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "big")


def _values(data: bytes) -> list[int]:
    return [
        int.from_bytes(data[index : index + 2], "big")
        for index in range(0, len(data) - 1, 2)
    ]


def _coils(data: bytes, quantity: int) -> list[bool]:
    bits = []
    for byte in data:
        for bit in range(8):
            bits.append(bool(byte & (1 << bit)))
    return bits[:quantity]


def decode(payload: bytes, src_ip: str, dst_ip: str, direction: str) -> dict | None:
    """Decode one MBAP frame into the normalized contract.

    Returns ``None`` when the frame is not a complete Modbus/TCP frame.
    """
    if len(payload) < 8:
        return None
    protocol = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:6], "big")
    if protocol != 0 or length < 2 or 6 + length > len(payload):
        return None

    transaction = int.from_bytes(payload[0:2], "big")
    unit = payload[6]
    pdu = payload[7 : 6 + length]
    if not pdu:
        return None
    raw_function = pdu[0]
    exception = bool(raw_function & 0x80)
    function = raw_function & 0x7F
    event: dict = {
        "direction": "response" if exception else direction,
        "function_code": function,
        "transaction_id": transaction,
        "unit_id": unit,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }
    if exception:
        event["exception_code"] = pdu[1] if len(pdu) > 1 else None
        return event

    if function in (1, 2, 3, 4):
        if direction == "request":
            event["register"] = _u16(pdu, 1)
            event["quantity"] = _u16(pdu, 3)
        else:
            byte_count = pdu[1] if len(pdu) > 1 else 0
            data = pdu[2 : 2 + byte_count]
            event["byte_count"] = byte_count
            if function in (1, 2):
                event["coils"] = _coils(data, byte_count * 8)
            else:
                event["values"] = _values(data)
                event["quantity"] = len(data) // 2
        return event

    if function == 5:
        register = _u16(pdu, 1)
        value = _u16(pdu, 3)
        event.update(
            {
                "register": register,
                "quantity": 1,
                "register_end": register,
                "value": 1 if value == 0xFF00 else 0,
                "coils": [value == 0xFF00],
            }
        )
        return event

    if function == 6:
        register = _u16(pdu, 1)
        event.update(
            {
                "register": register,
                "quantity": 1,
                "register_end": register,
                "value": _u16(pdu, 3),
            }
        )
        return event

    if function in (15, 16):
        register = _u16(pdu, 1)
        quantity = _u16(pdu, 3)
        event.update({"register": register, "quantity": quantity})
        if register is not None and quantity:
            event["register_end"] = register + quantity - 1
        if direction == "request" and len(pdu) > 5:
            byte_count = pdu[5]
            data = pdu[6 : 6 + byte_count]
            event["byte_count"] = byte_count
            if function == 15:
                event["coils"] = _coils(data, quantity or 0)
            else:
                event["values"] = _values(data)
                event["value"] = event["values"][0] if event["values"] else None
        return event

    if function == 22:
        register = _u16(pdu, 1)
        event.update(
            {
                "register": register,
                "quantity": 1,
                "register_end": register,
                "and_mask": _u16(pdu, 3),
                "or_mask": _u16(pdu, 5),
            }
        )
        return event

    if function == 23:
        if direction == "request":
            read_register = _u16(pdu, 1)
            read_quantity = _u16(pdu, 3)
            write_register = _u16(pdu, 5)
            write_quantity = _u16(pdu, 7)
            event.update(
                {
                    "register": read_register,
                    "quantity": read_quantity,
                    "write_register": write_register,
                    "write_quantity": write_quantity,
                }
            )
            if read_register is not None and read_quantity:
                event["register_end"] = read_register + read_quantity - 1
            if write_register is not None and write_quantity:
                event["write_register_end"] = write_register + write_quantity - 1
            if len(pdu) > 9:
                byte_count = pdu[9]
                event["values"] = _values(pdu[10 : 10 + byte_count])
            return event
        byte_count = pdu[1] if len(pdu) > 1 else 0
        event["values"] = _values(pdu[2 : 2 + byte_count])
        event["quantity"] = len(event["values"])
        return event

    if function == 43 and len(pdu) >= 4:
        event["mei_type"] = pdu[1]
        event["read_device_id_code"] = pdu[2]
        event["object_id"] = pdu[3]
        if direction == "response" and len(pdu) >= 7:
            event["conformity_level"] = pdu[3]
            event["more_follows"] = bool(pdu[4] & 0x80)
            event["next_object_id"] = pdu[5]
        return event

    event["function_name"] = "Unsupported"
    return event


def process_packet(packet) -> None:
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return
    tcp = packet[TCP]
    if tcp.dport != PORT and tcp.sport != PORT:
        return
    direction = "request" if tcp.dport == PORT else "response"
    payload = bytes(packet[Raw].load)
    offset = 0
    while offset + 8 <= len(payload):
        declared = int.from_bytes(payload[offset + 4 : offset + 6], "big")
        total = 6 + declared
        if declared < 2 or offset + total > len(payload):
            break
        event = decode(
            payload[offset : offset + total],
            packet[IP].src,
            packet[IP].dst,
            direction,
        )
        if event is not None:
            common.push_to_loki(SERVICE, {key: value for key, value in event.items() if value is not None})
        offset += total


def main() -> None:
    print(f"Starting Modbus telemetry producer (tcp/{PORT})...", flush=True)
    sniff(iface=common.capture_interfaces(), filter=f"tcp port {PORT}", prn=process_packet, store=0)


if __name__ == "__main__":
    main()
