import os
import sys

import pytest
from scapy.all import IP, TCP, Raw

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection", "rules"))


def modbus_request(src, dst, func_code, reg_addr=0, reg_value=0, unit_id=1):
    mbap = b"\x00\x01\x00\x00\x00\x06" + bytes([unit_id])
    if func_code in (6, 16):
        pdu = bytes([func_code]) + reg_addr.to_bytes(2, "big") + reg_value.to_bytes(2, "big")
    else:
        pdu = bytes([func_code]) + reg_addr.to_bytes(2, "big") + reg_value.to_bytes(2, "big")
    return IP(src=src, dst=dst) / TCP(dport=502) / Raw(load=mbap + pdu)


def modbus_response(src, dst, func_code=3, byte_count=12, regs=b"\x00\x00" * 6):
    mbap = b"\x00\x01\x00\x00\x00\x0f\x01"
    pdu = bytes([func_code, byte_count]) + regs
    return IP(src=src, dst=dst) / TCP(sport=502, dport=45000) / Raw(load=mbap + pdu)


def modbus_multiple_write(src, dst, start, values, unit_id=1):
    """Build a Modbus FC16 (Write Multiple Registers) request."""
    data = b"".join(value.to_bytes(2, "big") for value in values)
    pdu = (
        bytes([16])
        + start.to_bytes(2, "big")
        + len(values).to_bytes(2, "big")
        + bytes([len(data)])
        + data
    )
    mbap = b"\x00\x01\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit_id])
    return IP(src=src, dst=dst) / TCP(dport=502) / Raw(load=mbap + pdu)


@pytest.fixture
def alert_log(tmp_path):
    return tmp_path / "alerts.json"
