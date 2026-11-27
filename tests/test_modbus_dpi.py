import modbus_dpi
import pytest
from otdpi import common
from scapy.all import IP, TCP, Raw


@pytest.fixture(autouse=True)
def _capture_loki(monkeypatch):
    events = []
    monkeypatch.setattr(
        common,
        "push_to_loki",
        lambda service, fields, job="ot_ndr": events.append((service, fields)),
    )
    return events


def frame(pdu: bytes, direction: str, src="172.24.0.10", dst="172.21.0.10", unit=1):
    mbap = b"\x00\x01\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit])
    if direction == "request":
        return IP(src=src, dst=dst) / TCP(sport=41000, dport=502) / Raw(load=mbap + pdu)
    return IP(src=src, dst=dst) / TCP(sport=502, dport=41000) / Raw(load=mbap + pdu)


def decode(packet, direction):
    return modbus_dpi.decode(
        bytes(packet[Raw].load), packet[IP].src, packet[IP].dst, direction
    )


def test_decode_single_register_write():
    event = decode(frame(bytes([6]) + (1024).to_bytes(2, "big") + (1).to_bytes(2, "big"), "request"), "request")
    assert event["direction"] == "request"
    assert event["function_code"] == 6
    assert event["register"] == 1024
    assert event["register_end"] == 1024
    assert event["value"] == 1


def test_decode_multiple_register_write():
    pdu = bytes([16]) + (3999).to_bytes(2, "big") + (3).to_bytes(2, "big") + bytes([6]) + b"\x00\x01\x00\x02\x00\x03"
    event = decode(frame(pdu, "request"), "request")
    assert event["function_code"] == 16
    assert event["register"] == 3999
    assert event["quantity"] == 3
    assert event["register_end"] == 4001
    assert event["values"] == [1, 2, 3]


def test_decode_response_and_exception():
    response = decode(frame(bytes([3, 4]) + b"\x00\x01\x00\x02", "response", "172.21.0.10", "172.22.0.10"), "response")
    assert response["direction"] == "response"
    assert response["function_code"] == 3
    assert response["values"] == [1, 2]

    exception = decode(frame(bytes([0x83, 2]), "response", "172.21.0.10", "172.22.0.10"), "response")
    assert exception["direction"] == "response"
    assert exception["function_code"] == 3
    assert exception["exception_code"] == 2


def test_process_packet_pushes_the_normalized_event(_capture_loki):
    packet = frame(bytes([6]) + (1024).to_bytes(2, "big") + (1).to_bytes(2, "big"), "request")
    modbus_dpi.process_packet(packet)
    assert len(_capture_loki) == 1
    service, fields = _capture_loki[0]
    assert service == "modbus"
    assert fields["src_ip"] == "172.24.0.10"
    assert fields["dst_ip"] == "172.21.0.10"
    assert fields["register"] == 1024


def test_wrong_port_is_ignored(_capture_loki):
    packet = frame(bytes([6]) + (1024).to_bytes(2, "big") + (1).to_bytes(2, "big"), "request")
    packet[TCP].dport = 9999
    modbus_dpi.process_packet(packet)
    assert _capture_loki == []
