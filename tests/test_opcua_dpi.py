import json

import opcua_dpi
import pytest
from otdpi import common, opcua
from scapy.all import IP, TCP, Raw


def opcua_msg(service_id, message_type=b"MSG", channel=1, token=1, sequence=2, request_id=2):
    body = bytes([0x01, 0x00]) + service_id.to_bytes(2, "little")  # FourByte NodeId, ns 0
    if message_type != b"MSG":
        body = b""
    header = b"MSGF"
    payload = header + (0).to_bytes(4, "little")
    payload += channel.to_bytes(4, "little") + token.to_bytes(4, "little")
    payload += sequence.to_bytes(4, "little") + request_id.to_bytes(4, "little")
    payload += body
    size = len(payload)
    return payload[:4] + size.to_bytes(4, "little") + payload[8:]


def packet(payload, dport=4840):
    return IP(src="172.23.0.20", dst="172.21.0.51") / TCP(dport=dport) / Raw(load=payload)


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture(autouse=True)
def _no_loki(monkeypatch):
    monkeypatch.setattr(common, "push_to_loki", lambda *a, **k: True)


def test_decode_write_request():
    event = opcua.decode(opcua_msg(673))
    assert event["message_type"] == "MSG"
    assert event["opcua_service"] == "WriteRequest"
    assert event["service_id"] == 673
    assert event["direction"] == "request"
    assert event["secure_channel_id"] == 1
    assert event["request_id"] == 2


def test_decode_hel_header_only():
    event = opcua.decode(b"HELF" + (8).to_bytes(4, "little"))
    assert event == {"message_type": "HEL", "chunk_type": "F"}


def test_decode_ignores_non_opcua():
    assert opcua.decode(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08") is None


def test_write_request_alert(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    opcua_dpi.process_packet(packet(opcua_msg(673)))
    alerts = load_alerts(alert_log)
    assert alerts[0]["alert_type"] == "OPCUA_WRITE_REQUEST"
    assert alerts[0]["mitre_id"] == "T1692.001"


def test_method_call_alert(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    opcua_dpi.process_packet(packet(opcua_msg(712)))
    assert load_alerts(alert_log)[0]["alert_type"] == "OPCUA_METHOD_CALL"


def test_browse_alert(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    opcua_dpi.process_packet(packet(opcua_msg(527)))
    assert load_alerts(alert_log)[0]["alert_type"] == "OPCUA_BROWSE_REQUEST"


def test_response_not_alerted(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    opcua_dpi.process_packet(packet(opcua_msg(676)))
    assert load_alerts(alert_log) == []
