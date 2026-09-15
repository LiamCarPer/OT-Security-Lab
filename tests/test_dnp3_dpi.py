import json

import dnp3_dpi
import pytest
from otdpi import common, dnp3
from scapy.all import IP, TCP, Raw


def dnp3_frame(function_code, link_source=3, link_destination=10, group=12, control=3, ctrl=0xC4):
    application = bytes([0xC0, function_code, group, 0x01, 0x17, 0x01, control])
    return (
        b"\x05\x64"
        + bytes([14])
        + bytes([ctrl])
        + link_destination.to_bytes(2, "little")
        + link_source.to_bytes(2, "little")
        + b"\x00\x00"
        + b"\xc0"
        + application
    )


def packet(frame, dport=20000):
    return IP(src="172.23.0.20", dst="172.21.0.50") / TCP(dport=dport) / Raw(load=frame)


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture(autouse=True)
def _no_loki(monkeypatch):
    monkeypatch.setattr(common, "push_to_loki", lambda *a, **k: True)


def test_decode_direct_operate_request():
    event = dnp3.decode(dnp3_frame(5))
    assert event["direction"] == "request"
    assert event["function_code"] == 5
    assert event["function_name"] == "Direct Operate"
    assert event["link_source"] == 3
    assert event["link_destination"] == 10
    assert event["object_group"] == 12
    assert event["control_code"] == 3


def test_decode_does_not_require_payload_type():
    assert dnp3.decode(b"\x00\x01\x02") is None
    assert dnp3.decode(b"\x05\x64" + b"\x00" * 8) is None


def test_unauthorized_control_alerts(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    dnp3_dpi.process_packet(packet(dnp3_frame(5, link_source=3)))
    alerts = load_alerts(alert_log)
    assert [a["alert_type"] for a in alerts] == ["DNP3_UNAUTHORIZED_CONTROL"]
    assert alerts[0]["mitre_id"] == "T1692.001"
    assert alerts[0]["link_source"] == 3


def test_authorized_control_not_alerted(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    dnp3_dpi.process_packet(packet(dnp3_frame(5, link_source=1)))
    assert load_alerts(alert_log) == []


def test_restart_and_unsolicited_alerts(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    dnp3_dpi.process_packet(packet(dnp3_frame(13, link_source=3)))
    dnp3_dpi.process_packet(packet(dnp3_frame(21, link_source=3)))
    types = [a["alert_type"] for a in load_alerts(alert_log)]
    assert types == ["DNP3_RESTART_COMMAND", "DNP3_UNSOLICITED_DISABLED"]


def test_read_not_alerted(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    dnp3_dpi.process_packet(packet(dnp3_frame(1)))
    assert load_alerts(alert_log) == []


def test_wrong_port_ignored(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    dnp3_dpi.process_packet(packet(dnp3_frame(5), dport=502))
    assert load_alerts(alert_log) == []
