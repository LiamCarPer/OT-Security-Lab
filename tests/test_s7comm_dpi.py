import json

import pytest
import s7comm_dpi
from otdpi import common, s7comm
from scapy.all import IP, TCP, Raw


def s7_frame(function_code, rosctr=1, pdu_reference=0x026B):
    s7 = (
        b"\x32"
        + bytes([rosctr])
        + b"\x00\x00"
        + pdu_reference.to_bytes(2, "big")
        + b"\x00\x0e\x00\x00"
        + bytes([function_code])
    )
    body = b"\x02\xf0\x80" + s7
    total = 4 + len(body)
    return b"\x03\x00" + total.to_bytes(2, "big") + body


def packet(frame, dport=102):
    return IP(src="172.23.0.20", dst="172.21.0.52") / TCP(dport=dport) / Raw(load=frame)


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture(autouse=True)
def _no_loki(monkeypatch):
    monkeypatch.setattr(common, "push_to_loki", lambda *a, **k: True)


def test_decode_request_download():
    event = s7comm.decode(s7_frame(0x1A))
    assert event["direction"] == "request"
    assert event["function_code"] == 0x1A
    assert event["function_name"] == "Request Download"
    assert event["pdu_reference"] == 0x026B
    assert event["cotp_type"] == 0xF0


def test_decode_ack_data_is_response():
    assert s7comm.decode(s7_frame(0x04, rosctr=3))["direction"] == "response"


def test_decode_ignores_connection_setup():
    cotp_only = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01"
    assert "function_code" not in s7comm.decode(cotp_only)


def test_decode_ignores_s7comm_plus():
    frame = bytearray(s7_frame(0x04))
    frame[7] = 0x72
    assert s7comm.decode(bytes(frame)) is None


def test_program_download_alert(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    s7comm_dpi.process_packet(packet(s7_frame(0x1A)))
    alerts = load_alerts(alert_log)
    assert alerts[0]["alert_type"] == "S7COMM_PROGRAM_DOWNLOAD"
    assert alerts[0]["mitre_id"] == "T0843"


def test_program_upload_and_stop_alert(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    s7comm_dpi.process_packet(packet(s7_frame(0x1E)))
    s7comm_dpi.process_packet(packet(s7_frame(0x29)))
    types = [a["alert_type"] for a in load_alerts(alert_log)]
    assert types == ["S7COMM_PROGRAM_UPLOAD", "S7COMM_CHANGE_OPERATING_MODE"]


def test_read_var_not_alerted(alert_log, monkeypatch):
    monkeypatch.setattr(common, "LOG_FILE", str(alert_log))
    s7comm_dpi.process_packet(packet(s7_frame(0x04)))
    assert load_alerts(alert_log) == []
