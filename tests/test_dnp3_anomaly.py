import json

import dnp3_anomaly as rule
from scapy.all import IP, TCP, Raw

HMI = "172.22.0.10"
EWS = "172.23.0.4"
ATTACKER = "172.24.0.10"
RTU = "172.21.0.50"


def dnp3_request(src, dst, function_code):
    header = b"\x05\x64" + bytes([9 + 1 + 1]) + b"\xc4" + b"\x00\x01" + b"\x00\x02"
    header += b"\x00\x00"  # CRC placeholder (not validated by the rule)
    app = bytes([0xc0 | 0x01]) + bytes([function_code])
    return IP(src=src, dst=dst) / TCP(dport=20000) / Raw(load=header + app)


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_authorized_hmi_dnp3_write_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    rule.process_packet(dnp3_request(HMI, RTU, 4))
    assert load_alerts(alert_log) == []


def test_unauthorized_dnp3_direct_operate_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    rule.process_packet(dnp3_request(ATTACKER, RTU, 4))
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "DNP3_WRITE_UNAUTHORIZED"
    assert alerts[0]["source_ip"] == ATTACKER
    assert alerts[0]["function_code"] == 4
    assert alerts[0]["mitre_id"] == "T0831"


def test_unauthorized_dnp3_write_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    rule.process_packet(dnp3_request(ATTACKER, RTU, 3))
    assert load_alerts(alert_log)[0]["alert_type"] == "DNP3_WRITE_UNAUTHORIZED"


def test_dnp3_read_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    rule.process_packet(dnp3_request(ATTACKER, RTU, 1))
    assert load_alerts(alert_log) == []


def test_non_dnp3_payload_ignored(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = IP(src=ATTACKER, dst=RTU) / TCP(dport=20000) / Raw(load=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_truncated_dnp3_payload_ignored(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = IP(src=ATTACKER, dst=RTU) / TCP(dport=20000) / Raw(load=b"\x05\x64")
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []
