import json

import modbus_anomaly as rule
from conftest import modbus_request

HMI = "172.22.0.10"
EWS = "172.23.0.4"
ATTACKER = "172.24.0.10"
PLC = "172.21.0.10"


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_authorized_hmi_write_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request(HMI, PLC, 6, reg_addr=0, reg_value=1)
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_authorized_ews_write_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request(EWS, PLC, 6, reg_addr=0, reg_value=1)
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_unauthorized_write_single_register_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request(ATTACKER, PLC, 6, reg_addr=3, reg_value=1)
    rule.process_packet(packet)
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "UNAUTHORIZED_MODBUS_WRITE"
    assert alerts[0]["source_ip"] == ATTACKER
    assert alerts[0]["target_register"] == 3
    assert alerts[0]["mitre_id"] == "T0831"


def test_unauthorized_write_multiple_registers_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request(ATTACKER, PLC, 16, reg_addr=0, reg_value=1)
    rule.process_packet(packet)
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "UNAUTHORIZED_MODBUS_WRITE"


def test_read_command_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request(ATTACKER, PLC, 3)
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_truncated_payload_no_crash(alert_log):
    rule.LOG_FILE = str(alert_log)
    from scapy.all import IP, TCP, Raw
    packet = IP(src=ATTACKER, dst=PLC) / TCP(dport=502) / Raw(load=b"\x00\x01")
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_non_tcp502_packet_ignored(alert_log):
    rule.LOG_FILE = str(alert_log)
    from scapy.all import IP, TCP
    packet = IP(src=ATTACKER, dst=PLC) / TCP(dport=80)
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_invalid_src_ip_treated_as_untrusted(alert_log):
    rule.LOG_FILE = str(alert_log)
    from scapy.all import IP
    from scapy.packet import RawVal
    packet = modbus_request("172.24.0.10", PLC, 6)
    packet[IP].src = RawVal(b"\xff\xff\x01\x01")
    rule.process_packet(packet)
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "UNAUTHORIZED_MODBUS_WRITE"
