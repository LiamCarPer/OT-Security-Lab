import json

import cross_zone_traffic as rule
from conftest import modbus_request

IT_HOST = "172.24.0.10"
PLC = "172.21.0.10"
HMI = "172.22.0.10"
GATEWAY = "172.24.0.2"


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_it_to_control_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request(IT_HOST, PLC, 3)
    rule.process_packet(packet)
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "CROSS_ZONE_VIOLATION"
    assert alerts[0]["source_ip"] == IT_HOST
    assert alerts[0]["dest_ip"] == PLC
    assert alerts[0]["mitre_id"] == "T0886"


def test_supervisory_to_control_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request(HMI, PLC, 3)
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_ops_to_control_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    packet = modbus_request("172.23.0.10", PLC, 3)
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []


def test_it_to_ops_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    from scapy.all import IP, TCP
    packet = IP(src=IT_HOST, dst="172.23.0.10") / TCP(dport=8086)
    rule.process_packet(packet)
    assert load_alerts(alert_log) == []
