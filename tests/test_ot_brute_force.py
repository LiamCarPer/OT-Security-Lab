import json

import ot_brute_force as rule
from conftest import modbus_request

ATTACKER = "172.24.0.10"
PLC = "172.21.0.10"


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_exception_burst_triggers_alert(alert_log, monkeypatch):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    clock = {"t": 1000.0}
    monkeypatch.setattr(rule.time, "time", lambda: clock["t"])

    for _ in range(5):
        rule.process_packet(modbus_request(ATTACKER, PLC, 131))
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "OT_BRUTE_FORCE_SCAN"
    assert alerts[0]["source_ip"] == ATTACKER
    assert alerts[0]["error_count"] == 5
    assert alerts[0]["mitre_id"] == "T0846"


def test_below_threshold_not_alerted(alert_log, monkeypatch):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    clock = {"t": 1000.0}
    monkeypatch.setattr(rule.time, "time", lambda: clock["t"])

    for _ in range(4):
        rule.process_packet(modbus_request(ATTACKER, PLC, 131))
    assert load_alerts(alert_log) == []


def test_window_expiry_resets_count(alert_log, monkeypatch):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    clock = {"t": 1000.0}
    monkeypatch.setattr(rule.time, "time", lambda: clock["t"])

    for _ in range(4):
        rule.process_packet(modbus_request(ATTACKER, PLC, 131))
    clock["t"] += rule.WINDOW_SECONDS + 1
    rule.process_packet(modbus_request(ATTACKER, PLC, 131))
    assert load_alerts(alert_log) == []


def test_normal_function_code_not_alerted(alert_log, monkeypatch):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    monkeypatch.setattr(rule.time, "time", lambda: 1000.0)

    for _ in range(10):
        rule.process_packet(modbus_request(ATTACKER, PLC, 3))
    assert load_alerts(alert_log) == []


def test_tracker_reset_after_alert(alert_log, monkeypatch):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    clock = {"t": 1000.0}
    monkeypatch.setattr(rule.time, "time", lambda: clock["t"])

    for _ in range(5):
        rule.process_packet(modbus_request(ATTACKER, PLC, 131))
    assert len(load_alerts(alert_log)) == 1

    for _ in range(4):
        rule.process_packet(modbus_request(ATTACKER, PLC, 131))
    assert len(load_alerts(alert_log)) == 1
