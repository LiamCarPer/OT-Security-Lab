import json

import process_safety_violation as rule
import pytest
from conftest import modbus_multiple_write, modbus_request, modbus_response
from otdpi import common


@pytest.fixture(autouse=True)
def _no_loki(monkeypatch):
    monkeypatch.setattr(common, "push_to_loki", lambda *args, **kwargs: True)

HMI = "172.22.0.10"
PLC = "172.21.0.10"
ATTACKER = "172.24.0.10"


def load_alerts(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def set_tank_level(alert_log, level):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    regs = b"\x00\x00" * 5 + level.to_bytes(2, "big")
    rule.process_packet(modbus_response(PLC, HMI, func_code=3, byte_count=12, regs=regs))


def open_valve(src=HMI):
    return modbus_request(src, PLC, 6, reg_addr=0, reg_value=1)


def test_open_valve_at_overflow_level_alerted(alert_log):
    set_tank_level(alert_log, 95)
    rule.process_packet(open_valve())
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PROCESS_SAFETY_VIOLATION"
    assert alerts[0]["source_ip"] == HMI
    assert alerts[0]["mitre_id"] == "T0836"
    assert "95" in alerts[0]["details"]


def test_open_valve_at_safe_level_not_alerted(alert_log):
    set_tank_level(alert_log, 50)
    rule.process_packet(open_valve())
    assert load_alerts(alert_log) == []


def test_open_valve_with_unknown_level_not_alerted(alert_log):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    rule.process_packet(open_valve())
    assert load_alerts(alert_log) == []


def test_close_valve_at_overflow_level_not_alerted(alert_log):
    set_tank_level(alert_log, 95)
    rule.process_packet(modbus_request(HMI, PLC, 6, reg_addr=0, reg_value=0))
    assert load_alerts(alert_log) == []


def test_write_to_other_register_not_alerted(alert_log):
    set_tank_level(alert_log, 95)
    rule.process_packet(modbus_request(HMI, PLC, 6, reg_addr=4, reg_value=1))
    assert load_alerts(alert_log) == []


def test_unauthorized_open_valve_at_overflow_alerted(alert_log):
    set_tank_level(alert_log, 95)
    rule.process_packet(open_valve(src=ATTACKER))
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == ATTACKER


def test_level_shadowing_updates_after_open_valve(alert_log):
    set_tank_level(alert_log, 95)
    rule.process_packet(open_valve())
    assert rule.shadow_registers[rule.INLET_VALVE_REG] == 1


def test_fc16_open_valve_at_overflow_level_alerted(alert_log):
    set_tank_level(alert_log, 95)
    rule.process_packet(modbus_multiple_write(HMI, PLC, start=0, values=[1]))
    alerts = load_alerts(alert_log)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PROCESS_SAFETY_VIOLATION"


def test_fc16_only_valve_register_is_checked(alert_log):
    set_tank_level(alert_log, 95)
    # second value (reg 1) is 1, but the inlet valve (reg 0) stays closed
    rule.process_packet(modbus_multiple_write(HMI, PLC, start=0, values=[0, 1]))
    assert load_alerts(alert_log) == []


def test_short_read_does_not_shadow_level(alert_log):
    rule.LOG_FILE = str(alert_log)
    rule.reset_state()
    # byte_count=8 -> only registers 0..3; level register (5) is absent
    regs = b"\x00\x00" * 4
    rule.process_packet(modbus_response(PLC, HMI, func_code=3, byte_count=8, regs=regs))
    assert rule.shadow_registers[rule.TANK_LEVEL_REG] == 0


def test_alert_contains_normalized_siem_fields(alert_log):
    set_tank_level(alert_log, 95)
    rule.process_packet(open_valve())
    alert = load_alerts(alert_log)[0]
    assert alert["event_type"] == "process_safety_violation"
    assert alert["tank_level_pct"] == 95
    assert alert["actor"] == HMI
    assert alert["asset"] == "PLC-01"
    assert alert["response"] == "none"
