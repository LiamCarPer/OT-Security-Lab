import json

import process_safety_violation as rule
from conftest import modbus_request, modbus_response

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
