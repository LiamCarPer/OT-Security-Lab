"""Unit tests for the stateful OT service-port scan detector."""
import ot_port_scan as rule
from scapy.all import IP, TCP

ATTACKER = "172.24.0.10"
PLC = "172.21.0.10"


def syn(dst, port, src=ATTACKER):
    return IP(src=src, dst=dst) / TCP(sport=40000, dport=port, flags="S")


def test_three_distinct_ports_trigger_alert(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule.reset_state()

    for port in (502, 102, 20000):
        rule.process_packet(syn(PLC, port), now=1000.0)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "OT_PORT_SCAN"
    assert alerts[0]["source_ip"] == ATTACKER
    assert alerts[0]["port_count"] == 3
    assert alerts[0]["mitre_id"] == "T0846"


def test_two_ports_do_not_trigger(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule.reset_state()

    for port in (502, 102):
        rule.process_packet(syn(PLC, port), now=1000.0)

    assert alerts == []


def test_normal_hmi_polling_does_not_trigger(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule.reset_state()

    for _ in range(10):
        rule.process_packet(syn(PLC, 502, src="172.22.0.10"), now=1000.0)

    assert alerts == []


def test_window_expiry_resets_ports(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule.reset_state()

    rule.process_packet(syn(PLC, 502), now=1000.0)
    rule.process_packet(syn(PLC, 102), now=1000.0)
    rule.process_packet(syn(PLC, 20000), now=1000.0 + rule.WINDOW_SECONDS + 1)

    assert alerts == []


def test_syn_ack_is_ignored(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule.reset_state()

    for port in (502, 102, 20000):
        packet = IP(src=PLC, dst=ATTACKER) / TCP(sport=port, dport=40000, flags="SA")
        rule.process_packet(packet, now=1000.0)

    assert alerts == []


def test_cooldown_suppresses_repeated_alerts(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule.reset_state()

    for port in (502, 102, 20000):
        rule.process_packet(syn(PLC, port), now=1000.0)
    assert len(alerts) == 1

    # A continued scan inside the cooldown must not flood the alert stream.
    for port in (502, 102, 20000, 4840):
        rule.process_packet(syn(PLC, port), now=1001.0)
    assert len(alerts) == 1

    # After the cooldown a new scan is a new alert.
    for port in (502, 102, 20000):
        rule.process_packet(syn(PLC, port), now=1000.0 + rule.COOLDOWN_SECONDS + 1)
    assert len(alerts) == 2
