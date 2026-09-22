"""Unit tests for the stateful C2-beacon detection in ``firewall_events.py``.

The live behaviour is asserted by the compliance gate; these pin the interval
maths and the retransmission debounce so the logic cannot silently drift.
"""
import firewall_events as rule


def test_interval_regularity_regular():
    cv, mean = rule.interval_regularity([0.0, 5.0, 10.0, 15.0, 20.0])
    assert cv == 0.0
    assert mean == 5.0


def test_interval_regularity_irregular():
    cv, _ = rule.interval_regularity([0.0, 1.0, 9.0, 11.0, 30.0])
    assert cv > rule.BEACON_MAX_CV


def test_check_beacon_emits_for_regular_egress(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule._beacon_times.clear()

    for step in range(5):
        rule.check_beacon("172.23.0.20", "172.24.0.10", 443, "TCP", float(step) * 5.0)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "C2_BEACON"
    assert alerts[0]["beacon_count"] == 5
    assert alerts[0]["mitre_id"] == "T0869"


def test_check_beacon_collapses_retransmissions(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule._beacon_times.clear()

    # Each beacon is a SYN plus a retransmit ~1s later; only one should count.
    for now in (0.0, 1.0, 5.0, 6.0, 10.0, 11.0, 15.0, 16.0, 20.0, 21.0):
        rule.check_beacon("172.23.0.20", "172.24.0.10", 443, "TCP", now)

    assert len(alerts) == 1
    assert alerts[0]["beacon_count"] == 5


def test_check_beacon_ignores_irregular(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    rule._beacon_times.clear()

    for now in (0.0, 1.0, 9.0, 11.0, 30.0):
        rule.check_beacon("172.23.0.20", "172.24.0.10", 443, "TCP", now)

    assert alerts == []
