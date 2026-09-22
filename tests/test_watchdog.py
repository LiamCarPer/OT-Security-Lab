"""Unit tests for the detection-availability watchdog (Inhibit Response Function)."""
import watchdog as rule


def test_producers_excludes_self():
    scripts = rule.producers()
    assert "watchdog.py" not in scripts
    assert "firewall_events.py" in scripts


def test_check_raises_for_stopped_producer(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule.common, "push_to_loki", lambda *args, **kwargs: True)
    monkeypatch.setattr(rule, "running", lambda script: False)
    rule._last_alerted.clear()

    rule.check(["modbus_anomaly.py"], now=1000.0)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "DETECTION_SERVICE_DOWN"
    assert alerts[0]["service"] == "modbus_anomaly.py"
    assert alerts[0]["mitre_id"] == "T0881"


def test_check_quiet_when_producer_running(monkeypatch):
    alerts = []
    monkeypatch.setattr(rule.common, "write_alert", alerts.append)
    monkeypatch.setattr(rule, "running", lambda script: True)
    rule._last_alerted.clear()

    rule.check(["modbus_anomaly.py"], now=1000.0)

    assert alerts == []
