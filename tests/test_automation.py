import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from automation.metrics import summarize  # noqa: E402
from automation.playbooks.auto_block_ip import find_offenders  # noqa: E402


def make_alert(alert_type, src, ts):
    return {"timestamp": ts, "alert_type": alert_type, "source_ip": src}


def test_find_offenders_below_threshold():
    alerts = [
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:00Z"),
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:01Z"),
    ]
    assert find_offenders(alerts, trigger=3) == {}


def test_find_offenders_above_threshold():
    alerts = [
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:00Z"),
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:01Z"),
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:02Z"),
    ]
    offenders = find_offenders(alerts, trigger=3)
    assert offenders == {"172.24.0.10": 3}


def test_find_offenders_ignores_other_alert_types():
    alerts = [
        make_alert("CROSS_ZONE_VIOLATION", "172.24.0.10", "2026-08-01T10:00:00Z"),
        make_alert("CROSS_ZONE_VIOLATION", "172.24.0.10", "2026-08-01T10:00:01Z"),
        make_alert("CROSS_ZONE_VIOLATION", "172.24.0.10", "2026-08-01T10:00:02Z"),
    ]
    assert find_offenders(alerts, trigger=3) == {}


def test_find_offenders_multiple_sources():
    alerts = [
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:00Z"),
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:01Z"),
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.10", "2026-08-01T10:00:02Z"),
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.11", "2026-08-01T10:00:03Z"),
    ]
    offenders = find_offenders(alerts, trigger=3)
    assert offenders == {"172.24.0.10": 3}


def test_summarize_counts_and_unique_sources():
    alerts = [
        make_alert("CROSS_ZONE_VIOLATION", "172.24.0.10", "2026-08-01T10:00:00Z"),
        make_alert("CROSS_ZONE_VIOLATION", "172.24.0.10", "2026-08-01T10:00:30Z"),
        make_alert("UNAUTHORIZED_MODBUS_WRITE", "172.24.0.11", "2026-08-01T10:00:00Z"),
    ]
    summary = summarize(alerts)
    assert summary["total_alerts"] == 3
    assert summary["rules"]["CROSS_ZONE_VIOLATION"]["count"] == 2
    assert summary["rules"]["CROSS_ZONE_VIOLATION"]["unique_sources"] == 1
    assert summary["rules"]["UNAUTHORIZED_MODBUS_WRITE"]["count"] == 1
    assert summary["total_unique_sources"] == 2


def test_summarize_empty_alerts():
    summary = summarize([])
    assert summary["total_alerts"] == 0
    assert summary["total_unique_sources"] == 0


def test_summarize_invalid_timestamp_no_crash():
    alerts = [
        {"timestamp": "not-a-date", "alert_type": "CROSS_ZONE_VIOLATION", "source_ip": "1.2.3.4"},
    ]
    summary = summarize(alerts)
    assert summary["rules"]["CROSS_ZONE_VIOLATION"]["count"] == 1
    assert summary["rules"]["CROSS_ZONE_VIOLATION"]["first_seen"] is None
