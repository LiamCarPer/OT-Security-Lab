import responder


def test_threshold_reached():
    state = {}
    assert responder.record(state, "1.2.3.4", 100, window=300, threshold=3) is False
    assert responder.record(state, "1.2.3.4", 101, window=300, threshold=3) is False
    assert responder.record(state, "1.2.3.4", 102, window=300, threshold=3) is True


def test_window_prunes_old_offences():
    state = {}
    assert responder.record(state, "1.2.3.4", 0, window=60, threshold=2) is False
    # 200s later the first offence has aged out, so this is only the first in-window.
    assert responder.record(state, "1.2.3.4", 200, window=60, threshold=2) is False


def test_sources_are_tracked_independently():
    state = {}
    responder.record(state, "1.1.1.1", 10, window=60, threshold=2)
    assert responder.record(state, "2.2.2.2", 10, window=60, threshold=2) is False


def test_dry_run_does_not_touch_iptables(monkeypatch):
    calls = []
    monkeypatch.setattr(responder.subprocess, "run", lambda *a, **k: calls.append(a))
    assert responder.apply_drop("1.2.3.4", enforce=False) == "dry-run"
    assert calls == []
