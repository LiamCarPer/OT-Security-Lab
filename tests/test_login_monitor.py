import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "lab-environment" / "hmi-login-monitor")
)

import monitor  # noqa: E402


def test_failed_login_is_detected():
    entry = {
        "request": "POST /Scada-LTS/login.htm HTTP/1.1",
        "location": "http://172.25.0.10/Scada-LTS/login.htm?error",
    }
    assert monitor.is_login_failure(entry) is True


def test_successful_login_redirect_is_not_a_failure():
    entry = {
        "request": "POST /Scada-LTS/login.htm HTTP/1.1",
        "location": "http://172.25.0.10/Scada-LTS/",
    }
    assert monitor.is_login_failure(entry) is False


def test_get_login_page_is_not_counted():
    assert monitor.is_login_failure({"request": "GET /Scada-LTS/login.htm HTTP/1.1"}) is False


def test_threshold_and_window():
    state = {}
    assert monitor.record(state, "10.0.0.9", 100, window=300, threshold=3) is False
    assert monitor.record(state, "10.0.0.9", 101, window=300, threshold=3) is False
    assert monitor.record(state, "10.0.0.9", 102, window=300, threshold=3) is True
    # old attempts age out of the window
    assert monitor.record(state, "10.0.0.9", 500, window=300, threshold=3) is False
