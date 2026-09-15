import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "lab-environment" / "historian-poller")
)

import historian  # noqa: E402


def test_parse_targets():
    targets = historian.parse_targets("plc_intake=172.21.0.10:502, plc_a=10.0.0.1")
    assert targets == [("plc_intake", "172.21.0.10", 502), ("plc_a", "10.0.0.1", 502)]


def test_decode_registers_intake():
    registers = [1, 60, 0, 0, 0, 78, 0]
    assert historian.decode_registers("plc_intake", registers) == {
        "valve": 1,
        "pump": 60,
        "level": 78,
        "alarm": 0,
    }


def test_decode_registers_ignores_unknown_asset():
    assert historian.decode_registers("plc_unknown", [1, 2, 3]) == {}


def test_decode_registers_skips_short_read():
    # only 2 registers: offset 5 is missing
    assert historian.decode_registers("plc_intake", [1, 60]) == {"valve": 1, "pump": 60}


def test_line_protocol():
    line = historian.line_protocol(
        "process_state", {"asset": "plc_intake", "zone": "control"}, {"level": 78, "valve": 1}
    )
    assert line == "process_state,asset=plc_intake,zone=control level=78i,valve=1i"


def test_line_protocol_none_tag_omitted():
    line = historian.line_protocol("poller_health", {"zone": None}, {"points": 3})
    assert line == "poller_health points=3i"


def test_choose_targets_prefers_reachable_primary(monkeypatch):
    monkeypatch.setattr(historian, "reachable", lambda host, port, timeout=2.0: host == "primary")
    primary = [("plc_intake", "primary", 502)]
    fallback = [("plc_intake", "fallback", 502)]
    assert historian.choose_targets(primary, fallback) == primary


def test_choose_targets_falls_back(monkeypatch):
    monkeypatch.setattr(historian, "reachable", lambda host, port, timeout=2.0: False)
    primary = [("plc_intake", "primary", 502)]
    fallback = [("plc_intake", "fallback", 502)]
    assert historian.choose_targets(primary, fallback) == fallback
