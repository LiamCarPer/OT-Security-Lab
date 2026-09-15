"""Zone-isolation invariants for the lab compose stack.

These are static checks on `lab-environment/docker-compose.yml` and the firewall
ruleset: they assert the properties the architecture claims (single chokepoint,
internal OT zones, source-restricted conduits) so a claim cannot silently drift.
"""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE = REPO_ROOT / "lab-environment" / "docker-compose.yml"
FIREWALL = REPO_ROOT / "lab-environment" / "network-config" / "firewall-rules.sh"


def _compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_only_the_gateway_is_multihomed():
    """Exactly one service bridges zones: the gateway (the chokepoint)."""
    services = _compose()["services"]
    multihomed = {
        name: list(svc.get("networks") or {})
        for name, svc in services.items()
        if isinstance(svc.get("networks"), dict) and len(svc["networks"]) > 1
    }
    assert set(multihomed) == {"gateway"}, f"unexpected multi-homed services: {multihomed}"


def test_gateway_bridges_every_zone():
    networks = set(_compose()["services"]["gateway"]["networks"])
    assert {
        "it_network",
        "ops_network",
        "supervisory_network",
        "control_network",
    } <= networks


def test_ot_zones_are_internal():
    networks = _compose()["networks"]
    for name, config in networks.items():
        if name == "it_network":
            continue
        assert config.get("internal") is True, f"{name} must be internal"


def test_firewall_is_default_deny():
    rules = FIREWALL.read_text(encoding="utf-8")
    assert "iptables -P FORWARD DROP" in rules
    assert "iptables -P INPUT DROP" in rules


def test_sensitive_conduits_are_source_restricted():
    """The deployment API and the protocol endpoints allow only their host."""
    rules = FIREWALL.read_text(encoding="utf-8")
    for source, port in (("172.23.0.4", "8443"), ("172.23.0.20", "20000")):
        assert f"-s {source} -p tcp --dport {port}" in rules, f"C{port} not source-restricted"
