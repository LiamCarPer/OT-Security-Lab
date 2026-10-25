"""Static validation for the Sigma rules in ``detection/sigma``.

The lab's live Loki bundle is generated elsewhere; these checks keep the
portable Sigma rules honest: required metadata, unique IDs, a real detection
block and ATT&CK for ICS tags that exist in the vendored catalog.
"""
import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = REPO_ROOT / "detection" / "sigma"
CATALOG = REPO_ROOT / "threat-model" / "attack_ics_catalog.json"
REQUIRED = {"title", "id", "status", "description", "logsource", "detection", "level"}
ICS_TAG_RE = re.compile(r"^attack\.ics\.(t[0-9]{4}(?:\.[0-9]{3})?)$")


def _rules():
    return [(path, yaml.safe_load(path.read_text(encoding="utf-8"))) for path in sorted(SIGMA_DIR.glob("*.yml"))]


def _catalog():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    return {tech["id"] for tech in data["techniques"]}


def test_sigma_directory_is_populated():
    assert len(_rules()) >= 8


def test_required_metadata_and_unique_ids():
    ids = {}
    for path, rule in _rules():
        missing = REQUIRED - set(rule)
        assert not missing, f"{path.name} is missing {sorted(missing)}"
        assert rule["logsource"].get("product"), f"{path.name} has no logsource.product"
        assert rule["detection"].get("condition"), f"{path.name} has no detection.condition"
        ids.setdefault(rule["id"], []).append(path.name)
    duplicates = {rule_id: names for rule_id, names in ids.items() if len(names) > 1}
    assert not duplicates, f"duplicate Sigma IDs: {duplicates}"


def test_ics_tags_exist_in_catalog():
    catalog = _catalog()
    missing = []
    for path, rule in _rules():
        for tag in rule.get("tags", []):
            match = ICS_TAG_RE.match(str(tag))
            if match and match.group(1).upper() not in catalog:
                missing.append(f"{path.name}: {tag}")
    assert not missing, f"unknown ATT&CK for ICS tags: {missing}"


def test_powershell_rules_use_script_block_text():
    powershell_rules = [
        rule for path, rule in _rules() if rule.get("logsource", {}).get("service") == "powershell"
    ]
    assert powershell_rules, "expected at least one PowerShell Sigma rule"
    for rule in powershell_rules:
        assert "ScriptBlockText" in yaml.safe_dump(rule["detection"]), (
            f"{rule['title']} must select on ScriptBlockText"
        )
