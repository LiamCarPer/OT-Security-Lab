"""Validate MITRE ATT&CK for ICS technique references against the catalog.

The catalog (`threat-model/attack_ics_catalog.json`) is a vendored snapshot of
the ATT&CK for ICS matrix. These tests fail if a document references an ID that
does not exist, or if the detection-coverage table's technique name disagrees
with the catalog (the class of error that mislabelled T0802 as "Alarm
Suppression").
"""
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG = REPO_ROOT / "threat-model" / "attack_ics_catalog.json"
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"
RULE_DIR = REPO_ROOT / "detection" / "rules"

TECHNIQUE_RE = re.compile(r"\bT[01][0-9]{3}(?:\.[0-9]{3})?\b")
COVERAGE_ROW_RE = re.compile(
    r"^\|\s*`?([A-Z0-9_]+)`?\s*\|\s*(T[0-9]{4}(?:\.[0-9]{3})?)\s*\|\s*([^|]+?)\s*\|\s*$"
)


def _catalog():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    return {tech["id"]: tech["name"] for tech in data["techniques"]}


def test_catalog_is_present_and_has_ids():
    catalog = _catalog()
    assert len(catalog) > 50
    assert "T0831" in catalog


def test_all_ids_referenced_in_threat_model_exist():
    catalog = _catalog()
    missing = []
    for path in THREAT_MODEL_DIR.glob("*.md"):
        for technique in TECHNIQUE_RE.findall(path.read_text(encoding="utf-8")):
            if technique not in catalog:
                missing.append(f"{path.name}: {technique}")
    assert not missing, f"unknown ATT&CK for ICS IDs: {missing}"


def test_all_detection_rule_mitre_ids_exist():
    catalog = _catalog()
    missing = []
    for path in RULE_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in re.findall(r'"mitre_id":\s*"(T[^"]+)"', text):
            if match not in catalog:
                missing.append(f"{path.name}: {match}")
    assert not missing, f"unknown ATT&CK for ICS IDs in detection rules: {missing}"


def test_detection_coverage_names_match_catalog():
    catalog = _catalog()
    mapping = (THREAT_MODEL_DIR / "mitre-ics-mapping.md").read_text(encoding="utf-8")
    rows = 0
    for line in mapping.splitlines():
        match = COVERAGE_ROW_RE.match(line)
        if not match:
            continue
        rows += 1
        _, technique, name = match.groups()
        assert technique in catalog, f"{technique} not in catalog"
        assert name.lower() == catalog[technique].lower(), (
            f"{technique} is '{catalog[technique]}', document says '{name}'"
        )
    assert rows >= 10, f"expected a populated detection-coverage table, found {rows} rows"
