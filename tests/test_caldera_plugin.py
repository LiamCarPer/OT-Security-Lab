"""Validate the optional Caldera plugin without booting Caldera.

The live operation is exercised by the manual Caldera workflow; these checks
keep the plugin data loadable and aligned with the lab's ATT&CK catalog.
"""
import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN = REPO_ROOT / "lab-environment" / "caldera" / "plugins" / "ot-lab"
CATALOG = REPO_ROOT / "threat-model" / "attack_ics_catalog.json"
REQUIRED_ABILITY = {"id", "name", "description", "tactic", "technique", "platforms"}


def _abilities():
    return [
        (path, yaml.safe_load(path.read_text(encoding="utf-8")))
        for path in sorted((PLUGIN / "data" / "abilities").rglob("*.yml"))
    ]


def _catalog():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    return {tech["id"] for tech in data["techniques"]}


def test_hook_exposes_the_plugin_contract():
    hook = (PLUGIN / "hook.py").read_text(encoding="utf-8")
    for token in ("name =", "description =", "address =", "async def enable"):
        assert token in hook


def test_abilities_are_well_formed_and_reference_the_lab_scripts():
    catalog = _catalog()
    ids = set()
    for path, abilities in _abilities():
        assert isinstance(abilities, list) and abilities, f"{path.name} is empty"
        for ability in abilities:
            missing = REQUIRED_ABILITY - set(ability)
            assert not missing, f"{path.name} is missing {sorted(missing)}"
            assert ability["id"] not in ids, f"duplicate ability id {ability['id']}"
            ids.add(ability["id"])
            technique = ability["technique"]["attack_id"]
            assert technique in catalog, f"{path.name} uses unknown technique {technique}"
            command = ability["platforms"]["linux"]["sh"]["command"]
            for script in ("/attacker/",):
                if script in command:
                    name = command.split(script, 1)[1].split()[0]
                    assert (REPO_ROOT / "lab-environment" / "attacker" / name).exists(), (
                        f"{path.name} references missing script {name}"
                    )
    assert len(ids) >= 4


def test_adversary_orders_every_ability_once():
    abilities = {ability["id"] for _, items in _abilities() for ability in items}
    profile = yaml.safe_load(
        (PLUGIN / "data" / "adversaries" / "ot-external-adversary.yml").read_text(encoding="utf-8")
    )
    ordered = profile["atomic_ordering"]
    assert ordered, "adversary has no atomic_ordering"
    assert len(ordered) == len(set(ordered)), "adversary repeats an ability"
    assert set(ordered) == abilities
