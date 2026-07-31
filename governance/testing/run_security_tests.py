#!/usr/bin/env python3
"""Automated security compliance test suite for the OT lab.

Expects the lab to be running (`docker compose up -d` from lab-environment).
Boots attack simulations from the attacker container and asserts that the
persistent IDS rules in the gateway produced the expected alerts.

Usage:
    python3 run_security_tests.py [--reset]
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_LOG = REPO_ROOT / "detection" / "logs" / "alerts.json"

TESTS = [
    {
        "name": "Cross-Zone Violation",
        "cmd": "docker exec ot_attacker python3 /attacker/simulate_attack.py",
        "expected": ["CROSS_ZONE_VIOLATION"],
    },
    {
        "name": "Unauthorized Modbus Write",
        "cmd": "docker exec ot_attacker python3 /attacker/simulate_attack.py",
        "expected": ["UNAUTHORIZED_MODBUS_WRITE"],
    },
    {
        "name": "Modbus Brute-Force Scan",
        "cmd": "docker exec ot_attacker python3 /attacker/simulate_attack.py",
        "expected": ["OT_BRUTE_FORCE_SCAN"],
    },
    {
        "name": "Lateral Movement",
        "cmd": "docker exec ot_attacker python3 /attacker/simulate_lateral_movement.py",
        "expected": ["CROSS_ZONE_VIOLATION"],
    },
    {
        "name": "Physics-Aware Safety Violation",
        "cmd": "docker exec ot_attacker python3 /attacker/simulate_process_violation.py",
        "expected": ["PROCESS_SAFETY_VIOLATION"],
    },
]

def alert_counts():
    counts = {}
    if not ALERT_LOG.exists():
        return counts
    for line in ALERT_LOG.read_text(encoding="utf-8").splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        alert_type = alert.get("alert_type")
        counts[alert_type] = counts.get(alert_type, 0) + 1
    return counts

def run_command(cmd, retries=6, delay=5):
    for attempt in range(1, retries + 1):
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result
        print(f"[WARN] '{cmd}' failed (attempt {attempt}/{retries}): {result.stderr.strip()}")
        time.sleep(delay)
    return result

def wait_for_attacker_ready(retries=36, delay=5):
    """Wait until the attacker container has scapy and the pivot routes."""
    checks = [
        "docker exec ot_attacker python3 -c 'import scapy.all'",
        "docker exec ot_attacker sh -c 'ip route | grep -q 172.21.0.0/24'",
    ]
    for attempt in range(1, retries + 1):
        ready = True
        for check in checks:
            result = subprocess.run(check, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                ready = False
                break
        if ready:
            print("[READY] Attacker container initialized (scapy + pivot routes).")
            return True
        if attempt % 6 == 0:
            print(f"[WAIT] Attacker not ready yet (attempt {attempt}/{retries})...")
        time.sleep(delay)
    return False

def main():
    parser = argparse.ArgumentParser(description="OT Security Lab compliance test suite")
    parser.add_argument("--reset", action="store_true", help="Archive current alerts.json before testing")
    args = parser.parse_args()

    if args.reset and ALERT_LOG.exists():
        backup = ALERT_LOG.with_name("alerts_archive.json")
        ALERT_LOG.replace(backup)
        print(f"[RESET] Archived existing alerts to {backup.name}")

    print("--- OT Security Lab: Automated Compliance Test Suite ---")
    print(f"Alert log: {ALERT_LOG}")

    if not wait_for_attacker_ready():
        print("[FATAL] Attacker container not ready after timeout.")
        return 1

    results = []
    all_passed = True

    for test in TESTS:
        print(f"\n[TEST] {test['name']}")
        baseline = alert_counts()
        result = run_command(test["cmd"])
        if result.returncode != 0:
            print(f"[FAIL] Simulation command error: {result.stderr.strip()}")
            results.append((test["name"], "FAIL"))
            all_passed = False
            continue

        print("[WAIT] Waiting for IDS ingestion...")
        time.sleep(3)
        after = alert_counts()

        missing = []
        for expected_type in test["expected"]:
            new_alerts = after.get(expected_type, 0) - baseline.get(expected_type, 0)
            if new_alerts <= 0:
                missing.append(expected_type)

        if not missing:
            print(f"[PASS] Detected: {', '.join(test['expected'])}")
            results.append((test["name"], "PASS"))
        else:
            print(f"[FAIL] Expected alerts NOT produced: {', '.join(missing)}")
            results.append((test["name"], "FAIL"))
            all_passed = False

    print("\n" + "=" * 60)
    print("FINAL SECURITY COMPLIANCE REPORT")
    print("=" * 60)
    for name, status in results:
        print(f"{name:.<52} {status}")
    print("=" * 60)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
