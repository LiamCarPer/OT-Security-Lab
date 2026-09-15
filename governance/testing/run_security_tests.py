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
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_LOG = REPO_ROOT / "detection" / "logs" / "alerts.json"
SCADA_BASE = os.getenv("OT_SCADA_URL", "http://localhost:8080/Scada-LTS")
INTAKE_LEVEL_XID = os.getenv("OT_SCADA_LEVEL_XID", "DP_DS_PLC1_HR5")
LEVEL_THRESHOLD = int(os.getenv("OT_LEVEL_THRESHOLD", "90"))

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
        "fallback_cmd": "docker exec ot_attacker python3 /attacker/simulate_process_violation_spoof.py",
        "precondition": "real_process",
        "expected": ["PROCESS_SAFETY_VIOLATION"],
    },
]


def scada_get_value(xid, timeout=5):
    """Authenticate to Scada-LTS and read a live point value.

    The session id is captured from the auth response and passed explicitly as a
    Cookie header (curl's cookie jar is not reliably replayed in every image).
    """
    auth = subprocess.run(
        ["curl", "-s", "-D", "-", "-o", "/dev/null",
         f"{SCADA_BASE}/api/auth/admin/admin"],
        capture_output=True,
        text=True,
    )
    session = re.search(r"JSESSIONID=([^;]+)", auth.stdout)
    if not session:
        return None
    result = subprocess.run(
        ["curl", "-s", "--max-time", str(timeout),
         "-H", f"Cookie: JSESSIONID={session.group(1)}",
         f"{SCADA_BASE}/api/point_value/getValue/{xid}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    value = payload.get("value") if isinstance(payload, dict) else None
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def real_process_ready(timeout=90):
    """Wait until the live tank level (via Scada-LTS) exceeds the safety envelope.

    This is only possible when the OpenPLC program bundles are committed and the
    HMI is genuinely polling. If it never happens, the test falls back to the
    simulated stimulus so the detection pipeline is still exercised.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        level = scada_get_value(INTAKE_LEVEL_XID)
        if level is not None and level > LEVEL_THRESHOLD:
            print(f"[READY] Live tank level {level:.0f}% > {LEVEL_THRESHOLD}% (Scada-LTS)")
            return True
        time.sleep(2)
    return False


PRECONDITIONS = {"real_process": real_process_ready}

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

def dump_diagnostics():
    """Print container and IDS state to help debug failed detections."""
    print("\n===== DIAGNOSTICS =====")
    for cmd in [
        "docker ps -a",
        "docker exec ot_gateway sh -c 'pgrep -af python3 || echo NO_IDS_RUNNING'",
        "docker exec ot_gateway sh -c 'for f in /detection/logs/*.out; do echo --- $f; tail -10 $f; done'",
        "docker exec ot_attacker sh -c 'ip route'",
    ]:
        print(f"$ {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print((result.stdout or result.stderr).strip()[:2000] or "(no output)")
    if ALERT_LOG.exists():
        print(f"$ tail alerts.json ({ALERT_LOG.stat().st_size} bytes)")
        print(ALERT_LOG.read_text(encoding="utf-8")[-1500:])
    else:
        print(f"$ alerts.json MISSING at {ALERT_LOG}")
    print("===== END DIAGNOSTICS =====\n")

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
        cmd = test["cmd"]
        precondition = PRECONDITIONS.get(test.get("precondition"))
        if precondition and not precondition():
            fallback = test.get("fallback_cmd")
            if not fallback:
                print("[FAIL] Real-process precondition not met and no fallback is defined.")
                results.append((test["name"], "FAIL"))
                all_passed = False
                continue
            print("[FALLBACK] Real process unavailable; using simulated stimulus.")
            cmd = fallback
        baseline = alert_counts()
        result = run_command(cmd)
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
            dump_diagnostics()

    print("\n" + "=" * 60)
    print("FINAL SECURITY COMPLIANCE REPORT")
    print("=" * 60)
    for name, status in results:
        print(f"{name:.<52} {status}")
    print("=" * 60)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
