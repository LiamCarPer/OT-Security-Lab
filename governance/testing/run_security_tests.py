import json
import time
import subprocess
import os

def run_command(cmd):
    print(f"[EXEC] {cmd}")
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def check_logs(expected_type):
    log_path = "../../detection/logs/alerts.json"
    if not os.path.exists(log_path):
        return False
    
    with open(log_path, 'r') as f:
        for line in f:
            try:
                alert = json.loads(line)
                if alert.get("alert_type") == expected_type:
                    return True
            except:
                continue
    return False

def main():
    print("--- OT Security Lab: Automated Compliance Test Suite ---")
    
    tests = [
        {"name": "Modbus Recon/Brute Force", "cmd": "docker exec ot_attacker python3 /attacker/simulate_attack.py", "expected": "OT_BRUTE_FORCE_SCAN"},
        {"name": "Physics-Aware Safety Violation", "cmd": "docker exec ot_attacker python3 /attacker/simulate_process_violation.py", "expected": "PROCESS_SAFETY_VIOLATION"}
    ]

    results = []

    for test in tests:
        print(f"\n[TEST] {test['name']}")
        run_command(test['cmd'])
        print("[WAIT] Waiting for log ingestion...")
        time.sleep(3)
        
        if check_logs(test['expected']):
            print(f"[PASS] Success: {test['expected']} detected.")
            results.append((test['name'], "PASS"))
        else:
            print(f"[FAIL] Error: {test['expected']} NOT found in logs.")
            results.append((test['name'], "FAIL"))

    print("\n" + "="*50)
    print("FINAL SECURITY COMPLIANCE REPORT")
    print("="*50)
    for name, status in results:
        print(f"{name:.<40} {status}")
    print("="*50)

if __name__ == "__main__":
    main()
