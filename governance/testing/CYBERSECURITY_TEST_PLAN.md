# Cybersecurity Test Plan: Industrial Lab
**System:** OT Security Lab v1.5
**Reference:** ISA/IEC 62443-4-1 (V&V), MAGERIT Safeguard Verification

## 1. Test Objectives
To verify the effectiveness of the safeguards identified in the **MAGERIT Risk Assessment**, specifically the detection of unauthorized Modbus commands and physical safety violations.

## 2. Test Environment
- **Zone:** Level 3 (Ops Network)
- **Tooling:** Docker-based Attacker (ot_attacker)
- **Monitors:** Grafana SIEM (Level 4), `alerts.json` (Local)

## 3. Test Cases (Casos de Prueba)

### [TC-01] Protocol Anomaly Detection
- **Description:** Verify that Modbus Function Codes not in the allow-list are flagged.
- **Prerequisite:** Lab environment is healthy.
- **Execution:** `python3 /attacker/simulate_attack.py` (Step 1-2).
- **Expected Result:** Alert `UNAUTHORIZED_MODBUS_WRITE` in SIEM.
- **Status:** PASS

### [TC-02] Brute Force / Exception Flooding
- **Description:** Verify that high-frequency Modbus errors trigger reconnaissance alerts.
- **Execution:** `python3 /attacker/simulate_attack.py` (Step 3).
- **Expected Result:** Alert `OT_BRUTE_FORCE_SCAN` in SIEM.
- **Status:** PASS

### [TC-03] Physics-Aware Safety Interlock
- **Description:** Verify that safe commands (OPEN valve) are flagged when the process context is UNSAFE (Tank Full).
- **Execution:** `python3 /attacker/simulate_process_violation.py`.
- **Expected Result:** Alert `PROCESS_SAFETY_VIOLATION` in SIEM.
- **Status:** PASS

## 4. Test Summary
All three critical safeguards have been verified through automated simulation. The system correctly correlates network telemetry with physical state to identify high-impact process threats.
