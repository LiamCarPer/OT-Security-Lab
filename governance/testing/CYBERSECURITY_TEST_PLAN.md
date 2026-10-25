# Cybersecurity Test Plan: Industrial Lab
**System:** OT Security Lab v1.6
**Reference:** ISA/IEC 62443-4-1 (V&V), MAGERIT Safeguard Verification

## 1. Test Objectives
To verify the effectiveness of the safeguards identified in the **MAGERIT Risk Assessment**, specifically the detection of unauthorized Modbus commands and physical safety violations.

## 2. Test Environment
- **Zone:** Level 3 (Ops Network)
- **Tooling:** Docker-based attacker (`ot_attacker`), PowerShell 7 operator workstation (`ot_powershell`), optional MITRE Caldera profile
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

### [TC-04] PowerShell Adversary Emulation
- **Description:** Verify that a PowerShell 7 Modbus FC6 write from the L2 operator workstation is detected.
- **Execution:** `pwsh -File /opt/otsec/Invoke-OTAdversaryEmulation.ps1 -Scenario UnauthorizedWrite -Target 172.21.0.10 -AllowLab`.
- **Expected Result:** Alert `UNAUTHORIZED_MODBUS_WRITE` with source `172.22.0.30`.
- **Status:** PASS

### [TC-05] OT Service-Port Scan
- **Description:** Verify that a SYN scan across Modbus, S7comm, DNP3 and OPC UA ports is detected.
- **Execution:** `nmap -Pn -n -p 502,102,20000,4840 172.21.0.10-12`.
- **Expected Result:** Alert `OT_PORT_SCAN`.
- **Status:** PASS

## 4. Test Summary
The authoritative scenario list is `governance/testing/run_security_tests.py`; it
covers the protocol detections, the benign baseline, the PowerShell scenario,
the OT port scan, the detection-service watchdog, the historian path and the
remote-engineering hop. The three original safety-critical safeguards remain
verified, and the two new scenarios extend coverage to PowerShell and
reconnaissance behaviour.
