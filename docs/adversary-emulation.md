# Adversary Emulation & BAS Tooling

This page explains how the lab's emulation content maps to the tools named in
detection-engineering job descriptions.

## What is implemented

| Tool / approach | Status in this repo | Evidence |
| :--- | :--- | :--- |
| Custom Python/Scapy BAS harness | Implemented and run in CI | `governance/testing/run_security_tests.py`, 16 compliance checks |
| PowerShell 7 adversary scenario | Implemented and run in CI | `powershell/OTSec`, `tests/powershell`, `UNAUTHORIZED_MODBUS_WRITE` |
| MITRE/Apache Caldera | Optional profile; built on demand | `lab-environment/caldera`, `OT External Adversary`, `evidence/caldera_operation.json` |
| AttackIQ | Not deployed (commercial) | AttackIQ Academy training is the honest CV path |
| Atomic Red Team | Not deployed | Candidate extension for a future Windows EWS endpoint |

## Why Caldera rather than AttackIQ

AttackIQ is a commercial platform; a personal lab cannot deploy it without a
licence. Caldera is open source, runs as a container, and exposes the same
workflow a commercial BAS uses:

1. Define an adversary profile (ATT&CK techniques).
2. Map abilities to executable procedures.
3. Run an operation against a scoped agent group.
4. Collect link results and correlate them with SIEM alerts.
5. Report expected vs observed coverage.

The lab keeps the deterministic Python harness as the regression gate and uses
Caldera as the platform-level orchestration demonstration. This separation is
deliberate: a UI product should not make the compliance suite flaky.

## AttackIQ Academy

AttackIQ Academy (<https://www.academy.attackiq.com/>) offers free, hands-on courses and Credly badges, including:

- *Foundations of Breach & Attack Simulation*
- *Validating Security Controls with AttackIQ Enterprise*
- *Assessment Design for Security Controls*

These are training, not production product experience. If the role asks for
AttackIQ specifically, list the Academy badges and explain that the Caldera
operation follows the same assessment-design and control-validation workflow.

## Scenario-to-detection map

| Scenario | Technique | Expected detection |
| :--- | :--- | :--- |
| OT service discovery | T0846 | `CROSS_ZONE_VIOLATION`, `OT_PORT_SCAN` |
| Unauthorized Modbus write | T0831 | `UNAUTHORIZED_MODBUS_WRITE`, `OT_BRUTE_FORCE_SCAN` |
| OT lateral movement | T0886 | `CROSS_ZONE_VIOLATION` |
| Process-safety stimulus | T0836 | `PROCESS_SAFETY_VIOLATION` |
| PowerShell Modbus write | T0831 | `UNAUTHORIZED_MODBUS_WRITE` |

## Scope and safety

- The lab is isolated; the PowerShell scenario refuses targets outside
  `172.21.0.0/24`.
- The PowerShell write uses an unused register and restores it.
- Caldera is an optional compose profile; it is not started by `make up`.
- The Caldera server is in the Enterprise zone and the agent runs on the
  existing attacker host, preserving the single-chokepoint invariant.
