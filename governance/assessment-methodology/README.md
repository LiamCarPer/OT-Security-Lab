# OT Security Assessment Methodology

**Document Owner:** IT/OT Security Engineer
**Date:** 2026-08-01
**Alignment:** IEC 62443-2-1 (security management), IEC 62443-3-2 (risk assessment), NIST SP 800-82 Rev. 3, PTES (where applicable)
**Evidence Base:** OT-Security-Lab (simulated water treatment facility, IEC 62443 SL-2 target)

## 1. Purpose

This document defines the engagement methodology used to assess the security posture of industrial control systems, from initial scoping through remediation support. It is the formal, repeatable process behind the findings in `governance/risk_register.csv` and `iec62443/gap-analysis.csv`, and it is demonstrated against the lab environment (PLC_Intake 172.21.0.10, PLC_Treatment 172.21.0.11, PLC_Distribution 172.21.0.12, HMI 172.22.0.10, Historian 172.23.0.10, EWS 172.23.0.4, Gateway 172.24.0.2).

**Safety-first principle:** all technical testing is passive or simulated against a non-production environment; in production engagements, no test is executed that can alter a live process without documented plant-owner authorization and a validated rollback plan.

## 2. Engagement Phases

| Phase | Activities | Key Deliverable |
| :--- | :--- | :--- |
| **1. Scoping** | Confirm boundaries, zones in scope, testing windows, safety constraints, regulatory context, stakeholder map | Scoping questionnaire (`scoping-questionnaire.md`) completed and signed-off scope statement |
| **2. Discovery** | Asset inventory validation, network architecture review, documentation collection, control maturity review | Discovery checklist (`discovery-checklist.md`) with evidence index |
| **3. Technical Testing** | Passive traffic analysis, configuration review, vulnerability validation, detection rule testing (against simulated attacks only) | Test execution log mapped to `governance/testing/CYBERSECURITY_TEST_PLAN.md` test cases |
| **4. Analysis** | Risk rating per asset/scenario, IEC 62443 requirement mapping (SL-T vs SL-A), root-cause analysis | Risk register (`governance/risk_register.csv`) and `iec62443/sl-mapping.md` comparison |
| **5. Reporting** | Findings report with severity rating, evidence, business impact and remediation plan | Findings report per `findings-template.md`; executive summary per `governance/executive/executive-summary.md` |
| **6. Remediation Support** | Prioritized roadmap, control validation (re-test), advisory on residual risk | Remediation roadmap (`governance/remediation_roadmap.md`); re-test records |

## 3. Deliverables per Phase

1. **Scoping:** signed scope document, rules of engagement (RoE), list of excluded/contained systems, point of contact per zone.
2. **Discovery:** validated asset inventory (CSV per `asset-inventory/assets.csv` schema), network topology diagram, documentation gap list.
3. **Technical Testing:** evidence pack — PCAP excerpts, alert logs (`detection/logs/alerts.json`), configuration exports, test case results (PASS/FAIL per `CYBERSECURITY_TEST_PLAN.md`).
4. **Analysis:** threat model update, risk scores (EXTREME/HIGH/MEDIUM per MAGERIT), gap analysis (`iec62443/gap-analysis.csv`).
5. **Reporting:** findings report (severity, evidence, impact, recommendation), executive summary for the board, and slide pack where required.
6. **Remediation Support:** prioritized roadmap, acceptance criteria per finding, KPI baseline (MTTD proxy, alert volumes per rule via `automation/metrics.py`).

## 4. References to Lab Evidence

| Evidence Artifact | Used For |
| :--- | :--- |
| `detection/logs/alerts.json` | Detection effectiveness; alert types UNAUTHORIZED_MODBUS_WRITE (T0831), PROCESS_SAFETY_VIOLATION (T0836), CROSS_ZONE_VIOLATION (T0886), OT_BRUTE_FORCE_SCAN (T0846), DNP3_WRITE_UNAUTHORIZED (T0831), PLC_LOGIC_TAMPERED (T0853) |
| `detection/rules/` (modbus_anomaly.py, process_safety_violation.py, cross_zone_traffic.py, ot_brute_force.py, dnp3_anomaly.py) | Detection coverage validation |
| `lab-environment/docker-compose.yml` | Architecture and zone/IP verification |
| `governance/testing/CYBERSECURITY_TEST_PLAN.md` | Test case execution (TC-01, TC-02, TC-03) |
| `governance/incident_response/IR_PLAYBOOK_PLC_TAMPERING.md` | Incident readiness validation |
| `automation/metrics.py` | KPI computation (per-rule counts, unique sources, mean-time-to-detect proxy) |
| `threat-model/THREAT_MODEL.md`, `threat-model/mitre-ics-mapping.md` | Threat scenario substantiation |

## 5. Assessment Team Roles

- **Engagement Lead:** owns the RoE, schedule, and report sign-off.
- **OT Test Engineer:** executes technical testing; must be accompanied by plant operations during any active test.
- **Plant Operations Liaison:** grants process access, validates safety constraints, approves rollback.
- **Security Architect:** validates findings against IEC 62443 SL targets and the zone/conduit model.
- **Report Author:** produces findings report and executive summary.

---

**Approved By:** OT Security Director
**Revision:** 1.0
