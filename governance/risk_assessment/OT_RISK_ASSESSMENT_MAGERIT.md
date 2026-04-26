# OT Risk Assessment (MAGERIT Methodology)
**Scope:** Water Treatment Lab Environment (Purdue Model)
**Metodología:** MAGERIT v3.0

## 1. Asset Inventory (Activos)

| Asset ID | Name | Category | Criticality (C/I/A) | Description |
| --- | --- | --- | --- | --- |
| A.01 | PLC_Intake | Hardware/Logic | H / H / H | Siemens PLC controlling water input. |
| A.02 | OT_Gateway | Network/Software | M / H / H | Trust boundary & Security monitoring. |
| A.03 | Alerts_Log | Data | L / H / H | Evidence of unauthorized activity. |
| A.04 | HMI_Dashboard | Software | M / M / H | Operational visibility. |

## 2. Threat Analysis (Amenazas)

| Threat ID | Name | Target | Impact | Likelihood | Risk Level |
| --- | --- | --- | --- | --- | --- |
| T.01 | Unauthorized Write | A.01 | Critical | High | **EXTREME** |
| T.02 | Network Recon | A.01, A.02 | Low | High | **MEDIUM** |
| T.03 | Log Tampering | A.03 | Medium | Medium | **HIGH** |
| T.04 | Physics Violation| A.01 | Critical | Medium | **HIGH** |

## 3. Safeguards (Salvaguardas)

| Safeguard ID | Description | Threat Mitigated | Standard (IEC 62443) |
| --- | --- | --- | --- |
| S.01 | Network Segmentation (Purdue) | T.01, T.02 | 3-3 (FR5) |
| S.02 | Physics-Aware IDS (Shadowing) | T.01, T.04 | 4-2 (Safety-Cyber) |
| S.03 | SIEM Integration (Loki/Grafana) | T.03 | 2-4 (Monitoring) |

## 4. Residual Risk Statement
With the implementation of the **Physics-Aware IDS** and **Purdue Model Zoning**, the residual risk of a successful process violation (T.04) is reduced from "High" to "Low". The remaining risk is primarily associated with host-based vulnerabilities in the HMI, which are mitigated by the network-level conduits.

---
**Prepared By:** IT/OT Security Engineer (Exceltic Candidate)
**Date:** 2026-04-26
