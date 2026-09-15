# Compliance Summary: IEC 62443 Posture

## 1. Executive Summary
The `ot-security-lab` environment is designed with a "Compliance-by-Design"
approach using **IEC 62443-3-2** (Zones and Conduits) and **IEC 62443-3-3**
(System Security Requirements) as the foundational frameworks. This document
reports the posture **measured from the repository**, not asserted: the 3-3
figure is computed from `iec62443/gap-analysis.csv` by
`governance/testing/compliance_score.py`, and the zoning properties are asserted
by `tests/test_zone_isolation.py`.

## 2. Key Compliance Achievements
- **Zoning:** Logical isolation of the Control, Supervisory, Operations and
  Enterprise zones; the Enterprise zone is the only non-internal network.
- **Conduit enforcement:** default-deny gateway with explicit, source-restricted
  conduits; the gateway is the only multi-homed service, and every OT host
  routes inter-zone traffic through it (no bypass) — verified by
  `tests/test_zone_isolation.py`.
- **Monitoring:** passive, protocol-aware IDS on the gateway (Modbus/TCP, DNP3,
  OPC UA, S7comm) with centralized JSON alerting to Loki/Grafana.

## 3. Posture Overview
| Framework | Focus Area | Status |
| :--- | :--- | :--- |
| **IEC 62443-3-2** | Zoning & Segmentation | **Implemented** — verified by `tests/test_zone_isolation.py` |
| **IEC 62443-3-3** | System Requirements | **72.7% weighted** (6 Implemented, 4 Partial, 1 Simulated, 1 N/A of 12) |
| **ISA-95** | Purdue Model Alignment | **Aligned** — L1 Control, L2 Supervisory, L3 Operations, L4/5 Enterprise, L0 field simulated |

**Scoring method:** `Implemented = 1.0`, `Partial = 0.5`, `Simulated = 0.0`,
`N/A` excluded. Score = weighted sum / scored requirements. Reproduce with
`python3 governance/testing/compliance_score.py`.

## 4. Remediation Roadmap
1. **Host-Based Integrity:** file integrity monitoring on the Engineering
   Workstation (SR_3.1).
2. **Encrypted Conduits:** transition from raw Modbus/TCP to Modbus/TCP Security
   or VPN tunnels (SR_4.1).
3. **Identity Management:** centralized authentication (LDAP/AD) and MFA for all
   SCADA/workstation logins (SR_1.1).
4. **Historian Backup:** automated offline backups with restore drills (SR_7.3).
