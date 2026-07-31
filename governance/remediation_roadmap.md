# OT Security Remediation Roadmap

**Document Owner:** IT/OT Security Engineer
**Date:** 2026-08-01
**Inputs:** `governance/risk_register.csv`, `iec62443/gap-analysis.csv`, `iec62443/sl-mapping.md`, `governance/bia.md`
**Target:** IEC 62443 SL-2 achieved per zone, with Control (L1) progressing toward SL-3

## 1. Scoring and Prioritization Scheme

Priorities are derived from the risk register (risk level) and the gap analysis (requirement status):

- **P1 (Immediate, 0-3 months):** EXTREME or HIGH risks, or gaps rated Partial that weaken SL-2 baseline requirements. Safety-critical and availability-critical assets take precedence per the BIA.
- **P2 (Short term, 3-6 months):** HIGH risks with existing compensating controls, or Partial gaps that mature the monitoring and hardening posture.
- **P3 (Mid term, 6-12 months):** MEDIUM risks, architecture improvements, and SL-3 progression items.

## 2. Prioritized Findings Table

| ID | Finding | Source | Priority | Effort | Target Phase | Owner |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| RD-01 | Implement automated, periodic PLC logic backups to offline storage (SR_7.3 currently Simulated) | gap-analysis.csv; RSK-008 | **P1** | Medium (3-5 weeks) | 0-3 months | IT/Engineering |
| RD-02 | Implement PLC-side Modbus connection limits and request throttling (SR_7.1 Partial) | gap-analysis.csv; RSK-011 | **P1** | Medium (3-5 weeks) | 0-3 months | Security |
| RD-03 | Harden HMI/PLC identification and authentication; enforce account lockout and session controls (SR_1.1 Partial, SR_2.6 Partial) | gap-analysis.csv; RSK-001/004 | **P1** | Medium (3-5 weeks) | 0-3 months | Security/Plant |
| RD-04 | Add DNP3 anomaly rules and DNP3 conduit allow-lists to detection coverage (RSK-005) | risk_register.csv; detection/rules/dnp3_anomaly.py | **P1** | Low-Medium (2-4 weeks) | 0-3 months | Detection Engineering |
| RD-05 | Formalize change management (MOC) for PLC logic with hash verification on every change (SR_3.3) | risk_register.csv RSK-007 | **P1** | Low (1-2 weeks) | 0-3 months | Engineering |
| RD-06 | Encrypt HMI-to-PLC and EWS-to-PLC conduits: Modbus/TCP Security or VPN tunneling (SR_4.1 Partial) | gap-analysis.csv; RSK-012 | **P2** | High (6-10 weeks) | 3-6 months | Security/Network |
| RD-07 | Integrate alert pipeline with external SIEM correlation and retention beyond Loki (SR_6.1) | gap-analysis.csv; RSK-006 | **P2** | Medium (3-5 weeks) | 3-6 months | Security |
| RD-08 | Deploy EDR/agent-based integrity monitoring on EWS (172.23.0.4) and HMI (SR_3.1) | compliance-summary.md | **P2** | Medium (4-6 weeks) | 3-6 months | IT/Engineering |
| RD-09 | Session inactivity timeouts on jump host / gateway (SR_2.6) | gap-analysis.csv | **P2** | Low (1 week) | 3-6 months | Security |
| RD-10 | Run regular restore exercises: golden PLC logic and historian dataset (SR_7.3 verification) | bia.md Section 6 | **P2** | Low (quarterly, 1-2 days each) | 3-6 months | IT/Operations |
| RD-11 | Centralized identity management (LDAP/AD) for all SCADA and workstation logins | compliance-summary.md | **P3** | High (6-10 weeks) | 6-12 months | IT |
| RD-12 | Centralized configuration management with cryptographic signing for logic updates (SL-3 path) | sl-mapping.md Section 4 | **P3** | High (8-12 weeks) | 6-12 months | Engineering |
| RD-13 | Hardware data diode between L3 and L4; SIS zone separation for safety functions | README known limitations; architecture/to-be-architecture.md | **P3** | High (project) | 6-12 months | Architecture |
| RD-14 | Adversary emulation playbooks (Industroyer, TRITON-style) added to test plan | README future roadmap | **P3** | Medium (4-6 weeks) | 6-12 months | Detection Engineering |

## 3. Narrative per Priority Tier

### P1 - Immediate (0-3 months)

The P1 items close the gaps that a low-resource attacker could exploit today. The most urgent is **RD-01**: the historian (InfluxDB 1.8.10, 172.23.0.10) currently has no implemented backup, so a ransomware event would cause permanent loss of audit and compliance data — a failure that no detection control can undo. Equally urgent are **RD-02** and **RD-03**, which convert the gateway-only protection into defense-in-depth: PLC-side connection limits prevent a Modbus flood from reaching the control stack, and authentication/session controls on the HMI close the credential-based vector behind the firewall. **RD-05** is the procedural linchpin — no logic change enters Level 1 without hash verification and an approved change record, which is what makes the PLC_LOGIC_TAMPERED detection actionable rather than purely reactive. Completion of P1 should bring every SL-2 baseline requirement in the gap analysis to "Implemented" or "Partially Implemented with compensating control".

### P2 - Short term (3-6 months)

P2 matures the environment from "detects well" to "contains well". **RD-06** (encrypted conduits) directly addresses the highest residual-risk item in the register (RSK-012, sniffing) and is a prerequisite for the SL-3 path; **RD-07** extends evidence retention so log tampering (RSK-006) no longer erases detection history; **RD-08** brings host-level visibility to the EWS and HMI, compensating for the deliberate absence of antivirus on the PLCs (SR_3.1). **RD-10** institutionalizes the BIA recovery strategy — quarterly restore exercises prove the RTO/RPO targets of Section 4 of the BIA rather than assuming them.

### P3 - Mid term (6-12 months)

P3 is the architecture and assurance tier. **RD-11** and **RD-12** are the formal steps from SL-2 to SL-3 (per `sl-mapping.md`): centralized identity plus cryptographically signed logic distribution. **RD-13** addresses the README's acknowledged limitation — replacing logically enforced unidirectional flow with a hardware data diode and separating the safety-integrity function into its own zone, as designed in `architecture/to-be-architecture.md`. **RD-14** validates the whole stack against the highest-severity ICS adversaries so the detection rules are exercised against realistic TTPs rather than only the lab's built-in simulations.

## 4. Success KPIs

| KPI | Target | Measurement |
| :--- | :--- | :--- |
| Gap closure rate (IEC 62443-3-3) | 100% SL-2 baseline requirements rated Implemented | `iec62443/gap-analysis.csv` status column, reviewed quarterly |
| Backup restore success | 100% of quarterly restore exercises pass within RTO | Restore test record per `bia.md` Section 6 |
| Detection coverage | 100% of risk register scenarios have a detection or compensating control | Mapping audit: risk_register vs detection/rules |
| Alert quality | False-positive proxy (single-event bursts, per `automation/metrics.py`) below 10% of total alerts | `detection/logs/metrics.json` |
| MTTD proxy | Mean time to detect (per-rule, `metrics.py`) trending downward quarter over quarter | `metrics.json` / Grafana dashboard |
| Incident readiness | At least 1 tabletop exercise and 1 IR drill per year | `governance/tabletop/tabletop-exercise-kit.md` after-action reports |
| Remediation velocity | 80% of P1 findings closed within 3 months of acceptance | This roadmap, status column updated monthly |

---

**Approved By:** OT Security Director
**Next Review:** 2026-10-01 (monthly status update of this document)
