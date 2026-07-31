# Executive Summary: OT Security Posture Review

**To:** Board of Directors
**From:** OT Security Director
**Date:** 2026-08-01
**Classification:** Internal
**Reference:** OT-Security-Lab assessment (2026), `governance/risk_register.csv`, `iec62443/compliance-summary.md`, `governance/bia.md`

## 1. Executive Overview

The facility operates a segmented industrial control architecture aligned to the Purdue model and IEC 62443, protecting the water treatment process across four zones: Control (172.21.0.0/24 - PLC_Intake 172.21.0.10, PLC_Treatment 172.21.0.11, PLC_Distribution 172.21.0.12), Supervisory (172.22.0.0/24 - HMI 172.22.0.10), Operations (172.23.0.0/24 - historian 172.23.0.10, EWS 172.23.0.4), and Enterprise (172.24.0.0/24 - SIEM stack). All inter-zone traffic transits a gateway chokepoint (172.24.0.2) enforcing explicit conduit allow-lists, with protocol-aware detection for Modbus/TCP, DNP3, and physics-aware safety violations.

The posture is **fundamentally sound but not yet resilient**. Zone isolation (SR_5.1, SR_5.2) and audit logging (SR_6.1) are fully implemented, and the detection layer successfully identified simulated intrusions across the engagement window: 32 security alerts from 3 distinct sources, including a cross-zone intrusion campaign from the attacker host (172.24.0.10) that was detected and blocked at the control zone boundary. The two material weaknesses are the **absence of implemented historian backups** (IEC 62443 SR_7.3, currently simulated) and **unencrypted control protocols** (SR_4.1) — both are addressable within the next six months and are priority items in the remediation roadmap.

## 2. Detection Posture (Evidence from 2026-04-22 to 2026-05-01)

| Detection Rule | MITRE Reference | Alert Count | Unique Sources |
| :--- | :--- | :--- | :--- |
| CROSS_ZONE_VIOLATION | T0886 (Lateral Movement) | 24 | 1 (172.24.0.10) |
| UNAUTHORIZED_MODBUS_WRITE | T0831 (Manipulation of Control) | 4 | 2 (172.26.0.2, 172.24.0.10) |
| OT_BRUTE_FORCE_SCAN | T0846 (Reconnaissance) | 3 | 2 (172.26.0.2, 172.24.0.10) |
| PROCESS_SAFETY_VIOLATION | T0836 (Safety Interlock) | 1 | 1 (172.22.0.10) |
| **Total (excluding test event)** | | **32** | **3** |

Source: `detection/logs/alerts.json`, computed by `automation/metrics.py`.

The intrusion campaign of 2026-05-01 demonstrates the architecture working as designed: the attacker (172.24.0.10) was detected 24 times attempting direct communication with the control zone, every unauthorized Modbus write was flagged, and the safety interlock blocked a valve-open command issued at 95% tank level. Mean-time-to-detect (MTTD) per rule is computable and tracked as the primary detection KPI.

## 3. Top 5 Risks and Mitigations

| Rank | Risk | Level | Key Mitigation (Implemented or Planned) |
| :--- | :--- | :--- | :--- |
| 1 | Unauthorized Modbus write to control logic (T0831) | EXTREME | Gateway allow-lists (Modbus restricted to HMI 172.21.0.20), UNAUTHORIZED_MODBUS_WRITE detection, IR playbook | 
| 2 | Process safety violation (T0836) | HIGH | Physics-aware IDS shadowing tank levels; safety interlock at overflow capacity |
| 3 | Ransomware on historian data | HIGH | Zone isolation in place; **automated offline backups required (P1)** |
| 4 | Denial of service on PLC network stack | HIGH | Gateway rate limiting; **PLC-side connection limits required (P1)** |
| 5 | Passive sniffing of unencrypted Modbus/TCP (SR_4.1) | HIGH | Zone isolation reduces exposure; **encrypted conduits planned (P2)** |

## 4. Key Performance Indicators

- **Compliance:** IEC 62443-3-2 zoning 100% implemented; IEC 62443-3-3 system requirements 75% implemented (12 requirements tracked in `iec62443/gap-analysis.csv`).
- **Detection:** 32 alerts logged, 3 unique sources, 100% of simulated test cases (TC-01/02/03) passing per `CYBERSECURITY_TEST_PLAN.md`.
- **MTTD proxy:** per-rule mean detection time tracked by `metrics.py`; trend reviewed monthly.
- **Recovery:** RTO/RPO defined per asset in `governance/bia.md`; quarterly restore exercises to be established (roadmap RD-10).
- **Risk:** 1 EXTREME, 6 HIGH, 3 MEDIUM, 2 LOW risks registered (`governance/risk_register.csv`).

## 5. Next 90-Day Priorities

1. **Implement automated historian backups to offline storage** (SR_7.3) and prove restore within RTO — closes the ransomware data-loss gap (RD-01).
2. **Add PLC-side connection limits** to defend the control stack against Modbus flooding (RD-02).
3. **Harden authentication** on HMI/PLCs: lockout enforcement, session timeouts, unique accounts (RD-03).
4. **Formalize change management (MOC)** with master logic hash verification for every PLC change (RD-05).
5. **Expand DNP3 detection coverage** and validate with the compliance gate (RD-04).

Budget impact is contained: P1 items are configuration and process changes to the existing stack (OpenPLC, Scada-LTS, InfluxDB, gateway, SIEM) with no new major procurements; the only capital items are in the 6-12 month horizon (encrypted conduits, and optionally a hardware data diode).

---

**Prepared By:** OT Security Director
**Next Reporting Date:** 2026-10-01
