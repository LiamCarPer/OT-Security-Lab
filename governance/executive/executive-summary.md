# Executive Summary: OT Security Posture

> **Auto-generated** by `governance/testing/generate_exec_summary.py` from the
> repository's machine-generated evidence (`detection/logs/alerts.json`), the
> risk register, and the IEC 62443 gap analysis. It describes the lab's
> **simulated** water-treatment range, not a production engagement. Do not edit
> by hand; regenerate after the Compliance Gate refreshes evidence.

## 1. Overview
A segmented ICS environment aligned to the Purdue model and IEC 62443 protects
the simulated water treatment process across four zones (Control, Supervisory,
Operations, Enterprise), with all inter-zone traffic transiting a default-deny
gateway chokepoint and protocol-aware detection (Modbus/TCP, DNP3, OPC UA,
S7comm).

The posture is **fundamentally sound but not yet resilient**. Zoning and conduit
enforcement are implemented and test-verified; the material weaknesses are the
absence of implemented historian backups (SR_7.3, simulated) and unencrypted
control protocols (SR_4.1).

## 2. Detection Posture (evidence window: 2026-09-15T11:31:16.241928 → 2026-09-15T11:33:24.525520)
| Detection | Alerts |
| :--- | ---: |
| `CROSS_ZONE_VIOLATION` | 30 |
| `OT_BRUTE_FORCE_SCAN` | 4 |
| `UNAUTHORIZED_MODBUS_WRITE` | 3 |
| `PROCESS_SAFETY_VIOLATION` | 1 |
| **Total** | **38** |

Distinct source addresses observed: 172.22.0.10, 172.24.0.10. Source:
`detection/logs/alerts.json`, aggregated by `automation/metrics.py`.

## 3. Risk Register
Registered risks by level: **1 EXTREME, 8 HIGH, 3 MEDIUM, 0 LOW** (see `governance/risk_register.csv`).

## 4. Key Performance Indicators
- **Compliance:** IEC 62443-3-3 implementation score **72.7%**
  (weighted; see `iec62443/compliance-summary.md`).
- **Zoning:** IEC 62443-3-2 zones/conduits verified by `tests/test_zone_isolation.py`.
- **Detection:** 38 alerts from 2 distinct
  sources; `make compliance` asserts every scenario is detected.
- **Recovery:** RTO/RPO defined per asset in `governance/bia.md`; restore
  exercises outstanding (roadmap RD-10).

## 5. Next 90-Day Priorities
1. Automated historian backups to offline storage (SR_7.3) with a restore drill.
2. PLC-side connection limits against Modbus flooding (RD-02).
3. HMI/PLC authentication hardening: lockout, session timeouts, unique accounts.
4. Formalize change management (MOC) with master logic-hash verification.
5. Encrypted control conduits (Modbus/TCP Security or VPN).
