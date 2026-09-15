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

## 2. Detection Posture (evidence window: 2026-09-15T20:52:06.735661 → 2026-09-15T20:54:33.876644)
| Detection | Alerts |
| :--- | ---: |
| `CROSS_ZONE_VIOLATION` | 50 |
| `UNAUTHORIZED_MODBUS_WRITE` | 23 |
| `PROCESS_SAFETY_VIOLATION` | 9 |
| `DNP3_UNAUTHORIZED_CONTROL` | 6 |
| `S7COMM_PROGRAM_DOWNLOAD` | 6 |
| `S7COMM_PROGRAM_UPLOAD` | 6 |
| `OT_BRUTE_FORCE_SCAN` | 4 |
| `S7COMM_CHANGE_OPERATING_MODE` | 4 |
| `HMI_LOGIN_FAILURE` | 3 |
| `DNP3_RESTART_COMMAND` | 2 |
| `DNP3_UNSOLICITED_DISABLED` | 2 |
| `OPCUA_BROWSE_REQUEST` | 2 |
| `OPCUA_WRITE_REQUEST` | 2 |
| `OPCUA_METHOD_CALL` | 2 |
| **Total** | **121** |

Distinct source addresses observed: 172.23.0.20, 172.24.0.10, 172.24.0.30. Source:
`detection/logs/alerts.json`, aggregated by `automation/metrics.py`.

## 3. Risk Register
Registered risks by level: **1 EXTREME, 8 HIGH, 3 MEDIUM, 0 LOW** (see `governance/risk_register.csv`).

## 4. Key Performance Indicators
- **Compliance:** IEC 62443-3-3 implementation score **72.7%**
  (weighted; see `iec62443/compliance-summary.md`).
- **Zoning:** IEC 62443-3-2 zones/conduits verified by `tests/test_zone_isolation.py`.
- **Detection:** 121 alerts from 3 distinct
  sources; `make compliance` asserts every scenario is detected.
- **Recovery:** RTO/RPO defined per asset in `governance/bia.md`; restore
  exercises outstanding (roadmap RD-10).

## 5. Next 90-Day Priorities
1. Automated historian backups to offline storage (SR_7.3) with a restore drill.
2. PLC-side connection limits against Modbus flooding (RD-02).
3. HMI/PLC authentication hardening: lockout, session timeouts, unique accounts.
4. Formalize change management (MOC) with master logic-hash verification.
5. Encrypted control conduits (Modbus/TCP Security or VPN).
