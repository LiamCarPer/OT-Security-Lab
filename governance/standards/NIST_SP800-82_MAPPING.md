# NIST SP 800-82 Rev 3: OT Security Control Mapping

**Scope:** OT-Security-Lab — simulated Water Treatment & Filtration facility (Purdue L0-L5)
**Reference Standard:** NIST SP 800-82 Rev 3, Guide to Operational Technology (OT) Security
**Status:** Mapping of NIST guidance families to concrete lab controls, with evidence references.

NIST SP 800-82 Rev 3 provides guidance for securing OT systems, including ICS-specific
interpretations of NIST SP 800-53 controls. This document maps the six core capability
areas highlighted by the standard — asset inventory, network segmentation, access
management, monitoring and logging, remote access, and incident response — to their
concrete implementations inside the lab. Maturity is rated per control:

| Maturity | Meaning |
| :--- | :--- |
| **Implemented** | Control is enforced by a working lab component and verifiable. |
| **Partial** | Control exists but is limited to a subset of assets or is logically (not physically) enforced. |
| **Simulated** | Control is represented conceptually (e.g., by policy or a stand-in component) but not fully exercised. |

---

## 1. Asset Inventory and Identification

| NIST Guidance (SP 800-82) | Lab Implementation | Evidence | Maturity |
| :--- | :--- | :--- | :--- |
| Maintain a complete OT asset inventory (HW, SW, network) | Master asset list covering PLCs (OpenPLC), HMI (Scada-LTS), Historian (InfluxDB), gateway, SIEM stack | `asset-inventory/assets.csv`, `asset-inventory/inventory-schema.md`, `governance/asset_inventory.csv` | Implemented |
| Identify assets by zone / Purdue level | Every asset is assigned a fixed IP bound to its zone subnet: IT 172.24.0.0/24, Ops 172.23.0.0/24, Supervisory 172.22.0.0/24, Control 172.21.0.0/24 | `lab-environment/docker-compose.yml` (static `ipv4_address` per service) | Implemented |
| Track asset criticality (C/I/A) | MAGERIT risk assessment records criticality per asset (e.g., PLC_Intake H/H/H); threat model assigns Safety & Availability priority to PLC-01/02 | `governance/risk_assessment/OT_RISK_ASSESSMENT_MAGERIT.md`, `threat-model/THREAT_MODEL.md` | Implemented |
| Automate discovery / detect rogue devices | Partial: no active or passive discovery service (Zeek/Nozomi-style) is deployed; inventory is manual. Rogue detection is approximated by IDS alerting on unexpected sources | `detection/rules/cross_zone_traffic.py`, README "Future Work" | Partial |

## 2. Network Segmentation and Zone Boundary Protection

| NIST Guidance (SP 800-82) | Lab Implementation | Evidence | Maturity |
| :--- | :--- | :--- | :--- |
| Segment OT from enterprise per Purdue model | Five-zone architecture: L4/5 IT 172.24.0.0/24; L3 Ops (Historian 172.23.0.10, EWS 172.23.0.4); L2 Supervisory (HMI 172.22.0.10); L1 Control (PLCs 172.21.0.10/11/12); L0 field (simulated) | `architecture/zone-conduit-design.md`, README architecture diagram | Implemented |
| Enforce default-deny between zones at chokepoints | Dedicated gateway container (172.24.0.2) running `iptables` with explicit ACCEPT/DROP per conduit; default posture DENY ALL | `lab-environment/docker-compose.yml` (gateway service), ADR-05 in `architecture/architecture-decisions.md`, `lab-environment/network-config/firewall-rules.sh` | Implemented |
| No direct L4 to L1 communication | IT-to-Control traffic is explicitly blocked and flagged; detection rule raises CROSS_ZONE_VIOLATION (T0886) for any IT 172.24.0.0/24 -> Control 172.21.0.0/24 traffic | `detection/rules/cross_zone_traffic.py`, conduit rules in `architecture/zone-conduit-design.md` | Implemented |
| DMZ for cross-boundary data flows | Industrial DMZ with jump host and reverse proxy terminates all sessions between enterprise and operations | ADR-04 in `architecture/architecture-decisions.md`, README DMZ diagram | Simulated |
| Data diode for unidirectional historian flow | Logical enforcement via `iptables` (ADT: writes restricted); hardware optical data diode explicitly called out as future work | ADR-02, README "Known Limitations" | Partial |

## 3. Access Management and Authentication

| NIST Guidance (SP 800-82) | Lab Implementation | Evidence | Maturity |
| :--- | :--- | :--- | :--- |
| Identify and authenticate users before access | HMI (Scada-LTS) implements login; Grafana is reachable at 172.24.0.22 with anonymous access enabled for demo (deliberate limitation) | `iec62443/gap-analysis.csv` (SR_1.1 Partial), `lab-environment/docker-compose.yml` (grafana env) | Partial |
| Restrict and authorize commands (usage enforcement) | Only HMI 172.22.0.10 and EWS 172.23.0.4 are authorized Modbus write sources; firewall restricts port 502 traffic to HMI; IDS enforces the same allow-list at the application layer | `detection/rules/modbus_anomaly.py` (AUTHORIZED_WRITERS), `iec62443/gap-analysis.csv` (SR_2.1) | Implemented |
| Terminate sessions after inactivity | Not enforced: gateway sessions are persistent; inactivity timeouts are a documented remediation | `iec62443/gap-analysis.csv` (SR_2.6 Partial) | Partial |
| Least privilege across zones | EWS is isolated in a dedicated enclave; direct connections to PLCs from any zone other than the EWS enclave are blocked by default | ADR-03 in `architecture/architecture-decisions.md` | Implemented |

## 4. Monitoring, Logging, and Anomaly Detection

| NIST Guidance (SP 800-82) | Lab Implementation | Evidence | Maturity |
| :--- | :--- | :--- | :--- |
| Monitor OT traffic without disrupting process | Passive Scapy-based IDS on the gateway sniffs Modbus/TCP (502) and DNP3 (20000) without injecting packets; passive sensor pattern documented | `detection/rules/*.py` (modbus, dnp3, brute force, cross-zone, safety), ADR-07 | Implemented |
| Detect protocol-aware anomalies | Rule set: UNAUTHORIZED_MODBUS_WRITE (T0831), PROCESS_SAFETY_VIOLATION (T0836), CROSS_ZONE_VIOLATION (T0886), OT_BRUTE_FORCE_SCAN (T0846), DNP3_WRITE_UNAUTHORIZED (T0831) | `detection/logs/alerts.json` (verified alert evidence), `detection/rules/` | Implemented |
| Monitor process physics (state-aware detection) | Physics-aware shadow monitor mirrors PLC registers (tank level, inlet valve) and alerts on interlock violations (e.g., opening inlet valve above 90% level) | `detection/rules/process_safety_violation.py`; evidence in `detection/logs/alerts.json` (2026-04-25 PROCESS_SAFETY_VIOLATION) | Implemented |
| Centralized log collection and correlation | Promtail ships JSON alerts to Loki; Grafana 11 (172.24.0.22) provides SOC dashboards; Alertmanager (172.24.0.23) forwards to webhook receiver (SOAR-lite, 172.24.0.24) | `lab-environment/docker-compose.yml` (loki/promtail/grafana/alertmanager/webhook services), `siem/configs/`, `automation/playbooks/webhook_receiver.py` | Implemented |
| Human-readable detection content | Sigma rules (e.g., `modbus_unauthorized_write.yml`, `process_safety_violation.yml`) formalize each alert type for SIEM portability | `detection/sigma/` | Implemented |

## 5. Remote Access

| NIST Guidance (SP 800-82) | Lab Implementation | Evidence | Maturity |
| :--- | :--- | :--- | :--- |
| Route remote access through a managed jump host | All external access terminates at the DMZ jump host, which initiates a new session into the operations zone; no direct IT-to-OT sessions | ADR-04, conduit C3 in `architecture/zone-conduit-design.md` | Simulated |
| Apply MFA and enforce access policy | Policy documented (MFA, time-based access, session recording as target state); no live MFA broker is deployed in the lab | `governance/standards/REMOTE_ACCESS_DESIGN.md` (to-be design) | Partial |
| Record and audit remote sessions | Documented as a jump-host enhancement; not yet implemented | ADR-04 "Consequences", `governance/standards/REMOTE_ACCESS_DESIGN.md` | Partial |

## 6. Incident Response and Recovery

| NIST Guidance (SP 800-82) | Lab Implementation | Evidence | Maturity |
| :--- | :--- | :--- | :--- |
| Documented IR plan tailored to OT | "Safety-First" IR playbook for unauthorized PLC changes, with containment steps that preserve process availability | `incident-response/ir-playbook-unauthorised-plc-change.md`, `governance/incident_response/IR_PLAYBOOK_PLC_TAMPERING.md` | Implemented |
| Detection-to-alert automation | IDS alerts flow to Loki alerting rules -> Alertmanager -> webhook receiver; verified in `detection/logs/alerts.json` and `siem/configs/alerting-rules.yml` | `lab-environment/docker-compose.yml`, `siem/configs/alerting-rules.yml` | Implemented |
| Backup / restore of control logic | Golden logic files stored on the EWS; automated periodic backup to offline storage is a documented gap | `iec62443/gap-analysis.csv` (SR_7.3 Simulated) | Simulated |
| Validate security functionality | CI + Compliance Gate (GitHub Actions) runs the attacker simulation and asserts detection, plus bandit/checkov/Trivy/pip-audit scans | `make compliance`, README DevSecOps section, `lab-environment/attacker/simulate_attack.py` | Implemented |

---

## Summary

The lab implements the core SP 800-82 capabilities with network segmentation, application-
layer allow-listing, and protocol/physics-aware detection at a production-quality pattern
level. Gaps are concentrated where physical or organizational controls are required
(hardware data diode, real MFA broker, session recording, automated backups), which are
deliberately represented as partial or simulated in a virtualized demonstration.
