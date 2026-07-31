# OT Security Assessment - Discovery Checklist

**Purpose:** Evidence and documentation to request and verify during Phase 2 (Discovery) of the engagement. Each item maps to the evidence index of the final report. The lab equivalents demonstrate the format expected.

## 1. Asset and Architecture Documentation

- [ ] Asset inventory covering all devices in scope (hostname, IP, MAC, manufacturer, model, firmware, role, zone). Lab reference: `asset-inventory/assets.csv`.
- [ ] Network topology and zone/conduit diagram mapped to the Purdue model. Lab reference: README.md architecture diagram and `architecture/zone-conduit-design.md`.
- [ ] IP addressing scheme per zone (e.g., Control 172.21.0.0/24, Supervisory 172.22.0.0/24, Operations 172.23.0.0/24, Enterprise 172.24.0.0/24).
- [ ] Firewall/segmentation rule base (allow-list rules per conduit). Lab reference: `lab-environment/network-config/firewall-rules.sh`.
- [ ] Protocol inventory: which protocols (Modbus/TCP, DNP3, etc.), on which ports, between which assets.
- [ ] Data flow diagrams for process data (PLC to HMI, PLC to historian) and for remote access.

## 2. Configuration Evidence

- [ ] HMI/SCADA user accounts, roles, and authentication settings (default accounts, password policy, lockout). Lab reference: Scada-LTS instance at 172.22.0.10.
- [ ] Historian configuration (databases, retention, encryption, listening interfaces). Lab reference: InfluxDB 1.8.10 at 172.23.0.10 (database `ot_data`).
- [ ] PLC configuration and firmware versions (OpenPLC v4), including any exposed services (e.g., 502/tcp, 8443/tcp).
- [ ] Engineering workstation build standard and installed tooling (RDP exposure noted at 172.23.0.4, port 3389).
- [ ] Jump host / bastion configuration, session controls, and timeout settings (SR_2.6 remote session termination).
- [ ] Backup configuration: scope, frequency, location, and restore procedure (SR_7.3).

## 3. Security Monitoring Evidence

- [ ] Detection rules and alerting configuration. Lab reference: `detection/rules/modbus_anomaly.py`, `process_safety_violation.py`, `cross_zone_traffic.py`, `ot_brute_force.py`, `dnp3_anomaly.py`.
- [ ] SIEM/SOC integration (log sources, retention, dashboards). Lab reference: Loki 172.24.0.20, Promtail 172.24.0.21, Grafana 172.24.0.22, Alertmanager 172.24.0.23.
- [ ] Sample of recent alerts and detection metrics (per-rule counts, unique sources, MTTD proxy). Lab reference: `detection/logs/alerts.json` and `automation/metrics.py`.
- [ ] Logging and audit configuration on all assets (what is logged, where, for how long).

## 4. Operational and Process Documentation

- [ ] Standard operating procedures for process start/stop and for manual/automatic mode transitions.
- [ ] Safety interlock description (e.g., tank overflow interlock that blocks valve-open commands at >95% level).
- [ ] Change management (MOC) records for the last 12 months of logic changes (SR_3.3).
- [ ] Incident history and post-incident reports (root-cause analysis records).

## 5. Governance Evidence

- [ ] Risk assessment (MAGERIT or equivalent) and risk register. Lab reference: `governance/risk_assessment/OT_RISK_ASSESSMENT_MAGERIT.md`, `governance/risk_register.csv`.
- [ ] BIA with RTO/RPO per asset. Lab reference: `governance/bia.md`.
- [ ] Existing policies (access control, change management, remote access, backup/DR). Lab reference: `governance/policies/`.
- [ ] Security level targets per zone (SL-T) and current achieved level (SL-A). Lab reference: `iec62443/sl-mapping.md`.
- [ ] Test plans and previous assessment findings. Lab reference: `governance/testing/CYBERSECURITY_TEST_PLAN.md`.

## 6. Documentation Gap Log

| Missing Item | Why It Matters | Owner | Deadline |
| :--- | :--- | :--- | :--- |
| (record items not provided) | (risk of unassessed area) | (asset owner) | (date) |

---

**Completed By:** Discovery Lead
**Date:**
