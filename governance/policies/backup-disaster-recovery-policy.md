# Backup and Disaster Recovery Policy - OT Environment

**Policy Owner:** IT/Engineering Lead
**Effective Date:** 2026-08-01
**Applies To:** PLC logic (golden images), HMI/SCADA configuration, historian data (InfluxDB `ot_data`), gateway firewall and IDS rule sets, SIEM configuration
**Alignment:** IEC 62443-3-3 SR_7.3 (control system backup), NIST SP 800-34 (contingency planning); recovery objectives per `governance/bia.md`

## 1. Purpose

The Business Impact Analysis defines maximum tolerable downtime (RTO) and data loss (RPO) per asset; this policy defines the backup and disaster recovery arrangements that guarantee those objectives are met. It closes the highest-priority gap identified in the gap analysis (SR_7.3 rated "Simulated" - automated backups outstanding) and protects the facility against ransomware (RSK-008), logic tampering (RSK-007), and hardware failure.

## 2. Recovery Objectives (from BIA)

| Asset | RTO | RPO | Backup Cadence |
| :--- | :--- | :--- | :--- |
| PLC_Intake (172.21.0.10) | 1 h | 15 min (logic) | After every approved logic change + weekly scheduled |
| PLC_Treatment (172.21.0.11) | 30 min | 15 min (logic) | After every approved logic change + weekly scheduled |
| PLC_Distribution (172.21.0.12) | 2 h | 1 h (logic) | After every approved logic change + weekly scheduled |
| OT_HMI (172.22.0.10) | 2 h | 1 h | Daily configuration backup |
| OT_Historian (172.23.0.10) | 4 h | 1 h | Daily incremental + weekly full backup |
| Industrial Gateway (172.24.0.2) | 30 min | n/a (config) | Versioned rule sets on every change |
| EWS (172.23.0.4) | 4 h | Daily | Daily workstation image + logic source in vault |
| SIEM (Loki/Grafana 172.24.0.20-22) | 8 h | 1 h | Daily configuration and rules backup |

## 3. Backup Policy Statements

1. **PLC logic:** every logic change performed under the Change Management Policy (MOC) must produce a golden logic file stored on the EWS (172.23.0.4) and mirrored to offline storage; the master logic hash is updated at the same time and is used to verify restores and to detect tampering (T0853).
2. **Historian data:** InfluxDB (172.23.0.10) data must be backed up daily (incremental) and weekly (full), stored on offline media isolated from the OT network so that a ransomware event cannot encrypt backups.
3. **Gateway and security configuration:** firewall rules (`firewall-rules.sh`), IDS rules (`detection/rules/`), and SIEM provisioning configuration are version-controlled; each change is tagged and deployable in under 30 minutes.
4. **Backup integrity:** all backups must be encrypted (AES-256 or equivalent) and verified for readability after creation (checksum/hash verification).
5. **Retention:** a minimum of 13 weekly backups and 12 monthly backups must be retained for the historian; PLC logic versions are retained indefinitely as golden references.
6. **Backup media:** offline (air-gapped or physically segregated) media is required for historian backups and PLC golden images; network-attached backup storage alone does not satisfy this policy.

## 4. Recovery Procedures

1. **PLC restore:** recover the golden logic file from the vault, verify against the master logic hash, load via the EWS, and return to automatic control while monitoring interlocks, per `IR_PLAYBOOK_PLC_TAMPERING.md` (Eradication and Recovery section).
2. **Historian restore:** rebuild InfluxDB `ot_data` from the latest verified backup; validate continuity with the Promtail-shipped logs retained in Loki.
3. **Gateway restore:** redeploy the versioned rule set and validate with the compliance gate (`make compliance`).
4. **Restore sequencing** follows the BIA: gateway and PLC_Treatment first, then remaining PLCs, HMI, historian, and SIEM last.

## 5. Testing and Assurance

1. A **restore exercise** must be performed quarterly, covering at minimum: one PLC golden logic restore, the historian restore, and the gateway rule redeployment. Each exercise must complete within the asset RTO.
2. Restore exercises are documented (date, participants, result, deviations) and reviewed by the OT Security Director; a failed exercise triggers corrective action within 30 days.
3. Annual disaster recovery testing must include a simulated ransomware scenario (see the tabletop kit, scenario 2) that exercises the offline restore path.

## 6. Roles and Responsibilities

- **IT/Engineering** performs backups, maintains the vault, and executes restore exercises.
- **Plant Operations** schedules and supervises restore exercises affecting the process.
- **Security** verifies backup encryption, offline isolation, and exercises the ransomware scenario.
- **OT Security Director** reviews exercise results and approves exceptions.

## 7. Exceptions and Compliance

- Deviations from backup cadence must be documented and risk-accepted by the OT Security Director; unrecoverable data gaps must be reported to the Plant Manager immediately.
- Non-compliance with this policy is escalated per the incident response process.

---

**Approved By:** OT Security Director / Plant Manager
**Review Date:** 2026-11-01
