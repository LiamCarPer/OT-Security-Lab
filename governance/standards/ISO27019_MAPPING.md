# ISO/IEC 27019: Control Mapping and Gap Analysis

**Scope:** OT-Security-Lab — simulated Water Treatment & Filtration facility
**Reference Standard:** ISO/IEC 27019 (Information security for process control, automation
and industrial systems in the energy utility sector — guidance based on ISO/IEC 27002)
**Companion Frameworks:** IEC 62443-3-2/3-3, NIST SP 800-82, MITRE ATT&CK for ICS

ISO/IEC 27019 applies the ISO/IEC 27002 control set to ICS/SCADA environments, adding
energy-sector-specific interpretation. This mapping follows the ISO 27002:2013 control
structure used by 27019 and notes where the lab implements, partially implements, or
lacks each control domain. Maturity ratings:

| Maturity | Meaning |
| :--- | :--- |
| **Implemented** | Working lab component enforces the control; verifiable evidence exists. |
| **Partial** | Control is applied to a subset of assets, or is logically rather than physically enforced. |
| **Gap** | No lab implementation; documented as future work or requiring non-lab assets. |

---

## Control Domain Map

| ISO 27019 Domain | Representative Controls | Lab Implementation | Maturity | Evidence / Gap Notes |
| :--- | :--- | :--- | :--- | :--- |
| **A.5 Information Security Policies** | ICS-specific security policy; review process | Zone/conduit policy, hardening checklist, threat model define the security posture for the OT environment | Implemented | `architecture/zone-conduit-design.md`, `hardening/HARDENING_CHECKLIST.md`, `threat-model/THREAT_MODEL.md` |
| **A.8 Asset Management** | Asset inventory, ownership, classification | Master asset list with zone, function, and criticality per asset; MAGERIT inventory records C/I/A per asset | Implemented | `asset-inventory/assets.csv`, `governance/asset_inventory.csv`, `governance/risk_assessment/OT_RISK_ASSESSMENT_MAGERIT.md` |
| **A.9 Access Control** | User access management; privileged access; authorization of control commands | Firewall restricts Modbus (502) to HMI 172.22.0.10; IDS allow-lists write sources (HMI + EWS 172.23.0.4); EWS isolated in a privileged enclave; HMI has login (Scada-LTS) | Implemented (Partial for user-level) | `detection/rules/modbus_anomaly.py`, `iec62443/gap-analysis.csv` (SR_1.1, SR_2.1). Gap: no centralized user directory or per-operator RBAC |
| **A.10 Cryptography** | Encryption of control traffic and data at rest | Modbus/TCP is unencrypted; Grafana access is anonymous; no TLS on industrial channels. Historian data unencrypted at rest | Gap (Partial) | `iec62443/gap-analysis.csv` (SR_4.1 Partial): transition to Modbus/TCP Security (TLS) or VPN tunnels |
| **A.12 Operations Security** | Malware protection, backups, logging, vulnerability management | No AV on PLCs (by design); passive network IDS compensates; JSON alert logging to Loki; golden logic files on EWS | Implemented (Partial) | `iec62443/gap-analysis.csv` (SR_3.1, SR_6.1, SR_7.3); `detection/logs/alerts.json`; `detection/rules/` |
| **A.13 Communications Security** | Network segmentation, segregation of networks | Full Purdue zone isolation with iptables gateway chokepoint (172.24.0.2); internal Docker networks are `internal: true` for OT zones; default-deny conduits | Implemented | `lab-environment/docker-compose.yml` (networks), ADR-05, `architecture/zone-conduit-design.md` |
| **A.14 System Acquisition, Development, Maintenance** | Security requirements in acquisition; secure development; change management | Change/management-of-change intent covered by ADRs and hardening baselines; STIG-style baseline for gateway and PLCs | Partial | `architecture/architecture-decisions.md`, `governance/hardening/LINUX_OT_GATEWAY_STIG.md`. Gap: no formal MOC workflow/ticketing in lab |
| **A.16 Incident Management** | Response procedures, escalation, lessons learned | OT-specific IR playbook (unauthorized PLC change), detection-to-alert pipeline (Loki -> Alertmanager -> webhook), post-mortem doc | Implemented | `incident-response/ir-playbook-unauthorised-plc-change.md`, `governance/incident_response/IR_PLAYBOOK_PLC_TAMPERING.md`, `LESSONS_LEARNED.md` |
| **A.17 Business Continuity** | Redundancy, backup, recovery | No HA/redundant PLC or historian; backup of control logic is simulated (golden files on EWS) | Gap | `iec62443/gap-analysis.csv` (SR_7.3 Simulated); acceptable for a single-host lab, required for production |
| **A.18 Compliance** | Compliance with legal/regulatory requirements; audits | Framework mappings (IEC 62443, MITRE, MAGERIT, NIST, NIS2 checklist); CI compliance gate asserts rule coverage | Implemented | `iec62443/sl-mapping.md`, `governance/standards/*.md`, README compliance section |

---

## 27019-Specific ICS Interpretations Demonstrated

ISO/IEC 27019 does more than restate ISO 27002; it adds guidance specific to process
control environments that the lab deliberately exercises:

| 27019 Emphasis | Lab Demonstration |
| :--- | :--- |
| Safety and availability take precedence over confidentiality | IEC 62443 SL targets reflect this ordering; safety-first IR playbook and physics-aware monitoring protect availability-critical PLCs |
| Network segregation is the primary OT defense | Full Purdue zoning with an iptables chokepoint rather than reliance on host hardening (ADR-05) |
| Protocol-aware monitoring, not just IT-style logging | Custom Scapy dissectors for Modbus/TCP (502) and DNP3 (20000) plus Sigma rules for portability |
| Passive observation to avoid process disruption | IDS is passive by design; active scanning is only performed from the attacker simulation, never against live process traffic (ADR-07) |
| Engineering access is the highest-risk activity | EWS dedicated enclave with restricted ACLs and write-only-to-PLCs posture (ADR-03) |

---

## Key Gaps Summary

1. **Cryptography (A.10):** Industrial traffic (Modbus/TCP, DNP3 over TCP) is plaintext.
   Remediation path: Modbus/TCP Security (TLS) or IPsec/VPN between zones.
2. **User-level access management (A.9):** Authentication is per-application (Scada-LTS,
   Grafana) with no central identity store; Grafana anonymous access is enabled by design
   for demo visibility.
3. **Business continuity (A.17):** No redundancy or automated restore; control-logic
   backups are stored in a single location.
4. **Change management (A.14):** Architecture decisions are documented, but no procedural
   MOC workflow (approval gates, rollback procedures) exists inside the lab.

These gaps are expected in a demonstration environment and each has a documented
remediation mapped in the IEC 62443 gap analysis (`iec62443/gap-analysis.csv`).
