# DOE C2M2: Cybersecurity Capability Maturity Self-Assessment

**Scope:** OT-Security-Lab — simulated Water Treatment & Filtration facility
**Reference Standard:** U.S. DOE Cybersecurity Capability Maturity Model (C2M2), v2.1
**Method:** Self-assessment of the lab across the 10 C2M2 domains. Each domain is rated at
MIL-1 (initial / ad hoc) to MIL-3 (managed / institutionalized) based on the controls
actually implemented in the repository, not on aspirational design. Where a domain is
deliberately out of scope for a lab, the rating reflects the pattern demonstrated.

---

## Summary Table

| # | Domain (C2M2 Abbr.) | Maturity (MIL) | Rationale |
| :--- | :--- | :--- | :--- |
| 1 | Risk Management (RISK) | MIL-2 | Documented risk assessment methodology, repeatable |
| 2 | Asset, Change, and Configuration Management (ACC) | MIL-2 | Central inventory + ADR-driven change control |
| 3 | Threat and Vulnerability Management (TVM) | MIL-2 | Threat model + automated vulnerability scanning |
| 4 | Situational Awareness (SA) | MIL-2 | Real-time SIEM with verified alert evidence |
| 5 | Information Sharing and Communications (ISC) | MIL-1 | Structured alerts exist; no external sharing |
| 6 | Event and Incident Response (IR) | MIL-2 | OT-specific playbooks + automated alerting |
| 7 | Continuity of Operations (COOP) | MIL-1 | Backups simulated only; no recovery drills |
| 8 | Supply Chain and External Dependencies (SC) | MIL-1 | Pinned/provenance-controlled images; no vendor program |
| 9 | Workforce Management (WFM) | MIL-1 | Documented culture/lessons learned; no training program |
| 10 | Cybersecurity Architecture (ARCH) | MIL-3 | Purdue zones, iptables chokepoint, defense in depth fully enforced |

---

## Domain Details

### 1. Risk Management (RISK) — MIL-2
- Formal MAGERIT v3 assessment covers asset criticality, threats, and residual risk with
  defined safeguards.
- Threat model identifies actor profiles (APT, insider, ransomware) and high-priority
  scenarios with attack trees.
- IEC 62443 SL-T/SL-A mapping ties risk appetite to zone security levels.
- *Evidence:* `governance/risk_assessment/OT_RISK_ASSESSMENT_MAGERIT.md`, `threat-model/THREAT_MODEL.md`, `iec62443/sl-mapping.md`

### 2. Asset, Change, and Configuration Management (ACC) — MIL-2
- Master asset inventory with zone, function, and criticality; inventory schema defined.
- Configuration is version-controlled (firewall rules, IDS rules, compose file) with
  ADRs documenting rationale and consequences of changes.
- No automated config-drift detection (gap to MIL-3).
- *Evidence:* `asset-inventory/assets.csv`, `architecture/architecture-decisions.md`, `lab-environment/network-config/`

### 3. Threat and Vulnerability Management (TVM) — MIL-2
- Threats mapped to MITRE ATT&CK for ICS tactics (T0800-T0890, e.g., T0831, T0836, T0886).
- Automated SAST/SCA/container scanning in CI: ruff, bandit, shellcheck, gitleaks,
  pip-audit, checkov, Trivy.
- Detection rules are derived from the threat model, closing the threat-to-detection loop.
- *Evidence:* `threat-model/mitre-ics-mapping.md`, `.github/workflows/`, `detection/sigma/`

### 4. Situational Awareness (SA) — MIL-2
- Real-time protocol-aware monitoring (Modbus/TCP port 502, DNP3 port 20000) on the gateway.
- Physics-aware shadow monitor detects safety-interlock violations that pure signature
  detection would miss (verified alert: tank at 95%).
- Grafana/Loki/Promtail SIEM provides SOC dashboards; alerts.json is live detection evidence.
- *Evidence:* `detection/rules/process_safety_violation.py`, `detection/logs/alerts.json`, `evidence/SOC_Overview_Dashboard.png`

### 5. Information Sharing and Communications (ISC) — MIL-1
- Alert pipeline produces structured JSON consumed by Alertmanager webhook (SOAR-lite),
  demonstrating machine-readable output suitable for sharing.
- No external threat-intelligence ingestion or formal ISAC-style sharing (gap to MIL-2).
- *Evidence:* `automation/playbooks/webhook_receiver.py`, `siem/configs/alerting-rules.yml`

### 6. Event and Incident Response (IR) — MIL-2
- OT-specific "safety-first" playbook for unauthorized PLC change; containment prioritizes
  process availability.
- Detection-to-alert automation: Loki rules -> Alertmanager -> webhook; CI compliance gate
  asserts attack simulation is detected.
- Lessons-learned documentation closes the loop.
- *Evidence:* `incident-response/ir-playbook-unauthorised-plc-change.md`, `make compliance`, `LESSONS_LEARNED.md`

### 7. Continuity of Operations (COOP) — MIL-1
- Control-logic golden files stored on the EWS as the backup pattern (IEC 62443 SR_7.3
  rated Simulated).
- No automated restore, no failover, no recovery drills — acceptable for a single-host lab.
- *Evidence:* `iec62443/gap-analysis.csv` (SR_7.3)

### 8. Supply Chain and External Dependencies (SC) — MIL-1
- Images are pinned, resources are limited, containers drop all capabilities except
  required ones (`cap_drop: ALL`), and Trivy scans for known CVEs.
- No formal supplier risk program, which is out of scope for the lab.
- *Evidence:* `lab-environment/docker-compose.yml`, README DevSecOps section

### 9. Workforce Management (WFM) — MIL-1
- Post-mortem culture demonstrated via LESSONS_LEARNED.md and hardening guidance written
  for operators.
- No role-based training curriculum or awareness program in the repo.
- *Evidence:* `LESSONS_LEARNED.md`, `governance/hardening/LINUX_OT_GATEWAY_STIG.md`

### 10. Cybersecurity Architecture (ARCH) — MIL-3
- Five-zone Purdue architecture with dedicated iptables gateway chokepoint (172.24.0.2),
  default-deny conduits, and internal-only Docker networks for OT zones.
- Defense in depth: network segmentation + application-layer allow-listing + physics-aware
  detection + centralized SIEM.
- Key ADRs (historian at L3, EWS enclave, iDMZ jump host, SIS air-gap proxy) are
  institutionalized patterns.
- *Evidence:* `architecture/zone-conduit-design.md`, `architecture/architecture-decisions.md` (ADR-02/03/04/05/06), `lab-environment/docker-compose.yml`

---

## Overall Assessment

The lab is strongest in **Cybersecurity Architecture (MIL-3)** and consistently
**MIL-2** across risk, asset/change, threat/vulnerability, situational awareness, and
incident response domains — a credible representation of a mid-maturity OT program.
Organizational domains (workforce, supply chain, continuity, information sharing) sit at
MIL-1 by design, as they require people, processes, and external relationships that a
virtualized lab intentionally does not simulate.
