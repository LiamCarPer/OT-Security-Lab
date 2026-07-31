# EU NIS2 Directive: Readiness Checklist (Lab Demonstration)

> **Important scope note:** The OT-Security-Lab is a **virtualized demonstration and
> learning environment**, not a production deployment of essential or important
> entities. It cannot, by itself, make an organization NIS2-compliant. This checklist
> is provided to demonstrate (a) understanding of the NIS2 cybersecurity requirements
> (Directive (EU) 2022/2555) and (b) how each requirement maps to a concrete control
> in the lab, so the pattern can be replicated in a production setting. Status columns
> therefore reflect the lab's coverage of the requirement's *pattern*, not legal
> compliance of any real entity.

| Status | Meaning |
| :--- | :--- |
| **Compliant** | Requirement's control pattern is fully demonstrated by a working lab component. |
| **Partially** | Pattern is demonstrated but limited (e.g., logical not physical, or single vendor). |
| **N/A** | Requirement is organizational/procedural or outside the scope of a lab simulation. |

---

## Checklist

| NIS2 Requirement (Art.) | Requirement Summary | Status | Lab Control Mapping / Notes |
| :--- | :--- | :--- | :--- |
| Art. 21(2)(a) | Risk analysis and information security policies | Compliant | MAGERIT risk assessment and threat model define the risk posture; zone/conduit policy encodes decisions (`governance/risk_assessment/OT_RISK_ASSESSMENT_MAGERIT.md`, `architecture/zone-conduit-design.md`) |
| Art. 21(2)(b) | Incident handling (prevention, detection, response, recovery) | Compliant | Detection rules feed Loki -> Alertmanager -> webhook (SOAR-lite); OT-specific IR playbook for PLC tampering; verified alert evidence in `detection/logs/alerts.json` |
| Art. 21(2)(c) | Business continuity, backup management, recovery | Partially | Control-logic backups simulated (golden files on EWS, SR_7.3). No automated restore or redundancy — a single-host lab limitation |
| Art. 21(2)(d) | Supply chain security (direct suppliers) | N/A | No real third-party suppliers in the lab. Image provenance is addressed via pinned images, `cap_drop`, `no-new-privileges`, and Trivy scanning (`lab-environment/docker-compose.yml`, CI) |
| Art. 21(2)(e) | Security in acquisition, development, lifecycle (incl. MOC) | Partially | Secure-by-design demonstrated through ADRs and STIG-style hardening baselines; formal MOC approval workflow not simulated (`architecture/architecture-decisions.md`, `governance/hardening/LINUX_OT_GATEWAY_STIG.md`) |
| Art. 21(2)(f) | Vulnerability handling and disclosure | Compliant | Automated scanning in CI: bandit, shellcheck, gitleaks, pip-audit, checkov, Trivy; functional security verification via attacker simulation + compliance gate (`make compliance`) |
| Art. 21(2)(g) | Practices for assessing effectiveness of measures | Compliant | Verification test plan maps simulations to requirements (V&V); CI compliance gate asserts detection coverage (`governance/testing/CYBERSECURITY_TEST_PLAN.md`) |
| Art. 21(2)(h) | Cyber hygiene and training | N/A | Organizational HR measure; lab documents a post-mortem/lessons-learned culture as a proxy (`LESSONS_LEARNED.md`) |
| Art. 21(2)(i) | Cryptography and encryption | Partially | Not implemented on OT channels: Modbus/TCP and DNP3 are plaintext (SR_4.1 Partial). Gap documented: TLS/VPN required for production |
| Art. 21(2)(j) | Human resources security / access control | Partially | Command-level access control enforced (authorized write sources: HMI 172.22.0.10, EWS 172.23.0.4); user-level authentication is per-application only (SR_1.1 Partial) |
| Art. 21(2)(k) | Authentication, MFA, secure voice/video comms | Partially | Access policies reference MFA (see `REMOTE_ACCESS_DESIGN.md`); no live MFA broker in the lab |
| Art. 23 | Management body approval and oversight | N/A | Organizational requirement; lab documents demonstrate the same rigor of sign-off (ADRs with Accepted status) |
| Art. 24 | Registration with authorities, contact points | N/A | Regulatory administrative duty; out of scope for a lab |
| Art. 27 | Reporting obligations to CSIRT (significant incidents) | Partially | Alert pipeline demonstrates structured notification (JSON alerts -> webhook receiver `siem_alerts.json`); CSIRT reporting workflow is procedural |
| Art. 21(2)(l) | Access control, MOC, monitoring, logging | Partially | Segregation, monitoring and logging are fully demonstrated (Grafana/Loki SIEM, JSON alerts); MOC procedural layer absent |
| Art. 21(2)(m) | Resilience, continuity, back-up, disaster recovery | Partially | see Art. 21(2)(c); single-host lab has no geo/HA redundancy |

---

## Mapping Methodology

Each checklist row is assessed against the same three evidence classes used across this
repository's governance documents:

1. **Architecture evidence** — zone/conduit design, ADRs, and docker-compose topology
   demonstrate that the control pattern is structurally in place.
2. **Detection evidence** — `detection/logs/alerts.json` contains verified alert records
   for UNAUTHORIZED_MODBUS_WRITE (T0831), PROCESS_SAFETY_VIOLATION (T0836),
   CROSS_ZONE_VIOLATION (T0886), OT_BRUTE_FORCE_SCAN (T0846), and DNP3_WRITE_UNAUTHORIZED
   (T0831), proving the monitoring requirements are operational, not only documented.
3. **Process evidence** — threat model, risk assessment (MAGERIT), gap analysis
   (`iec62443/gap-analysis.csv`), and IR playbooks demonstrate the procedural layer.

A row is rated "Partially" when the control exists in architecture or detection terms
but its organizational or physical equivalent is absent (e.g., MFA broker, encrypted
OT channels, formal MOC workflow).

## Transition Roadmap to a Production Deployment

| Phase | Action | Closes Checklist Row |
| :--- | :--- | :--- |
| 1 | Deploy TLS or IPsec on all OT channels (Modbus/TCP Security, VPN) | Cryptography (Art. 21(2)(i)) |
| 2 | Central identity provider + MFA broker on the jump host | Access control (Art. 21(2)(j)/(k)) |
| 3 | Formal MOC procedure with approval gates and rollback plans | MOC / development (Art. 21(2)(e)) |
| 4 | Automated control-logic backups to offline storage + recovery drills | Business continuity (Art. 21(2)(c)/(m)) |
| 5 | CSIRT notification workflow wired to the Alertmanager webhook | Reporting (Art. 27) |

---

## Coverage Summary| Status | Count | Notes |
| :--- | :--- | :--- |
| Compliant | 5 | Risk analysis, incident handling, vulnerability handling, effectiveness assessment, (monitoring/logging as pattern) |
| Partially | 7 | BC/backup, MOC, crypto, access control, MFA, reporting, resilience |
| N/A | 3 | Training, management oversight, authority registration |

**Primary production gaps identified for transition:** encrypted OT protocols, centralized
identity + MFA, automated backup/restore, and a documented MOC procedure. Each has an
equivalent remediation row in `iec62443/gap-analysis.csv`.
