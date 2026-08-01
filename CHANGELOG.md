# Changelog

### Bug Fixes

- Consolidate zone firewall, persist IDS services, and harden the lab stack

- Repair CI gates and make the lab boot deterministic in CI

- Correct checkov framework (all), add compliance diagnostics dump

- Harden gateway and attacker Dockerfiles to pass checkov gates

- Revert non-root attacker user, correct gateway healthcheck

- Make attacker pivot-route setup resilient and self-report compliance failures

- Webhook command doubles the python entrypoint, causing a crash loop

- Bake the webhook receiver into its own image (deterministic start)

- Raise gateway memory limit, robust IDS startup verification, and beefed-up boot diagnostics

- Grant DAC_OVERRIDE to gateway and webhook (cap_drop ALL broke log writes)

- Gateway healthcheck pattern and webhook default log path

- Pre-commit and cosign gates

- Pre-commit ruff/check-json gates and syft-based SBOM signing

- Release workflow pushes CHANGELOG via HEAD:main refspec


### CI/CD

- Guaranteed diagnostics issue posting and fully verbose webhook startup

- Fix invalid YAML in diagnostics step (heredoc indentation)

- Publish compliance diagnostics to a public paste (reliable channel)

- Expose compliance diagnostics URL via commit status

- Move webhook behind a compose profile and simplify diagnostics

- Publish compliance diagnostics to a dedicated branch


### Chores

- Update HMI and EWS IP addresses and modify gateway script execution command in docker-compose

- Trim compliance gate permissions and document the diagnostics step

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]


### Documentation

- Add known limitations, future roadmap, and compliance mapping to README

- Add threat model and MITRE ATT&CK for ICS mapping documents

- Add GRC documentation including MAGERIT risk assessment, STIG hardening guide, and cybersecurity test plan

- Add standards-breadth coverage (NIST 800-82, ISO 27019, NIS2, C2M2, SIS/BPCS, remote access)

- Add consultant-grade deliverables (risk register, BIA, roadmap, methodology, policies, exec brief, tabletop, to-be architecture)

- Fix CI and compliance gate badge URLs and clone URL


### Features

- Initialize project structure with comprehensive architecture documentation and Purdue Model design

- Implement Purdue Model segmentation and IEC 62443-3-2 zone-based firewalling

- Add detection rules for Modbus anomalies, brute-force activity, and cross-zone traffic violations

- Complete ot-security-lab v1.0 - architecture, segmentation, detection, and hardening

- Complete professional ot-security-lab v1.0 - fully automated and verified

- Implement static IP addressing and lateral movement simulation across multiple PLC zones

- Implement physics-aware process safety monitoring to detect unsafe Modbus commands based on tank level state

- Implement centralized SIEM observability stack using Grafana, Loki, and Promtail with automated dashboard provisioning.

- Harden container security, implement gateway firewall rules, and add automated compliance testing

- Add PLC hardening controls, incident response playbook, and asset inventory documentation

- Append new security alert logs to alerts.json

- Add Sysmon EDR log ingestion pipeline and dashboard visualization

- Add detection-as-code (Sigma), SIEM alerting, and SOAR-lite automation

- Add DNP3 detection, real PLC logic with integrity verification, and adversary emulation

- Auto-refresh committed alert evidence on every green compliance run

- Phase 5 devsecops polish - policy-as-code, SBOM attestation, pre-commit, dependabot, releases


### Testing

- Make detection rules testable and add CI gates (pytest, ruff, bandit, scans)
