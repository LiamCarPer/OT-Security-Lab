# Changelog

### Bug Fixes

- Suppress the bandit urlopen finding for the fixed Loki URL

- **scada:** Verify the session before trusting the JSESSIONID

- **ci:** Compare PLC bundle content, not zip bytes

- **plc:** Pin the STruC++ asset and regenerate the bundles

- **compose:** Drop the inert PLC host-port mappings


### CI/CD

- Rebuild PLC program bundles and fail on drift

- Build every lab image on pull requests

- **compliance:** Serialise gates and harden the evidence push

- **release:** Harden the CHANGELOG push and attach the machine-generated evidence


### Chores

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- Refresh the generated rules with a single trailing newline

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **plc:** Print a unified diff when a bundle entry changes

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **repo:** Ignore all detection/logs output except the evidence JSON

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **deps:** Stop python base bumps for the dnp3 images

- **deps:** Bump python from 3.12-slim to 3.14-slim in /lab-environment/plc-bootstrap (#35)

- **deps:** Bump python in /lab-environment/modbus-sim (#33)

- **deps:** Bump python in /lab-environment/historian-poller (#34)

- **deps:** Bump python in /lab-environment/opcua-server (#36)

- **deps:** Bump python in /lab-environment/s7-plc (#40)

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **deps-dev:** Update bandit requirement from >=1.7.0 to >=1.9.4 (#16)

- **deps-dev:** Update pre-commit requirement from >=4.6.1 to >=4.6.2 (#21)

- **deps:** Bump orhun/git-cliff-action from 4.8.0 to 4.9.0 (#27)

- **deps:** Bump kalilinux/kali-rolling in /lab-environment/attacker (#32)

- **deps-dev:** Update pyyaml requirement from >=6.0 to >=6.0.3 (#39)

- **deps-dev:** Update ruff requirement from >=0.16.0 to >=0.16.7 (#38)

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]


### Documentation

- Update CHANGELOG for v1.0.1 [skip ci]

- Add security policy, contributing guide, and GitHub Pages site

- Canonical Pages URL in the site badge

- Add the claims register and fix stale README claims

- **arch:** Correct network-design to the deployed 172.x schema

- **ir:** Consolidate the two PLC-tampering playbooks

- **evidence:** Add machine-generated runtime evidence

- **automation:** Correct the metrics.json consumer claim

- Fix drifted CI count, historian wording and typo

- **adr:** Normalise ADR statuses to match the implementation

- **claims:** Track the unbuilt ADR decisions as known gaps

- Lead the README with the compliance results


### Features

- Codespaces devcontainer - one-click lab in the browser

- Evaluate the generated detection bundle alongside the lab's rules

- Deploy real OpenPLC v4 logic and Scada-LTS HMI through the gateway

- Real multi-protocol endpoints and a live L2/L3 historian path

- Deploy real OpenPLC v4 logic and tighten the zone firewall

- **grc:** Make compliance, MITRE and executive claims data-derived

- **soar:** Gateway-side containment, SBOM attestation, supply-chain coverage

- **dmz:** Implement the Industrial DMZ (bastion, reverse proxy, corp workstation)

- **hmi:** Non-default Scada credentials and login-failure detection

- **dmz:** Implement the bastion -> EWS remote-engineering path (C11)


### Other

- Reconcile CI evidence refresh with the DMZ phase

- Normalize end-of-file newlines for pre-commit


### Testing

- **claims:** Guard against unsupported absolute claims


### Bug Fixes

- Resilient evidence push (rebase-retry on concurrent pushes)

- Normalize CHANGELOG trailing newline and cliff footer

- Pin SBOM verification identity to the running ref


### CI/CD

- Converge concurrent gate pushes instead of failing

- Make release CHANGELOG push resilient to concurrent pushes


### Chores

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **deps:** Bump python in /automation/playbooks (#4)

- **deps:** Bump alpine from 3.19 to 3.24 in /lab-environment/gateway (#6)

- **deps:** Bump kalilinux/kali-rolling in /lab-environment/attacker (#7)

- **deps:** Bump actions/upload-artifact from 4 to 7 (#5)

- **deps:** Bump actions/checkout from 4 to 7 (#9)

- **deps:** Bump gitleaks/gitleaks-action from 2.3.6 to 3.0.0 (#11)

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **deps:** Bump actions/setup-python from 5 to 7 (#12)

- **deps-dev:** Update pre-commit requirement from >=3.0 to >=4.6.1 (#8)

- **deps-dev:** Update scapy requirement from >=2.5.0 to >=2.7.0 (#13)

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **deps-dev:** Update requirement pip-audit>=2.7.0 to pip-audit>=2.10.1 (#10)

- **deps-dev:** Update requirement ruff>=0.4.0 to ruff>=0.16.0 (#15)

- **deps-dev:** Update pytest requirement from >=8.0 to >=9.1.1 (#14)

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]

- **evidence:** Refresh compliance gate alert evidence [skip ci]


### Documentation

- Update CHANGELOG for v1.0.0 [skip ci]

- Add the CI/CD debugging saga to lessons learned

- Update roadmap - adversary emulation shipped, refine remaining items


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
