# Security Policy

## Scope

This repository is a **demonstration OT/ICS security lab** (Docker-based
simulation of a water treatment facility). It contains no production systems,
no real operational technology, and no sensitive production data. The attack
simulations, detection rules, and adversary playbooks in this repository are
intended for educational and portfolio use only.

In scope for security reports:
- Vulnerabilities in the lab infrastructure (compose stack, Dockerfiles, CI/CD configuration)
- Bugs in the detection rules (`detection/rules/`) or automation (`automation/`)
- Unsafe default configurations that could affect someone running the lab

Out of scope:
- Vulnerabilities in third-party upstream components (Docker images, GitHub Actions)
  — report those to their respective maintainers

## Reporting a Vulnerability

Please **do not** open a public issue for security-sensitive findings.

Report privately via GitHub's **Private Vulnerability Reporting** (Security
tab → Report a vulnerability), or open a standard issue if the finding is not
sensitive (e.g., documentation errors).

What to include:
- A clear description of the issue and its impact
- Steps to reproduce (including the relevant compose services or scripts)
- Suggested remediation, if known

## Disclosure Policy

- **Acknowledgement:** you will be acknowledged for validated reports (unless you prefer to remain anonymous).
- **Response target:** an initial response within 5 business days.
- **Fix window:** validated critical/high findings are prioritized ahead of
  routine dependency updates; fixes land through the standard pipeline
  (CI gates + Compliance Gate must pass before merge).

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `main` | Yes — CI and Compliance Gate are enforced |
| Latest release (see [Releases](https://github.com/LiamCarPer/OT-Security-Lab/releases)) | Yes |
| Older releases | No — upgrade to the latest |

## Verification

Every security fix is verified by the repository's automated gates:
10 CI checks (lint, SAST, unit tests, policy-as-code, SBOM attestation, secret
scanning, dependency audits, container/IaC scans) and the Compliance Gate,
which boots the full lab, replays attack simulations, and asserts detection.
