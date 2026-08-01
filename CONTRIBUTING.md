# Contributing

Thanks for taking an interest in this project. It is a demonstration OT/ICS
security lab and portfolio piece, built and verified entirely through
automation. Contributions that improve the lab, its documentation, or its
pipeline are welcome.

## Ground Rules

- **Conventional Commits** are required (`feat:`, `fix:`, `docs:`, `test:`,
  `ci:`, `chore:`, `refactor:`) — the release workflow generates the CHANGELOG
  from them via git-cliff.
- Every change must pass the **10 CI gates** and, for changes that touch the
  lab stack, the **Compliance Gate** (boots the lab, replays attacks, asserts
  detection).
- No secrets. `gitleaks` runs in CI and as a pre-commit hook.
- Keep the evidence machine-generated: `detection/logs/alerts.json` is
  refreshed automatically by the Compliance Gate — do not hand-edit it.

## Development Setup

```bash
# Python 3.12+
pip install -r requirements-dev.txt
pre-commit install

# Run the checks locally
make lint      # ruff + bandit
make test      # pytest
make policy    # OPA/conftest policy on the compose stack
make scan      # pip-audit
make precommit # all pre-commit hooks

# Run the lab (Linux host or Codespaces)
make up
make compliance   # full validation: sims + detection assertions
```

## Where Things Live

| Area | Path |
| :--- | :--- |
| Lab environment (compose, Dockerfiles, firewall) | `lab-environment/` |
| Detection rules (Scapy IDS, DNP3, physics-aware monitor) | `detection/rules/` |
| Sigma rules and SIEM (Loki, Alertmanager, dashboards) | `detection/sigma/`, `siem/` |
| Automation (metrics, enrichment, playbooks, webhook) | `automation/` |
| PLC logic and integrity verification | `plc/` |
| Tests (unit + policy) | `tests/` |
| GRC, standards, policies, risk documentation | `governance/` |

## Making Changes

1. Fork the repository and create a branch (`git checkout -b feat/my-change`).
2. Make your change and add/update tests where appropriate:
   - Detection rules → unit tests in `tests/` (packets via Scapy, no sniffer needed)
   - Policy changes → update `tests/policy/compose.rego` accordingly
   - Pipeline changes → keep every gate meaningful; no empty gates
3. Run the local checks (`make lint test policy precommit`).
4. Open a pull request. The CI workflow runs automatically; a maintainer will
   review and, for lab-affecting changes, the Compliance Gate validates on merge.

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) — report privately, never in a public issue.
