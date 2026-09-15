# Detection Automation & Orchestration (SOAR-lite)

This directory contains the operational layer that converts raw detections into
actions: alert triage, OSINT enrichment, detection-health metrics, and
remediation playbooks.

## Components

| Module | Purpose |
| :--- | :--- |
| `metrics.py` | Computes detection KPIs from `detection/logs/alerts.json` (per-rule volumes, unique sources, MTTD estimates). Writes `detection/logs/metrics.json`, consumed by the executive summary and the KPI baseline in `governance/remediation_roadmap.md`. |
| `enrichment.py` | OSINT enrichment of alert source IPs (ASN/owner via Team Cymru, country via reverse DNS). No API keys required. |
| `playbooks/auto_block_ip.py` | Containment playbook: automatically blocks repeat unauthorized-Modbus-write offenders (threshold: 3 writes / 5 min) with an iptables DROP on the zone gateway. Dry-run and unblock modes included. |
| `playbooks/webhook_receiver.py` | Alertmanager webhook receiver: persists SIEM alerts to `detection/logs/siem_alerts.json`, bridging Loki alerting and downstream playbooks. |

## Alerting Flow

```
Gateway IDS ──NDJSON──▶ Promtail ──▶ Loki (alerting rules) ──▶ Alertmanager
     │                                                              │
     │ responder.py (gateway-side)                    webhook (9095)▼
     │ watches alerts.json and DROPs                  webhook_receiver.py
     ▼ repeat offenders                                (persists siem_alerts.json)
  iptables FORWARD DROP                                         │
                                                      playbooks (auto-block, enrichment)
```

Containment is enforced **inside the gateway** by `detection/rules/responder.py`
(it already holds `NET_ADMIN`; no Docker socket), which watches `alerts.json` and
DROPs a source after 3 unauthorized-write alerts in 5 minutes. It is **dry-run by
default** (`OT_RESPONDER_ENFORCE=1` to arm) and reversible with
`python3 detection/rules/responder.py --unblock <ip>` or a gateway restart.
`playbooks/auto_block_ip.py` is the host-side equivalent for running against a
local lab.


## Usage

```bash
# Detection health metrics
python3 automation/metrics.py

# Enrich a suspicious source
python3 automation/enrichment.py 172.24.0.10 --json

# Auto-block repeat offenders (dry run first!)
python3 automation/playbooks/auto_block_ip.py --dry-run
python3 automation/playbooks/auto_block_ip.py
python3 automation/playbooks/auto_block_ip.py --unblock
```

## Safety Notes

- Playbooks operate on a **simulated lab**; in production, automatic
  containment actions require change-management approval (IEC 62443 MOC).
- The block is gateway-local and fully reversible via `--unblock`.
