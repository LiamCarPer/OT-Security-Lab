# Detection Automation & Orchestration (SOAR-lite)

This directory contains the operational layer that converts raw detections into
actions: alert triage, OSINT enrichment, detection-health metrics, and
remediation playbooks.

## Components

| Module | Purpose |
| :--- | :--- |
| `metrics.py` | Computes detection KPIs from `detection/logs/alerts.json` (per-rule volumes, unique sources, MTTD estimates). Writes `detection/logs/metrics.json` for SIEM dashboards. |
| `enrichment.py` | OSINT enrichment of alert source IPs (ASN/owner via Team Cymru, country via reverse DNS). No API keys required. |
| `playbooks/auto_block_ip.py` | Containment playbook: automatically blocks repeat unauthorized-Modbus-write offenders (threshold: 3 writes / 5 min) with an iptables DROP on the zone gateway. Dry-run and unblock modes included. |
| `playbooks/webhook_receiver.py` | Alertmanager webhook receiver: persists SIEM alerts to `detection/logs/siem_alerts.json`, bridging Loki alerting and downstream playbooks. |

## Alerting Flow

```
Gateway IDS ──NDJSON──▶ Promtail ──▶ Loki (alerting rules) ──▶ Alertmanager
                                                                    │
                                                     webhook (9095)▼
                                              webhook_receiver.py
                                                                    │
                                                     playbooks (auto-block, enrichment)
```

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
