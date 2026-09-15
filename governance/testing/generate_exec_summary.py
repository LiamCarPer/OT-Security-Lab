#!/usr/bin/env python3
"""Generate the executive summary from the repository's own evidence.

The document is not hand-authored: the detection counts come from
`detection/logs/alerts.json` (machine-generated evidence), the risk figures from
`governance/risk_register.csv`, and the compliance figure from
`governance/testing/compliance_score.py`. Regenerate after the Compliance Gate
refreshes evidence:  python3 governance/testing/generate_exec_summary.py
"""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERTS = REPO_ROOT / "detection" / "logs" / "alerts.json"
RISK = REPO_ROOT / "governance" / "risk_register.csv"
OUTPUT = REPO_ROOT / "governance" / "executive" / "executive-summary.md"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compliance_score  # noqa: E402


def compute() -> dict:
    alerts = [
        json.loads(line)
        for line in ALERTS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    types = Counter(a.get("alert_type") for a in alerts)
    sources = sorted({a.get("source_ip") for a in alerts if a.get("source_ip")})
    timestamps = sorted(a["timestamp"] for a in alerts if a.get("timestamp"))
    risks = Counter(
        row["risk_level"] for row in csv.DictReader(RISK.open(encoding="utf-8"))
    )
    return {
        "alerts_total": len(alerts),
        "types": dict(types.most_common()),
        "sources": sources,
        "first": timestamps[0] if timestamps else "n/a",
        "last": timestamps[-1] if timestamps else "n/a",
        "risks": dict(risks),
        "compliance": compliance_score.compute()["percent"],
    }


def render(data: dict) -> str:
    rows = "\n".join(
        f"| `{alert_type}` | {count} |" for alert_type, count in data["types"].items()
    )
    risk_order = ("EXTREME", "HIGH", "MEDIUM", "LOW")
    risks = ", ".join(
        f"{data['risks'].get(level, 0)} {level}" for level in risk_order
    )
    return f"""# Executive Summary: OT Security Posture

> **Auto-generated** by `governance/testing/generate_exec_summary.py` from the
> repository's machine-generated evidence (`detection/logs/alerts.json`), the
> risk register, and the IEC 62443 gap analysis. It describes the lab's
> **simulated** water-treatment range, not a production engagement. Do not edit
> by hand; regenerate after the Compliance Gate refreshes evidence.

## 1. Overview
A segmented ICS environment aligned to the Purdue model and IEC 62443 protects
the simulated water treatment process across four zones (Control, Supervisory,
Operations, Enterprise), with all inter-zone traffic transiting a default-deny
gateway chokepoint and protocol-aware detection (Modbus/TCP, DNP3, OPC UA,
S7comm).

The posture is **fundamentally sound but not yet resilient**. Zoning and conduit
enforcement are implemented and test-verified; the material weaknesses are the
absence of implemented historian backups (SR_7.3, simulated) and unencrypted
control protocols (SR_4.1).

## 2. Detection Posture (evidence window: {data['first']} → {data['last']})
| Detection | Alerts |
| :--- | ---: |
{rows}
| **Total** | **{data['alerts_total']}** |

Distinct source addresses observed: {', '.join(data['sources'])}. Source:
`detection/logs/alerts.json`, aggregated by `automation/metrics.py`.

## 3. Risk Register
Registered risks by level: **{risks}** (see `governance/risk_register.csv`).

## 4. Key Performance Indicators
- **Compliance:** IEC 62443-3-3 implementation score **{data['compliance']}%**
  (weighted; see `iec62443/compliance-summary.md`).
- **Zoning:** IEC 62443-3-2 zones/conduits verified by `tests/test_zone_isolation.py`.
- **Detection:** {data['alerts_total']} alerts from {len(data['sources'])} distinct
  sources; `make compliance` asserts every scenario is detected.
- **Recovery:** RTO/RPO defined per asset in `governance/bia.md`; restore
  exercises outstanding (roadmap RD-10).

## 5. Next 90-Day Priorities
1. Automated historian backups to offline storage (SR_7.3) with a restore drill.
2. PLC-side connection limits against Modbus flooding (RD-02).
3. HMI/PLC authentication hardening: lockout, session timeouts, unique accounts.
4. Formalize change management (MOC) with master logic-hash verification.
5. Encrypted control conduits (Modbus/TCP Security or VPN).
"""


def main() -> None:
    data = compute()
    OUTPUT.write_text(render(data), encoding="utf-8")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
