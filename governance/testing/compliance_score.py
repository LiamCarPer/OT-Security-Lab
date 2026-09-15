#!/usr/bin/env python3
"""Compute the IEC 62443-3-3 implementation score from the gap analysis.

Scoring method (documented, reproducible):
  Implemented = 1.0, Partial = 0.5, Simulated = 0.0, N/A = excluded from the
  denominator. Score = sum(weight) / count(scored requirements) * 100.

Run:  python3 governance/testing/compliance_score.py
The value is asserted by tests/test_compliance_score.py and quoted in
iec62443/compliance-summary.md, so the document cannot drift from the data.
"""
import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GAP_ANALYSIS = REPO_ROOT / "iec62443" / "gap-analysis.csv"
WEIGHTS = {"Implemented": 1.0, "Partial": 0.5, "Simulated": 0.0}


def compute() -> dict:
    rows = list(csv.DictReader(GAP_ANALYSIS.open(encoding="utf-8")))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    scored = [row for row in rows if row["status"] != "N/A"]
    earned = sum(WEIGHTS.get(row["status"], 0.0) for row in scored)
    percent = round(100.0 * earned / len(scored), 1) if scored else 0.0
    return {
        "total_requirements": len(rows),
        "scored_requirements": len(scored),
        "counts": counts,
        "percent": percent,
    }


def main() -> None:
    print(json.dumps(compute(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
