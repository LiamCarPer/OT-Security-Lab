"""The compliance-summary percentage must match the computed gap-analysis score."""
import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "governance" / "testing")
)

import compliance_score  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY = REPO_ROOT / "iec62443" / "compliance-summary.md"


def test_score_matches_gap_analysis():
    result = compliance_score.compute()
    # 6 Implemented + 4 Partial(0.5) = 8 / 11 scored = 72.7%
    assert result["total_requirements"] == 12
    assert result["counts"]["Implemented"] == 6
    assert result["percent"] == 72.7


def test_summary_quotes_the_computed_percentage():
    text = SUMMARY.read_text(encoding="utf-8")
    expected = f"{compliance_score.compute()['percent']}%"
    assert expected in text, f"compliance-summary.md must quote {expected}"
