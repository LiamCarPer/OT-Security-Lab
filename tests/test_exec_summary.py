"""The executive summary must be the generated document, not a fabricated one."""
import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "governance" / "testing")
)

import generate_exec_summary as gen  # noqa: E402


def test_summary_matches_generated_output():
    expected = gen.render(gen.compute())
    actual = gen.OUTPUT.read_text(encoding="utf-8")
    assert actual == expected, (
        "governance/executive/executive-summary.md is stale; run "
        "`python3 governance/testing/generate_exec_summary.py`"
    )


def test_summary_has_no_placeholder_ips():
    data = gen.compute()
    text = gen.OUTPUT.read_text(encoding="utf-8")
    # Source addresses in the summary must be real lab addresses.
    for source in data["sources"]:
        assert source in text
    assert "172.26." not in text  # historical fabricated address
