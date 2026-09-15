"""Guard against unsupported absolute claims in the documentation.

A portfolio repository's credibility depends on claims being verifiable. This
test fails if a document asserts an unqualified absolute ("100% implemented",
"fully enforced", "no false positives") outside the files that legitimately
discuss such claims (the claims register and the generated changelog). When a
control really is complete, state the scope and evidence instead.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN = [
    re.compile(r"100%\s+(implemented|aligned|complete|coverage)", re.IGNORECASE),
    re.compile(r"fully\s+implemented", re.IGNORECASE),
    re.compile(r"fully\s+enforced", re.IGNORECASE),
    re.compile(r"(no|zero)\s+false\s+positives", re.IGNORECASE),
]

# Files that may discuss the forbidden claims (the register itself and the
# generated changelog are not asserting them as present-tense facts).
ALLOWED = {"CLAIMS.md", "CHANGELOG.md"}
SKIP_DIRS = {".git", ".pytest_cache", "node_modules", ".ruff_cache"}


def _markdown_files():
    for path in REPO_ROOT.rglob("*.md"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in ALLOWED:
            continue
        yield path


def test_no_unsupported_absolute_claims():
    violations = []
    for path in _markdown_files():
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for pattern in FORBIDDEN:
                if pattern.search(line):
                    rel = path.relative_to(REPO_ROOT)
                    violations.append(f"{rel}:{line_number}: {line.strip()}")
    assert not violations, (
        "Unsupported absolute claims (scope the claim and cite evidence, or add "
        "the file to CLAIMS.md):\n" + "\n".join(violations)
    )
