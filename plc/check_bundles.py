#!/usr/bin/env python3
"""Fail if the committed PLC bundles differ in *content* from a fresh build.

The `.zip` container is not guaranteed byte-identical across `zip`
implementations and build environments (entry ordering, permission bits,
archive metadata), so drift is checked on the meaningful payload: the sorted set
of file entries and the SHA-256 of each entry's contents.

Run after `plc/build.sh` (which overwrites `plc/programs/*/program.zip`); the
committed version is read from `HEAD`. Exit status is 1 if any bundle differs.
"""
import difflib
import hashlib
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

PLC_DIR = Path(__file__).resolve().parent
REPO_ROOT = PLC_DIR.parent
PROGRAMS_DIR = PLC_DIR / "programs"


def manifest(blob: bytes) -> dict:
    with zipfile.ZipFile(BytesIO(blob)) as archive:
        return {
            info.filename: hashlib.sha256(archive.read(info.filename)).hexdigest()
            for info in archive.infolist()
            if not info.is_dir()
        }


def entry(blob: bytes, name: str) -> bytes:
    with zipfile.ZipFile(BytesIO(blob)) as archive:
        return archive.read(name)


def text_diff(before: bytes, after: bytes, name: str, limit: int = 40) -> str:
    """A short unified diff of two (usually text) entries, for CI logs."""
    before_lines = before.decode("utf-8", "replace").splitlines()
    after_lines = after.decode("utf-8", "replace").splitlines()
    diff = list(
        difflib.unified_diff(before_lines, after_lines, f"HEAD:{name}", f"rebuild:{name}", lineterm="")
    )
    if len(diff) > limit:
        diff = diff[:limit] + [f"... ({len(diff) - limit} more differing lines)"]
    return "\n".join(diff)


def committed_zip(relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"HEAD:{relative}"], cwd=REPO_ROOT, capture_output=True
    )
    if result.returncode != 0:
        raise SystemExit(f"cannot read {relative} from HEAD: {result.stderr.decode().strip()}")
    return result.stdout


def main() -> int:
    programs = sorted(p.name for p in PROGRAMS_DIR.glob("*") if (p / "program.zip").is_file())
    if not programs:
        raise SystemExit("no bundles found under plc/programs/")

    failed = False
    for program in programs:
        relative = f"plc/programs/{program}/program.zip"
        committed_blob = committed_zip(relative)
        rebuilt_blob = (PROGRAMS_DIR / program / "program.zip").read_bytes()
        committed = manifest(committed_blob)
        rebuilt = manifest(rebuilt_blob)

        changed = sorted(
            filename
            for filename in set(committed) & set(rebuilt)
            if committed[filename] != rebuilt[filename]
        )
        added = sorted(set(rebuilt) - set(committed))
        removed = sorted(set(committed) - set(rebuilt))

        if not (changed or added or removed):
            print(f"{relative}: up to date ({len(committed)} entries)")
            continue

        failed = True
        for filename in removed:
            print(f"{relative}: missing from rebuild: {filename}")
        for filename in added:
            print(f"{relative}: new in rebuild: {filename}")
        for filename in changed:
            print(f"{relative}: content changed: {filename}")
            print(text_diff(entry(committed_blob, filename), entry(rebuilt_blob, filename), filename))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
