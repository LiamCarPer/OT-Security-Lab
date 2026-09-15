#!/usr/bin/env python3
"""Fail if the committed PLC bundles differ in *content* from a fresh build.

The `.zip` container is not guaranteed byte-identical across `zip`
implementations and build environments (entry ordering, permission bits,
archive metadata), so drift is checked on the meaningful payload: the sorted set
of file entries and the SHA-256 of each entry's contents.

Run after `plc/build.sh` (which overwrites `plc/programs/*/program.zip`); the
committed version is read from `HEAD`. Exit status is 1 if any bundle differs.
"""
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
    for name in programs:
        relative = f"plc/programs/{name}/program.zip"
        committed = manifest(committed_zip(relative))
        rebuilt = manifest((PROGRAMS_DIR / name / "program.zip").read_bytes())

        differences = []
        for entry in sorted(set(committed) - set(rebuilt)):
            differences.append(f"missing from rebuild: {entry}")
        for entry in sorted(set(rebuilt) - set(committed)):
            differences.append(f"new in rebuild: {entry}")
        for entry in sorted(set(committed) & set(rebuilt)):
            if committed[entry] != rebuilt[entry]:
                differences.append(f"content changed: {entry}")

        if differences:
            failed = True
            for message in differences:
                print(f"{relative}: {message}")
        else:
            print(f"{relative}: up to date ({len(committed)} entries)")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
