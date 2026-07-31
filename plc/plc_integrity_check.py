#!/usr/bin/env python3
"""PLC logic integrity verification (golden manifest).

Computes the SHA-256 of each deployed PLC logic file and compares it against
the golden manifest. A mismatch indicates unauthorized logic modification
(MITRE ATT&CK for ICS T0853 - Program Upload / T0872 - Modification of
Controller Logic), which is the trigger scenario of the incident-response
playbook (incident-response/ir-playbook-unauthorised-plc-change.md).

In production, the golden baseline would be the read-back of the program
from the PLC (OpenPLC exposes the running program via its web API); in this
lab the manifest verifies the golden files that would be uploaded.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

PLC_DIR = Path(__file__).resolve().parent
MANIFEST = PLC_DIR / "manifest.json"

def sha256_of(path):
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()

def load_manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))

def verify(manifest):
    results = {}
    for plc, info in sorted(manifest.items()):
        program = PLC_DIR.parent / info["program"]
        if not program.exists():
            results[plc] = "MISSING"
            continue
        digest = sha256_of(program)
        results[plc] = "OK" if digest == info["sha256"] else "TAMPERED"
    return results

def update_manifest():
    manifest = {}
    for st_file in sorted(PLC_DIR.glob("*.st")):
        manifest[st_file.stem] = {
            "program": f"plc/{st_file.name}",
            "sha256": sha256_of(st_file),
        }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest

def main():
    parser = argparse.ArgumentParser(description="PLC logic integrity verification")
    parser.add_argument("--update", action="store_true", help="Regenerate the golden manifest")
    parser.add_argument("--alert-log", default=None, help="Append tamper alerts to this NDJSON file")
    args = parser.parse_args()

    if args.update:
        update_manifest()
        print(f"[OK] Manifest updated: {MANIFEST}")
        return 0

    manifest = load_manifest()
    results = verify(manifest)

    all_ok = True
    for plc, status in results.items():
        print(f"{plc:<20} {status}")
        all_ok = all_ok and status == "OK"

    if not all_ok and args.alert_log:
        from datetime import datetime
        with open(args.alert_log, "a", encoding="utf-8") as f:
            for plc, status in results.items():
                if status != "OK":
                    entry = {
                        "timestamp": datetime.now().isoformat(),
                        "alert_type": "PLC_LOGIC_TAMPERED",
                        "plc": plc,
                        "status": status,
                        "mitre_id": "T0853",
                        "description": "PLC logic integrity verification failed.",
                    }
                    f.write(json.dumps(entry) + "\n")
        print(f"[ALERT] Integrity failure appended to {args.alert_log}")

    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
