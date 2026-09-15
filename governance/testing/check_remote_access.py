#!/usr/bin/env python3
"""Assert the DMZ -> EWS remote-engineering hop works and is key-only.

Proves conduit C11: the bastion (DMZ) re-initiates an SSH session into the EWS
(Operations) using the keypair it generated at boot. Expects the lab to be up.

Usage:
    python3 governance/testing/check_remote_access.py
"""
import subprocess
import sys

BASTION = "ot_bastion"
EWS_IP = "172.23.0.4"
MARKER = "REMOTE_OK"


def main() -> int:
    result = subprocess.run(
        [
            "docker", "exec", BASTION,
            "ssh", "-i", "/home/engineer/.ssh/id_ed25519",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            f"engineer@{EWS_IP}", f"echo {MARKER}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or MARKER not in result.stdout:
        print(
            f"[FAIL] bastion -> EWS hop failed (rc={result.returncode}): "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )
        return 1
    print("[PASS] bastion -> EWS SSH hop (key-only) reached the engineering workstation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
