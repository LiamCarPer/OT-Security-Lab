#!/usr/bin/env python3
"""Deploy committed OpenPLC v4 program bundles to the PLC runtimes.

The OpenPLC v4 runtime is headless and API-driven: it accepts an editor-built
program.zip over HTTPS, compiles it on-device, and starts the PLC. This service
runs once at lab boot and, for every committed bundle in OT_PROGRAM_DIR, drives
the full lifecycle:

    create-user -> login -> upload-file -> compile -> start-plc -> RUNNING

Bundles that are not committed are skipped with a warning so the rest of the
lab (and the simulated fallback test path) still comes up.
"""
import os
import sys
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
TARGETS = os.getenv(
    "OT_PLC_TARGETS",
    "intake=plc_intake,treatment=plc_treatment,distribution=plc_distribution",
)
PROGRAM_DIR = Path(os.getenv("OT_PROGRAM_DIR", "/programs"))
PLC_USER = os.getenv("OT_PLC_USER", "otadmin")
PLC_PASSWORD = os.getenv("OT_PLC_PASSWORD", "ot-lab-deploy")
PLC_ROLE = os.getenv("OT_PLC_ROLE", "admin")
API_PORT = int(os.getenv("OT_PLC_API_PORT", "8443"))
READY_TIMEOUT = int(os.getenv("OT_READY_TIMEOUT_S", "180"))
COMPILE_TIMEOUT = int(os.getenv("OT_COMPILE_TIMEOUT_S", "600"))
START_TIMEOUT = int(os.getenv("OT_START_TIMEOUT_S", "120"))
SENTINEL = Path("/tmp/deploy.ok")


def log(message):
    print(f"[PLC-BOOTSTRAP] {message}", flush=True)


def wait_ready(session, base):
    """Wait until the runtime HTTPS API answers (self-signed cert)."""
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        try:
            response = session.get(f"{base}/version", timeout=5)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(3)
    return False


def authenticate(session, base):
    """Create the first user (idempotent) and return a JWT access token."""
    session.post(
        f"{base}/create-user",
        json={"username": PLC_USER, "password": PLC_PASSWORD, "role": PLC_ROLE},
        timeout=10,
    )
    response = session.post(
        f"{base}/login",
        json={"username": PLC_USER, "password": PLC_PASSWORD},
        timeout=10,
    )
    response.raise_for_status()
    token = response.json().get("access_token")
    if not token:
        raise RuntimeError(f"login returned no access_token: {response.text}")
    return token


def deploy(name, host, bundle):
    base = f"https://{host}:{API_PORT}/api"
    session = requests.Session()
    session.verify = False

    log(f"{name}: waiting for runtime API at {host}...")
    if not wait_ready(session, base):
        log(f"{name}: FAILED - runtime API did not become ready")
        return False

    log(f"{name}: authenticating")
    token = authenticate(session, base)
    headers = {"Authorization": f"Bearer {token}"}

    log(f"{name}: uploading {bundle.name} ({bundle.stat().st_size} bytes)")
    with open(bundle, "rb") as handle:
        response = session.post(
            f"{base}/upload-file",
            files={"file": (bundle.name, handle, "application/zip")},
            headers=headers,
            timeout=120,
        )
    response.raise_for_status()
    payload = response.json()
    if payload.get("UploadFileFail"):
        log(f"{name}: FAILED - upload rejected: {payload['UploadFileFail']}")
        return False

    log(f"{name}: compiling on-device...")
    deadline = time.time() + COMPILE_TIMEOUT
    while time.time() < deadline:
        status = session.get(
            f"{base}/compilation-status", headers=headers, timeout=15
        ).json()
        state = status.get("status")
        if state in ("SUCCESS", "FAILED"):
            for line in status.get("logs", [])[-40:]:
                log(f"{name}:   {line}")
            if state != "SUCCESS":
                log(f"{name}: FAILED - compilation error")
                return False
            break
        time.sleep(3)
    else:
        log(f"{name}: FAILED - compilation timed out after {COMPILE_TIMEOUT}s")
        return False

    log(f"{name}: starting PLC")
    session.get(f"{base}/start-plc", headers=headers, timeout=15)

    deadline = time.time() + START_TIMEOUT
    while time.time() < deadline:
        state = session.get(f"{base}/status", headers=headers, timeout=15).json()
        if state.get("status") == "RUNNING":
            log(f"{name}: RUNNING")
            return True
        time.sleep(2)
    log(f"{name}: FAILED - PLC did not reach RUNNING")
    return False


def main():
    log(f"program directory: {PROGRAM_DIR}")
    deployed = skipped = failed = 0
    for entry in [t for t in TARGETS.split(",") if t.strip()]:
        name, _, host = entry.partition("=")
        name, host = name.strip(), host.strip()
        bundle = PROGRAM_DIR / name / "program.zip"
        if not bundle.exists():
            log(f"{name}: [SKIP] no committed bundle at {bundle}")
            skipped += 1
            continue
        if deploy(name, host, bundle):
            deployed += 1
        else:
            failed += 1

    if skipped:
        log(
            f"{skipped} PLC(s) left EMPTY (no committed program.zip); "
            "see plc/programs/README.md to build and commit bundles."
        )
    log(f"summary: deployed={deployed} skipped={skipped} failed={failed}")

    if failed:
        return 1
    SENTINEL.write_text("ok\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
