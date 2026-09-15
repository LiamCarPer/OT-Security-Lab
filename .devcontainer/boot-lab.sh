#!/bin/bash
# Boots the full OT lab inside a Codespace.
# First boot builds the gateway/attacker images and pulls the stack (~5-10 min).
set -e

LAB_DIR="$(cd "$(dirname "$0")/../lab-environment" && pwd)"

echo "[LAB] Building and booting the OT lab..."
cd "$LAB_DIR"
docker compose up -d --build

echo ""
echo "[LAB] Lab is up. Services:"
echo "      Grafana      -> http://localhost:3000"
echo "      SCADA HMI    -> http://localhost:8080"
echo "      Alertmanager -> http://localhost:9093"
echo "      (the PLC runtime API is internal to the Control zone; the EWS deploys over it)"
echo ""
echo "[LAB] Validate the environment:"
echo "      python3 governance/testing/run_security_tests.py --reset"
echo "      or: make compliance"
