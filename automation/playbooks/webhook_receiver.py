#!/usr/bin/env python3
"""Alertmanager webhook receiver.

Receives alert notifications from the lab Alertmanager and persists them as
structured events in `detection/logs/siem_alerts.json` — the bridge between
SIEM alerting and downstream playbooks (e.g., auto_block_ip.py).

Run inside the lab:
    docker exec ot_webhook python3 /app/webhook_receiver.py
"""
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG_PATH = Path(os.getenv(
    "OT_WEBHOOK_LOG",
    Path(__file__).resolve().parents[2] / "detection" / "logs" / "siem_alerts.json",
))
HOST, PORT = "0.0.0.0", 9095  # nosec B104 - container must accept connections from Alertmanager

def persist(payload):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        for alert in payload.get("alerts", []):
            entry = {
                "received_at": datetime.now().isoformat(),
                "status": alert.get("status"),
                "alertname": alert.get("labels", {}).get("alertname"),
                "severity": alert.get("labels", {}).get("severity"),
                "mitre_id": alert.get("labels", {}).get("mitre"),
                "annotations": alert.get("annotations", {}),
            }
            f.write(json.dumps(entry) + "\n")

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
            persist(payload)
            print(f"[WEBHOOK] {len(payload.get('alerts', []))} alert(s) received")
            self.send_response(200)
        except json.JSONDecodeError as exc:
            print(f"[WEBHOOK] Invalid payload: {exc}")
            self.send_response(400)
        self.end_headers()

    def log_message(self, fmt, *args):
        print(f"[WEBHOOK] {fmt % args}")

def main():
    print(f"[WEBHOOK] Starting on {HOST}:{PORT}, writing to {LOG_PATH}", flush=True)
    try:
        HTTPServer((HOST, PORT), Handler).serve_forever()
    except Exception:
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()
