# Detection & Monitoring Rules

This directory contains the custom Python-based detection logic (protocol-aware
anomaly detection) that runs as **persistent services inside the `ot_gateway`**
container — the L3/L4 chokepoint that observes all inter-zone traffic. The rules
are launched automatically on gateway startup by `lab-environment/scripts/start_ids.sh`.

## 1. Rule Overview

| Script | Tactic | Technique | Description |
| :--- | :--- | :--- | :--- |
| `modbus_anomaly.py` | Manipulation of Control | **T0831** | Detects unauthorized Modbus Write commands (FC 6/16) from sources outside the authorized set (HMI `172.22.0.10`, EWS `172.23.0.4`). |
| `process_safety_violation.py` | Inhibit Response / Impair Process Control | **T0836** | Stateful process shadowing: alerts when a safety interlock would be violated (e.g., opening the inlet valve while tank level > 90%). Shadows the **live** level from real PLC→HMI Modbus responses (register map in `plc/register-map.md`). |
| `cross_zone_traffic.py` | Lateral Movement | **T0886** | Detects direct IP communication between Level 4 (IT `172.24.0.0/24`) and Level 1 (Control `172.21.0.0/24`). |
| `ot_brute_force.py` | Reconnaissance | **T0846** | Sliding-window detection of high-frequency Modbus Exception codes (FC > 128), indicating scanning/brute-force. |
| `firewall_events.py` | (telemetry) | — | Ships a normalized `ot_firewall` event to Loki for each new cross-zone flow the conduit policy denies, so the generated detection bundle in `siem/rules/` can evaluate firewall drops. |
| `dnp3_dpi.py` | Manipulation of Control / Inhibit Response / Discovery | **T1692.001, T0816, T0878** | Live DNP3 decoder (link/transport/application). Ships the `ot_ndr`/`dnp3` contract to Loki and writes unauthorized-control, cold/warm-restart and disable-unsolicited alerts. |
| `opcua_dpi.py` | Discovery / Manipulation of Control / Execution | **T0888, T1692.001, T0871** | Live OPC UA decoder (message header + service NodeId). Ships the `ot_ndr`/`opcua` contract and writes browse, write and method-call alerts. Only plaintext (None/Sign) channels expose the service. |
| `s7comm_dpi.py` | Collection / Manipulation of Control / Inhibit Response | **T0843, T0845, T0858** | Live S7comm decoder (TPKT/COTP/S7). Ships the `ot_ndr`/`s7comm` contract and writes program download, program upload and PLC control/stop alerts. |
| `responder.py` | (containment) | **T0831** | Gateway-side SOAR responder: DROPs a source that repeatedly issues unauthorized writes (3 / 5 min). Dry-run by default; `OT_RESPONDER_ENFORCE=1` arms it. |

### 1.1 Live telemetry producers

The `*_dpi.py` rules are **normalized telemetry producers**, not just detectors.
Each decoded message is pushed to Loki as a `logfmt` line (`job="ot_ndr"`, one
`service` per protocol) using the exact field names of the detection telemetry
contract, so the generated ruler rules in `siem/rules/ot_*.yaml` evaluate live
lab traffic rather than replayed captures. The same rules append `alert_type`
NDJSON to `detection/logs/alerts.json` for evidence and the compliance gate.

The decoders live in `detection/rules/otdpi/` (one pure function per protocol,
unit tested without a sniffer); the top-level `*_dpi.py` modules own the capture
and the sinks. All rules capture every non-loopback gateway interface
(`otdpi.common.capture_interfaces()`), because the gateway is a multi-homed
chokepoint and `sniff(iface=None)` would only bind the default route.


## 2. Logic Implementation

The scripts use the `Scapy` library for passive network sniffing.

- **Deep Packet Inspection (DPI):** `modbus_anomaly.py` parses the MBAP header to
  identify the Function Code (offset index 7) and only inspects Modbus/TCP (port 502).
- **Allow-listing:** Only the HMI (`172.22.0.10`) and EWS (`172.23.0.4`) are
  authorized write sources. Unknown or unparseable source IPs are treated as
  untrusted (fail-safe).
- **Sliding Window:** `ot_brute_force.py` uses a 60-second sliding window
  (threshold: 5 exceptions) before alerting; state is reset after each alert.
- **Stateful Shadowing:** `process_safety_violation.py` maintains a shadow copy of
  the PLC register state, learned passively from real PLC-to-HMI read (FC 3)
  responses, and evaluates safety logic against it — protocol-valid commands can
  still trigger a cyber-safety alert. FC 6/16 writes are decoded from the real
  PDU (holding-register map documented in `plc/register-map.md`).
- **Configurability:** All thresholds and network definitions can be overridden
  with environment variables (`OT_*`), enabling tuning without code changes.

## 3. Centralized Logging

All rules write structured JSON alerts to `detection/logs/alerts.json`
(one JSON object per line, NDJSON). The file is ingested by Promtail and shipped
to Loki for SIEM visualization and alerting (`siem/`).

## 4. Testability & Quality

- Every rule exposes its packet-processing logic (`process_packet`) without
  starting a sniffer, enabling deterministic unit tests.
- The full test suite lives in `tests/` (run with `pytest`); the CI pipeline
  (`ci.yml`) enforces linting (ruff), static analysis (bandit), and the tests.
- The `Compliance Gate` workflow boots the lab, runs the attack simulations, and
  asserts that each rule produced the expected alerts.

## 5. Sample Alerts & Evidence

- `detection/logs/alerts.json` — live evidence captured during attack simulations.
- `detection/sample-alerts/alerts_sample.json` — curated examples of each alert type.
- `detection/logs/edr_sysmon_sample.json` — **synthetic** endpoint (Sysmon-style)
  telemetry used to demonstrate EDR-log correlation in the SIEM dashboard; it is a
  handcrafted sample, not output from a real endpoint agent.
