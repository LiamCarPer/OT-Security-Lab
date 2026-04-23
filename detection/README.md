# Detection & Monitoring Rules

This directory contains the custom Python-based detection logic used in the `ot_gateway` to monitor industrial traffic and identify anomalies.

## 1. Rule Overview
| Script | Tactic | Technique | Description |
| :--- | :--- | :--- | :--- |
| `modbus_anomaly.py` | Manipulation of Control | **T0831** | Detects unauthorized Modbus Write commands from non-HMI/EWS sources. |
| `cross_zone_traffic.py` | Lateral Movement | **T0886** | Detects direct IP communication between Level 4 (IT) and Level 1 (Control). |
| `ot_brute_force.py` | Reconnaissance | **T0846** | Detects high-frequency Modbus Exception codes indicating scanning/brute-force. |

## 2. Logic Implementation
The scripts use the `Scapy` library for passive network sniffing. 
- **Deep Packet Inspection (DPI):** `modbus_anomaly.py` parses the MBAP header to identify the Function Code (offset index 7).
- **Allow-listing:** Only the HMI (`172.22.0.2`) and EWS (`172.23.0.4`) are authorized to initiate writes.
- **Sliding Window:** `ot_brute_force.py` uses a 60-second sliding window to count error responses before alerting.

## 3. Centralized Logging
All scripts are configured to write alerts in a structured JSON format to:
`detection/logs/alerts.json`

This format is designed for easy integration with a SIEM (e.g., Splunk or Elastic) or visualization in a SOC dashboard.

## 4. Sample Alerts
Concrete examples of detected attack traffic can be found in:
`detection/sample-alerts/alerts_sample.json`
