# IEC 62443-3-2: Zone & Conduit Design

In accordance with IEC 62443-3-2, this document defines the security zones and the conduits (communication paths) that connect them within our simulated Water Treatment Facility.

## 1. Security Zones
Each zone is a grouping of logical or physical assets that share common security requirements.

| Zone Name | Purdue Level | Description | Target SL (SL-T) | Primary Assets |
| :--- | :--- | :--- | :--- | :--- |
| **Enterprise Zone** | 4/5 | Corporate IT infrastructure and external access. | SL-1 | Attacker Simulator, VPN Gateway. |
| **Operations Zone** | 3 | Data aggregation and engineering workstations. | SL-2 | Historian (InfluxDB), EWS. |
| **Supervisory Zone** | 2 | Real-time monitoring and operator interface. | SL-2 | HMI (Scada-LTS). |
| **Control Zone** | 1 | Real-time logic execution and control. | SL-3 | OpenPLC. |
| **Field Zone** | 0 | Physical sensors and actuators. | SL-1 | Simulated Valve, Flow Meter. |

The conduits below are the single source of truth and map 1:1 to the rules
applied by `lab-environment/network-config/firewall-rules.sh` on the gateway.

## 2. Conduits

### C1: HMI-to-PLC (Supervisory → Control)
*   **Source Zone:** Supervisory Zone (Level 2) — Scada-LTS `172.22.0.10`
*   **Destination Zone:** Control Zone (Level 1) — PLCs `172.21.0.10-12`
*   **Protocol:** Modbus/TCP (Port 502)
*   **Requirement:** Operator read/write access to controller holding registers.

### C2: Historian Data Collection (Operations → Control)
*   **Source Zone:** Operations Zone (Level 3) — Historian `172.23.0.10`
*   **Destination Zone:** Control Zone (Level 1)
*   **Protocol:** Modbus/TCP (Port 502)
*   **Requirement:** Read-only process data collection.

### C3: HMI-to-Historian (Supervisory → Operations)
*   **Source Zone:** Supervisory Zone (Level 2)
*   **Destination Zone:** Operations Zone (Level 3)
*   **Protocol:** InfluxDB (Port 8086)
*   **Requirement:** Process telemetry written to the historian.

### C4: Corporate Reporting (Enterprise → Operations)
*   **Source Zone:** Enterprise Zone (Level 4)
*   **Destination Zone:** Operations Zone (Level 3)
*   **Protocol:** InfluxDB (Port 8086)
*   **Requirement:** Read-only reporting; no path from IT to the Control Zone.

### C5: Engineering Deployment (Operations → Control)
*   **Source Zone:** Operations Zone (Level 3) — EWS/provisioning host `172.23.0.4`
*   **Destination Zone:** Control Zone (Level 1)
*   **Protocol:** OpenPLC runtime API (Port 8443, HTTPS)
*   **Requirement:** The engineering workstation may push compiled logic to the
  controllers, but is denied Modbus (502) access. Deployment only.

---

## 3. Communication Constraints & Segmentation Rules
1.  **Strict Isolation:** No direct communication is allowed between Level 4 (Enterprise) and Level 1 (Control). This is the most critical conduit violation.
2.  **Default Deny:** All conduits follow a "Default Deny" policy. Only explicitly defined ports/protocols for technical communication are permitted.
3.  **Authentication:** Any administrative access (SSH, RDP) must terminate in the Operations Zone for logging and MFA before jumping to lower levels.
