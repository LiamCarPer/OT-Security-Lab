# IEC 62443-3-2: Zone & Conduit Design

In accordance with IEC 62443-3-2, this document defines the security zones and the conduits (communication paths) that connect them within our simulated Water Treatment Facility.

## 1. Security Zones
Each zone is a grouping of logical or physical assets that share common security requirements.

| Zone Name | Purdue Level | Description | Target SL (SL-T) | Primary Assets |
| :--- | :--- | :--- | :--- | :--- |
| **Enterprise Zone** | 4/5 | Corporate IT infrastructure and external access. | SL-1 | Attacker Simulator, VPN Gateway. |
| **Operations Zone** | 3 | Data aggregation and engineering workstations. | SL-2 | Historian (InfluxDB), EWS. |
| **Supervisory Zone** | 2 | Real-time monitoring and operator interface. | SL-2 | HMI (ScadaBR). |
| **Control Zone** | 1 | Real-time logic execution and control. | SL-3 | OpenPLC. |
| **Field Zone** | 0 | Physical sensors and actuators. | SL-1 | Simulated Valve, Flow Meter. |

---

## 2. Conduits
Conduits are the communication paths between zones. These are the "chokepoints" where security controls are applied.

### C1: HMI-to-PLC Communication (Supervisory → Control)
*   **Source Zone:** Supervisory Zone (Level 2)
*   **Destination Zone:** Control Zone (Level 1)
*   **Protocol:** Modbus/TCP (Port 502)
*   **Requirement:** Inbound Modbus traffic is only permitted from the HMI IP.
*   **Target SL:** SL-3

### C2: Historian Data Collection (Control → Operations)
*   **Source Zone:** Control Zone (Level 1)
*   **Destination Zone:** Operations Zone (Level 3)
*   **Protocol:** Modbus/TCP (Read-only) / HTTP
*   **Requirement:** Level 3 assets must not have direct "Write" access to Level 1.

### C3: Corporate Monitoring (Operations → Enterprise)
*   **Source Zone:** Operations Zone (Level 3)
*   **Destination Zone:** Enterprise Zone (Level 4)
*   **Protocol:** HTTPS / MQTT
*   **Requirement:** Data must pass through a DMZ. No direct access from IT to OT.

---

## 3. Communication Constraints & Segmentation Rules
1.  **Strict Isolation:** No direct communication is allowed between Level 4 (Enterprise) and Level 1 (Control). This is the most critical conduit violation.
2.  **Default Deny:** All conduits follow a "Default Deny" policy. Only explicitly defined ports/protocols for technical communication are permitted.
3.  **Authentication:** Any administrative access (SSH, RDP) must terminate in the Operations Zone for logging and MFA before jumping to lower levels.
