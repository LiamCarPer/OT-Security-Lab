# IEC 62443-3-2: Zone & Conduit Design

In accordance with IEC 62443-3-2, this document defines the security zones and the conduits (communication paths) that connect them within our simulated Water Treatment Facility.

## 1. Security Zones
Each zone is a grouping of logical or physical assets that share common security requirements.

| Zone Name | Purdue Level | Description | Target SL (SL-T) | Primary Assets |
| :--- | :--- | :--- | :--- | :--- |
| **Enterprise Zone** | 4/5 | Corporate IT infrastructure and external access. | SL-1 | Attacker Simulator, Corporate Workstation. |
| **Industrial DMZ** | 3.5 | Boundary zone: remote access and proxied operator UI. | SL-2 | Reverse Proxy, Jump Host/Bastion. |
| **Operations Zone** | 3 | Data aggregation and engineering workstations. | SL-2 | Historian (InfluxDB), EWS. |
| **Supervisory Zone** | 2 | Real-time monitoring and operator interface. | SL-2 | HMI (Scada-LTS), historian collector. |
| **Control Zone** | 1 | Real-time logic execution and control. | SL-3 | OpenPLC, DNP3/OPC UA/S7comm endpoints. |
| **Field Zone** | 0 | Physical sensors and actuators. | SL-1 | Simulated Valve, Flow Meter. |

The conduits below are the single source of truth and map 1:1 to the rules
applied by `lab-environment/network-config/firewall-rules.sh` on the gateway.

## 2. Conduits

### C1: HMI-to-PLC (Supervisory → Control)
*   **Source Zone:** Supervisory Zone (Level 2) — Scada-LTS `172.22.0.10`
*   **Destination Zone:** Control Zone (Level 1) — PLCs `172.21.0.10-12`
*   **Protocol:** Modbus/TCP (Port 502)
*   **Requirement:** Operator read/write access to controller holding registers.

### C2: Direct Historian Collection (Operations → Control) — not used
*   **Status:** Removed. The historian host has **no L3 → L1 path**; the L2
  collector reads the controllers over C1 and writes the historian northbound
  over C3. This keeps the tiered data architecture (ADR-02) one-directional with
  respect to the historian.

### C3: HMI-to-Historian (Supervisory → Operations)
*   **Source Zone:** Supervisory Zone (Level 2)
*   **Destination Zone:** Operations Zone (Level 3)
*   **Protocol:** InfluxDB (Port 8086)
*   **Requirement:** The L2 historian collector (`historian-poller`) writes the
  process values northbound to the InfluxDB historian (measurement
  `process_state`, 30-day retention).

### C4: Corporate Reporting (Enterprise → Operations)
*   **Source Zone:** Enterprise Zone (Level 4)
*   **Destination Zone:** Operations Zone (Level 3)
*   **Protocol:** InfluxDB (Port 8086)
*   **Requirement:** Read-only reporting; no path from IT to the Control Zone.

### C5: Engineering Deployment (Operations → Control)
*   **Source Zone:** Operations Zone (Level 3) — EWS `172.23.0.4`
*   **Destination Zone:** Control Zone (Level 1)
*   **Protocol:** OpenPLC runtime API (Port 8443, HTTPS)
*   **Requirement:** Source-restricted to the EWS `172.23.0.4`: it may push
  compiled logic to the controllers, but is denied Modbus (502) access.

### C6: DNP3 Polling (Operations → Control)
*   **Source Zone:** Operations Zone (Level 3) — insider `172.23.0.20`
*   **Destination Zone:** Control Zone (Level 1) — DNP3 outstation `172.21.0.50`
*   **Protocol:** DNP3/TCP (Port 20000)
*   **Requirement:** Source-restricted to `172.23.0.20`. The DNP3 application
  security rule authorizes specific master link addresses; the IDS flags others.

### C7: OPC UA Client Access (Operations → Control)
*   **Source Zone:** Operations Zone (Level 3) — insider `172.23.0.20`
*   **Destination Zone:** Control Zone (Level 1) — OPC UA server `172.21.0.51`
*   **Protocol:** OPC UA/TCP (Port 4840)
*   **Requirement:** Source-restricted to `172.23.0.20`. Plaintext (`None`)
  policy in the lab so the service layer is observable.

### C8: S7comm Engineering Access (Operations → Control)
*   **Source Zone:** Operations Zone (Level 3) — insider `172.23.0.20`
*   **Destination Zone:** Control Zone (Level 1) — S7comm server `172.21.0.52`
*   **Protocol:** S7comm/TCP (Port 102)
*   **Requirement:** Source-restricted to `172.23.0.20`. Siemens engineering
  access (read/write, program download/upload, PLC control).

### C9: Corporate Access to the DMZ (Enterprise → DMZ)
*   **Source Zone:** Enterprise Zone (Level 4/5) — corporate workstation `172.24.0.30`
*   **Destination Zone:** Industrial DMZ (Level 3.5) — reverse proxy `172.25.0.10`, bastion `172.25.0.11`
*   **Protocol:** HTTP (Port 80), SSH (Port 22)
*   **Requirement:** Corporate clients reach the operator UI and the jump host
  only through the DMZ.

### C10: DMZ to Supervisory (DMZ → Supervisory)
*   **Source Zone:** Industrial DMZ (Level 3.5) — reverse proxy `172.25.0.10`
*   **Destination Zone:** Supervisory Zone (Level 2) — HMI `172.22.0.10`
*   **Protocol:** HTTP (Port 8080)
*   **Requirement:** The proxy fronts the operator interface; the HMI itself is
  never exposed to the Enterprise zone.

### Single chokepoint (no bypass)
Every OT service is single-homed on its zone network and routes other zones'
traffic through the gateway; the gateway is the only multi-homed container. The
HMI, collector, EWS, insider and the controllers (via route sidecars) all use
static routes via the gateway, so inter-zone traffic is enforced and observed at
the chokepoint. `tests/test_zone_isolation.py` asserts these invariants (only
the gateway is multi-homed; OT zones are internal; the firewall is default-deny).


### Host access to OT services
The OT networks (`ops_network`, `supervisory_network`, `control_network`) are
Docker `internal` networks, so Docker does not publish their ports on the host.
The Enterprise and DMZ boundary zones are not internal: Grafana/Loki are
host-published directly, and the **DMZ reverse proxy** publishes the operator UI
on host `:8080` (proxied to the HMI via C10). InfluxDB and Scada-LTS themselves
are reached through the gateway or inspected with `docker exec`. This is a
deliberate consequence of the segmentation, not a misconfiguration.

---

## 3. Communication Constraints & Segmentation Rules
1.  **Strict Isolation:** No direct communication is allowed between Level 4 (Enterprise) and Level 1 (Control). This is the most critical conduit violation.
2.  **Default Deny:** All conduits follow a "Default Deny" policy. Only explicitly defined ports/protocols for technical communication are permitted.
3.  **Authentication:** Any administrative access (SSH, RDP) must terminate in the Operations Zone for logging and MFA before jumping to lower levels.
