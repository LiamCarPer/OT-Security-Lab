# Hardening Guide: Industrial Gateway (Linux)
**Standard Alignment:** NIST SP 800-82, ISA/IEC 62443-3-3, DISA STIG (RHEL/Ubuntu)

## 1. Overview
This document outlines the hardening (bastionado) procedures for the **Industrial Gateway (ot_gateway)** container, which serves as the trust boundary between the IT Network (Level 4) and the Ops/Control Networks (Level 3/2).

## 2. Hardening Controls (STIG-Derived)

### [ID: OT-GW-01] Network Interface Isolation
- **Control:** The gateway must maintain strict interface separation.
- **Implementation:** 
    - `eth0`: IT_NETWORK (Static IP: 172.24.0.2)
    - `eth1`: OPS_NETWORK (Static IP: 172.23.0.2)
    - `eth2`: SUPERVISORY_NETWORK (Static IP: 172.22.0.2)
    - `eth3`: CONTROL_NETWORK (Static IP: 172.21.0.2)
- **STIG Mapping:** V-204434 (IP Forwarding restricted to specific interfaces).

### [ID: OT-GW-02] Least-Privilege Routing (Conduits)
- **Control:** IP Forwarding is disabled by default and enabled ONLY for specific conduits.
- **Implementation:** 
    - DROP ALL traffic by default (IPTables Policy).
    - ALLOW Modbus (TCP/502) only from HMI (172.23.0.5) to PLCs (172.21.0.10-12).
    - DENY all traffic from Control Zone to IT Zone.

### [ID: OT-GW-03] Service Minimization
- **Control:** Only essential services shall run on the gateway.
- **Implementation:**
    - Removal of `ssh`, `telnet`, `ftp`, and `http` from the gateway base image.
    - Only the `detection-engine` (Python) and `iptables` are permitted active processes.

### [ID: OT-GW-04] Secure Logging (Centralized)
- **Control:** Audit logs must be immediately off-loaded to a secure sink.
- **Implementation:**
    - Security alerts are written to `/logs/alerts.json` (Host-mounted volume).
    - Logs are ingested by **Promtail** and sent to **Loki** in Level 4.
- **STIG Mapping:** V-204523 (Off-load logs to central server).

---

## 3. Verification Checklist

| Check ID | Control Name | Status | Verified By |
| --- | --- | --- | --- |
| OT-VER-01 | Ping IT to Control (Blocked) | [x] | `simulate_attack.py` |
| OT-VER-02 | Modbus PLC to HMI (Allowed) | [x] | `simulate_process_violation.py` |
| OT-VER-03 | No SSH active on 172.23.0.2 | [x] | `nmap -p 22` |

---

## 4. PLC-Level Hardening (Compensating Controls)
- **Problem:** Many legacy PLCs (including OpenPLC) lack native encryption or authentication for the Modbus protocol.
- **Strategy:** Implementation of **Compensating Controls** at the Gateway Conduit.
- **Rules:**
    - Disable all unused PLC ports (e.g., HTTP/8080) if they are not required for SCADA.
    - Change Default Admin Passwords on the PLC web interface (OpenPLC: `openplc`/`openplc`).
    - Enable **Read-Only Mode** on the Modbus server where physical control is not required.

---

## 5. Maintenance & Compliance
This guide shall be reviewed quarterly or upon significant network changes in accordance with **MAGERIT** periodic risk reviews.
