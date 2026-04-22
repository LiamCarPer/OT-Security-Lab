# OT Security Lab: Hardening Checklist

This document details the specific security configurations and compensating controls applied to each asset in the `ot-security-lab` environment.

## 1. Network Hardening (Applied to `ot_gateway`)
| Control ID | Control Description | Implementation Status | Justification |
| :--- | :--- | :--- | :--- |
| **NW-1.1** | **Default-Deny Policy:** All inter-zone traffic is dropped unless explicitly permitted. | **Implemented** | Enforces strict segmentation between Purdue levels. |
| **NW-1.2** | **Conduit Control:** Only Modbus/TCP (Port 502) is allowed from HMI to PLCs. | **Implemented** | Minimizes the attack surface for control protocols. |
| **NW-1.3** | **Boundary Logging:** All dropped packets at the IT/OT boundary are logged for detection. | **Implemented** | Provides visibility into unauthorized traversal attempts. |
| **NW-1.4** | **Unused Services:** Disable SSH and ICMP at the L1/L2 boundaries. | **In Progress** | Prevents lateral movement via non-control protocols. |

## 2. PLC Hardening (Applied to `plc_intake`)
| Control ID | Control Description | Implementation Status | Justification |
| :--- | :--- | :--- | :--- |
| **PLC-2.1** | **Interface Minimization:** PLC is placed on a segregated network with no internet path. | **Implemented** | Protects the critical control logic from direct external threats. |
| **PLC-2.2** | **Logic Password:** Protect PLC runtime logic with a master password. | **Simulated** | Prevents unauthorized ladder logic modification. |
| **PLC-2.3** | **Modbus Restriction:** Limit the number of allowable connections to the PLC. | **Recommended** | Mitigates resource exhaustion attacks (DDoS). |

## 3. HMI/SCADA Hardening (Applied to `ot_hmi`)
| Control ID | Control Description | Implementation Status | Justification |
| :--- | :--- | :--- | :--- |
| **HMI-3.1** | **Interface Isolation:** Multi-homed setup separates L2 management from L1 control. | **Implemented** | Ensures management traffic does not spill into the control zone. |
| **HMI-3.2** | **Default Credentials:** Remove or change the default `admin/admin` credentials. | **Required** | Prevents trivial unauthorized access to the SCADA interface. |
| **HMI-3.3** | **Login Attempt Thresholds:** Integrated with `ot_brute_force.py` for monitoring. | **Implemented** | Detects and logs credential stuffing or service scanning. |

## 4. Historian Hardening (Applied to `ot_historian`)
| Control ID | Control Description | Implementation Status | Justification |
| :--- | :--- | :--- | :--- |
| **HIST-4.1** | **One-Way Conduit:** Data is pushed from L1 to L3; no L3-to-L1 path exists. | **Implemented** | Protects PLCs if the historian is compromised. |
| **HIST-4.2** | **Token-Based Auth:** Use InfluxDB tokens for all telemetry ingestion. | **Recommended** | Ensures only authorized PLCs can post process data. |
