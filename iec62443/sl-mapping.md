# IEC 62443 Security Level (SL) Mapping

This document explains the Security Level (SL) targets and achieved levels for each zone in the `ot-security-lab`, based on the definitions in **IEC 62443-3-3**.

## 1. Understanding SL-T, SL-C, and SL-A
- **SL-T (Target):** The desired security level for a zone based on risk assessment.
- **SL-C (Capability):** The security level that the assets/system *can* achieve if configured correctly.
- **SL-A (Achieved):** The current actual security level based on implemented and verified controls.

## 2. Security Level Definitions
| Level | Description |
| :--- | :--- |
| **SL-1** | Protection against casual or coincidental violation. |
| **SL-2** | Protection against intentional violation using simple means with low resources. |
| **SL-3** | Protection against intentional violation using sophisticated means with moderate resources. |
| **SL-4** | Protection against intentional violation using sophisticated means with extended resources. |

## 3. Lab Zone Mapping
| Zone | Target (SL-T) | Achieved (SL-A) | Justification |
| :--- | :--- | :--- | :--- |
| **Control (L1)** | SL-3 | **SL-2** | Achieved via network isolation and firewalling. Gap to SL-3: Lack of host-based integrity protection on PLCs. |
| **Supervisory (L2)** | SL-2 | **SL-2** | Achieved via multi-homed isolation and user authentication (Scada-LTS). |
| **Operations (L3)** | SL-2 | **SL-2** | Achieved via iDMZ chokepoint and Historian isolation. |
| **Enterprise (L4/5)** | SL-1 | **SL-1** | Standard corporate security posture assumed. |

## 4. Path to SL-3
To move the Control Zone from SL-2 to SL-3, the following would be required:
- Implementation of **Secure Boot** and hardware root-of-trust on PLCs.
- Use of **encrypted industrial protocols** (e.g., Modbus/TCP Security or CIP Security) to prevent sniffing and tampering.
- Implementation of **Centralized Configuration Management** with cryptographic signing for ladder logic updates.
