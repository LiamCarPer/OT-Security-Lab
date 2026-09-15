# MITRE ATT&CK for ICS Mapping

This document maps the lab's high-priority risk scenarios and its **implemented
detections** to the **MITRE ATT&CK for ICS** matrix.

Technique IDs are validated by `tests/test_mitre_mapping.py` against the vendored
catalog `threat-model/attack_ics_catalog.json` (MITRE ATT&CK for ICS release
recorded in that file), so a stale or mistyped ID fails CI.

## 1. Scenario 1: State-Sponsored APT (Water Toxicity)
| Phase | Tactic | Technique ID | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | External Remote Services | **T0822** | Use of VPN/Jump Host for entry. |
| **Persistence** | Valid Accounts | **T0859** | Using stolen engineer credentials. |
| **Lateral Movement** | Remote Services | **T0886** | Moving from DMZ to EWS/HMI. |
| **Command & Control** | Standard Application Layer Protocol | **T0869** | Sending malicious Modbus/TCP traffic. |
| **Impact** | Manipulation of Control | **T0831** | Altering chemical dosing thresholds. |

## 2. Scenario 2: Disgruntled Insider (Pump Sabotage)
| Phase | Tactic | Technique ID | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Valid Accounts | **T0859** | Direct use of internal access rights. |
| **Command & Control** | Standard Application Layer Protocol | **T0869** | Manual Modbus command execution. |
| **Inhibit Response** | Alarm Suppression | **T0878** | Disabling alarms so operators don't notice. |
| **Impact** | Loss of Control | **T0827** | Disabling critical pumps (PLC-01). |

## 3. Scenario 3: Ransomware (Historian Encryption)
| Phase | Tactic | Technique ID | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Exploit Public-Facing Application | **T0819** | Vulnerable web dashboard on Level 3. |
| **Persistence** | System Firmware | **T1693.001** | Ensuring ransomware runs after reboot. |
| **Impact** | Data Destruction | **T0813** | Encrypting or deleting the Historian data. |
| **Impact** | Loss of Availability | **T0828** | Encrypted files make system unusable. |

## 4. Detection Coverage (implemented, verified on lab traffic)
| Detection alert | Technique | Name |
| :--- | :--- | :--- |
| `UNAUTHORIZED_MODBUS_WRITE` | T0831 | Manipulation of Control |
| `PROCESS_SAFETY_VIOLATION` | T0836 | Modify Parameter |
| `CROSS_ZONE_VIOLATION` | T0886 | Remote Services |
| `OT_BRUTE_FORCE_SCAN` | T0846 | Remote System Discovery |
| `PLC_LOGIC_TAMPERED` | T0843 | Program Download |
| `DNP3_UNAUTHORIZED_CONTROL` | T1692.001 | Command Message |
| `DNP3_RESTART_COMMAND` | T0816 | Device Restart/Shutdown |
| `DNP3_UNSOLICITED_DISABLED` | T0878 | Alarm Suppression |
| `OPCUA_BROWSE_REQUEST` | T0888 | Remote System Information Discovery |
| `OPCUA_WRITE_REQUEST` | T1692.001 | Command Message |
| `OPCUA_METHOD_CALL` | T0871 | Execution through API |
| `S7COMM_PROGRAM_DOWNLOAD` | T0843 | Program Download |
| `S7COMM_PROGRAM_UPLOAD` | T0845 | Program Upload |
| `S7COMM_CHANGE_OPERATING_MODE` | T0858 | Change Operating Mode |
