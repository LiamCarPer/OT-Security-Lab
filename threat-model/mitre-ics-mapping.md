# MITRE ATT&CK for ICS Mapping

This document maps our high-priority risk scenarios to the **MITRE ATT&CK for ICS** matrix.

## Scenario 1: State-Sponsored APT (Water Toxicity)
| Phase | Tactic | Technique ID | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | External Remote Services | **T0822** | Use of VPN/Jump Host for entry. |
| **Persistence** | Valid Accounts | **T0859** | Using stolen engineer credentials. |
| **Lateral Movement** | Remote Services | **T0886** | Moving from DMZ to EWS/HMI. |
| **Command & Control** | Standard App Layer Protocol | **T0884** | Sending malicious Modbus/TCP traffic. |
| **Impact** | Manipulation of Control | **T0831** | Altering chemical dosing thresholds. |

## Scenario 2: Disgruntled Insider (Pump Sabotage)
| Phase | Tactic | Technique ID | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Valid Accounts | **T0859** | Direct use of internal access rights. |
| **Command & Control** | Standard App Layer Protocol | **T0884** | Manual Modbus command execution. |
| **Inhibit Response** | Alarm Suppression | **T0802** | Disabling alarms so operators don't notice. |
| **Impact** | Loss of Control | **T0827** | Disabling critical pumps (PLC-01). |

## Scenario 3: Ransomware (Historian Encryption)
| Phase | Tactic | Technique ID | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Exploit Public Application | **T0819** | Vulnerable web dashboard on Level 3. |
| **Persistence** | System Firmware | **T0857** | Ensuring ransomware runs after reboot. |
| **Impact** | Data Destruction | **T0813** | Encrypting or deleting the Historian data. |
| **Impact** | Loss of Availability | **T0828** | Encrypted files make system unusable. |
