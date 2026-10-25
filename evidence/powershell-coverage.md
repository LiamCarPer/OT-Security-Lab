# Detection Coverage

| Sigma rule | ATT&CK for ICS | Alert types |
| :--- | :--- | :--- |
| Cross-Zone Violation (IT to Control) | T0886 | CROSS_ZONE_VIOLATION |
| Suspicious Modbus Client Initiated from Endpoint | T0884 |  |
| Modbus Exception Flood (Brute-Force / Scan) | T0846 | OT_BRUTE_FORCE_SCAN |
| Unauthorized Modbus Write Command | T0831 | UNAUTHORIZED_MODBUS_WRITE |
| OT Service Port Scan | T0846 | OT_PORT_SCAN |
| PowerShell OT Conduit Discovery | T0846 |  |
| PowerShell Modbus Client Against OT Controller | T0831 |  |
| Process Safety Interlock Violation | T0836 | PROCESS_SAFETY_VIOLATION |

Sigma rules: **8**
