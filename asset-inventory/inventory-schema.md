# Asset Inventory Schema

This document defines the fields used in `assets.csv` and their significance in an OT security context.

| Field | Description | Security Significance |
| :--- | :--- | :--- |
| **asset_id** | Unique identifier | Essential for incident tracking and CMDB alignment. |
| **hostname** | Network name | Used in DNS/Service discovery and alert context. |
| **ip_address** | Primary IP | Critical for firewall ACLs and network segmentation. |
| **zone** | IEC 62443 Zone | Defines the trust level and required security controls. |
| **purdue_level** | ISA-95 Level | Context for the asset's role (Control vs Operations). |
| **device_type** | Functional type | Determines the vulnerability profile (e.g., PLC vs HMI). |
| **manufacturer** | OEM Name | Used for tracking security advisories (CVEs). |
| **model** | Model Number | Identifies hardware-specific vulnerabilities. |
| **firmware_version** | Current version | Critical for patch management and vulnerability analysis. |
| **open_ports** | Exposed services | Defines the network attack surface. |
| **last_seen** | Inventory update | Ensures the asset list is current and not stale. |
