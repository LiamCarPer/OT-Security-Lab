# Findings Report Template - OT Security Assessment

**Engagement:** [Facility / Environment name]
**Client:** [Asset owner]
**Assessment Date:** [YYYY-MM-DD]
**Version:** 1.0 | **Status:** Draft / Final

## 1. Severity Rating Scheme

| Severity | Score | Definition | Example |
| :--- | :--- | :--- | :--- |
| **Critical** | 9 (EXTREME) | Exploitation causes loss of safety function, physical damage, or loss of control with no compensating control. Requires immediate action. | Unauthorized Modbus write to Treatment PLC dosing registers (RSK-001). |
| **High** | 6 (HIGH) | Exploitation degrades control integrity or availability, or permanently destroys evidence. Action required within the current remediation cycle. | Ransomware on the historian (RSK-008); unencrypted Modbus sniffing (RSK-012). |
| **Medium** | 3-4 (MEDIUM) | Exploitation assists further attacks or affects single non-critical assets. Action required within 6 months. | Log tampering of audit evidence (RSK-006); insider HMI misuse (RSK-009). |
| **Low** | 1-2 (LOW) | Exploitation has limited impact or requires privileged access. Action on schedule. | Supply-chain image compromise without exploit path (RSK-010). |

Score = likelihood (H=3/M=2/L=1) x impact (H=3/M=2/L=1), consistent with `governance/risk_register.csv` and the MAGERIT assessment.

## 2. Findings Summary Table

| ID | Title | Severity | Affected Assets | Status (Open/In Progress/Closed) |
| :--- | :--- | :--- | :--- | :--- |
| FIN-001 | [Title] | [Critical/High/Medium/Low] | [IP / zone] | Open |

## 3. Detailed Finding

**Finding ID:** FIN-00X
**Title:** [Concise statement of the weakness]
**Severity:** [Critical / High / Medium / Low] | **Risk score:** [n/9]
**Affected assets:** [Asset name(s) and IP(s), e.g., PLC_Treatment 172.21.0.11]
**Requirement reference:** [e.g., IEC 62443-3-3 SR_4.1; MITRE ATT&CK for ICS technique T0831]

### 3.1 Description
[Describe the weakness in plain language: what exists, what is missing, and how an attacker or failure could exploit it. Example: "Modbus/TCP traffic between the HMI (172.22.0.10) and the PLCs (172.21.0.10-12) is transmitted in cleartext; an attacker with any foothold on the control network can passively read and replay write commands."]

### 3.2 Evidence
[Concrete, reproducible evidence with references: alert log entries (timestamp, alert_type, source_ip from `detection/logs/alerts.json`), configuration excerpts (e.g., gateway firewall rules), PCAP excerpts, tool output, screenshot locations. Each piece of evidence must be traceable to a file or log entry. Example: "2026-05-01T10:09:24 CROSS_ZONE_VIOLATION from 172.24.0.10 to 172.21.0.10, followed by UNAUTHORIZED_MODBUS_WRITE to register 1 at 10:09:25."]

### 3.3 Business Impact
[Impact on the facility in terms of safety, availability, integrity, confidentiality, and regulatory exposure, quantified where possible using the BIA (e.g., "per BIA Section 3, a dosing integrity failure incurs recall and regulatory liability; historian loss breaches audit obligations").]

### 3.4 Root Cause
[Underlying cause: missing control, misconfiguration, architectural limitation, or process gap.]

### 3.5 Recommendation
[Specific, actionable remediation with the IEC 62443 requirement it satisfies and an effort estimate. Example: "Transition the HMI-to-PLC conduit to Modbus/TCP Security or a VPN tunnel (SR_4.1). Effort: 6-10 weeks. Reference: remediation roadmap RD-06."]

### 3.6 Validation / Re-test Plan
[How the remediation will be verified: control test, rule test case (per `governance/testing/CYBERSECURITY_TEST_PLAN.md`), or restore exercise.]

### 3.7 Residual Risk after Remediation
[Risk level remaining after the control is implemented, e.g., HIGH to MEDIUM.]

## 4. Executive Summary Section (Board Copy)

- Posture in one paragraph (zone SL-T vs SL-A per `iec62443/sl-mapping.md`).
- Top 5 findings by severity.
- Detection KPIs snapshot (alert volumes per rule, unique sources, MTTD proxy per `automation/metrics.py`).
- Next 90-day priorities (per `governance/remediation_roadmap.md`).

## 5. Approval and Sign-off

| Role | Name | Signature | Date |
| :--- | :--- | :--- | :--- |
| Engagement Lead | | | |
| Plant Operations Liaison | | | |
| OT Security Director | | | |

---

**Distribution:** Client stakeholders per scoping questionnaire section F.
**Retention:** Evidence retained for [period] per scoping questionnaire section G.
