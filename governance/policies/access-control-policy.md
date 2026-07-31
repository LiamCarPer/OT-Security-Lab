# Access Control Policy - OT Environment

**Policy Owner:** OT Security Director
**Effective Date:** 2026-08-01
**Applies To:** All users, accounts, and sessions accessing the OT environment (Control 172.21.0.0/24, Supervisory 172.22.0.0/24, Operations 172.23.0.0/24, Enterprise 172.24.0.0/24)
**Alignment:** IEC 62443-3-3 SR_1.1 (identification and authentication), SR_2.1 (authorization enforcement), NIST SP 800-82; SL-2 target

## 1. Purpose

This policy defines how identities are established, authorized, and controlled for all access to industrial control system assets, including the PLCs (PLC_Intake 172.21.0.10, PLC_Treatment 172.21.0.11, PLC_Distribution 172.21.0.12), the HMI (172.22.0.10), the historian (172.23.0.10), the engineering workstation (172.23.0.4), and the gateway (172.24.0.2). The objective is to ensure that every access attempt is attributable to a unique identity and limited to the minimum privileges required for the role.

## 2. Policy Statements

### 2.1 Identity and Authentication

1. Every user must have a unique account. Shared accounts are prohibited, including on the HMI, EWS, and gateway.
2. Passwords must be at least 12 characters, with complexity and rotation per the organizational password standard. Default vendor credentials (e.g., OpenPLC, Scada-LTS) must be changed before commissioning.
3. Multi-factor authentication is required for all remote and privileged access (see the Remote Access Policy).
4. Account lockout must be enforced after 5 failed attempts, with a lockout duration of at least 15 minutes, aligned with the OT_BRUTE_FORCE_SCAN detection threshold.

### 2.2 Authorization and Least Privilege

5. Access rights are granted based on role (per SR_2.1) and documented in the access rights matrix in Annex A.
6. Roles are limited to: Operator (read/monitor via HMI), Engineer (logic modification on EWS, PLC program access), Administrator (system configuration, gateway rule changes), Security (monitoring and alert triage only).
7. No user account may span zones with different trust levels; the gateway enforces zone boundaries independent of user identity.
8. Privileged access (root, administrator) is restricted to named individuals and requires written approval. Privileged sessions are logged and reviewed monthly.

### 2.3 Access Paths

9. All access to the control zone must traverse the gateway (172.24.0.2) or the defined conduit; direct access from the Enterprise zone (172.24.0.0/24) to the control zone (172.21.0.0/24) is prohibited and is monitored by the CROSS_ZONE_VIOLATION rule.
10. Modbus/TCP access to the PLCs is permitted only from the HMI (172.21.0.20) and the EWS conduit; the gateway firewall allow-list is the enforcement point.
11. Session inactivity timeout must terminate idle sessions within 15 minutes (SR_2.6).

### 2.4 Account Lifecycle

12. Accounts are created, modified, and revoked through a formal request process. Revocation must occur within 24 hours of an employee's departure or role change.
13. A quarterly account review is required, reconciling the account list against the asset inventory and personnel records.
14. Service accounts are limited to machine-to-machine communication (e.g., historian data collection), must not be usable for interactive login, and must have their credentials rotated at least annually.

## 3. Roles and Responsibilities

- **Asset owners** approve access requests for their systems and perform quarterly reviews.
- **IT/Engineering** provision and deprovision accounts within the defined SLA.
- **Security** monitors authentication logs, responds to OT_BRUTE_FORCE_SCAN alerts, and reports anomalies.
- **All users** are responsible for safeguarding credentials and reporting suspected compromise immediately to the incident response team.

## 4. Monitoring and Compliance

- Authentication failures are monitored; a cluster of failures triggers OT_BRUTE_FORCE_SCAN (T0846) and is escalated per the incident response playbook.
- Violations of this policy are reported to the OT Security Director and are subject to disciplinary action.
- Compliance is reviewed annually and after any material change to the architecture.

## 5. Exceptions

Exceptions require documented, risk-accepted approval by the OT Security Director, with a compensating control and a review date. Exceptions are recorded in the risk register.

---

**Annex A - Access Rights Matrix (summary)**

| Role | HMI (172.22.0.10) | EWS (172.23.0.4) | PLC logic | Gateway rules | Historian (172.23.0.10) | SIEM (172.24.0.22) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Operator | Read/operate | None | None | None | Read | None |
| Engineer | Read | Full | Change (MOC-approved) | None | Read/Write | None |
| Administrator | Config | Config | Change (MOC-approved) | Read/Write | Config | Read |
| Security | None | None | None | Read | Read | Read/Write |

---

**Approved By:** OT Security Director | **Review Date:** 2026-11-01
