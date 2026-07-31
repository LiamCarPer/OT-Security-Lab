# Remote Access Policy - OT Environment

**Policy Owner:** OT Security Director
**Effective Date:** 2026-08-01
**Applies To:** All remote access to OT assets from external or corporate (L4/5) networks, including the jump host in the Industrial DMZ, the EWS (172.23.0.4), and the HMI (172.22.0.10)
**Alignment:** IEC 62443-3-3 SR_2.6 (remote session termination), SR_4.1 (confidentiality), NIST SP 800-82 Section 6.4; SL-2 target

## 1. Purpose

Remote access is one of the highest-risk vectors in an OT environment: the threat model identifies remote access hijack (stolen VPN credentials) as a primary scenario for HMI compromise and unsafe process manipulation. This policy restricts remote access to an explicit, authenticated, logged, and time-limited path that never grants direct session rights to control-zone assets.

## 2. Policy Statements

### 2.1 Authorized Access Path

1. All remote access must terminate at the jump host in the Industrial DMZ. Direct remote access to PLCs (172.21.0.10-12), the HMI (172.22.0.10), the historian (172.23.0.10), or the EWS (172.23.0.4) from external networks is prohibited.
2. From the jump host, further movement is permitted only to authorized destinations (e.g., EWS via RDP/SSH) and only for the approved task; the gateway (172.24.0.2) continues to enforce zone conduits.
3. Remote sessions are allowed only during approved maintenance windows, except for emergency response approved by the Plant Manager.

### 2.2 Authentication

4. Remote access requires multi-factor authentication (MFA) in addition to the user's password; the remote access policy is aligned with the Access Control Policy's identity requirements.
5. Shared remote access accounts are prohibited. Each session is attributable to a unique identity.
6. Default and vendor accounts on the jump host and EWS must be disabled or renamed before commissioning.

### 2.3 Session Controls

7. Remote sessions must be terminated after 15 minutes of inactivity (SR_2.6); the gateway and jump host must enforce this termination, not merely display a warning.
8. All remote sessions are recorded: connection logs (source, destination, start, end) must be shipped to the SIEM (Loki at 172.24.0.20) and retained per the logging standard. Where feasible, sessions are subject to screen recording for privileged actions.
9. Concurrent remote sessions per user are limited to one.

### 2.4 Confidentiality and Endpoint Protection

10. All remote access traffic must be encrypted (VPN, SSH, or TLS); plaintext administrative protocols (e.g., unencrypted RDP, Modbus) are prohibited on remote paths (SR_4.1).
11. The remote user's endpoint must run current antivirus, OS patches, and a host firewall, and must be compliant with the endpoint standard before connection.
12. Downloads or transfers between the corporate network and the OT environment during remote sessions are prohibited except through the approved file transfer process.

### 2.5 Approval and Review

13. Remote access rights are granted per user and per task, with an expiry date; standing perpetual remote access is prohibited.
14. The remote access entitlement list is reviewed quarterly by Security and the asset owners; expired rights are revoked automatically.
15. Remote access events are correlated with detection rules: unusual access patterns are investigated, and any remote session associated with suspicious activity (e.g., CROSS_ZONE_VIOLATION, OT_BRUTE_FORCE_SCAN) is terminated immediately by Security.

## 3. Roles and Responsibilities

- **Security** administers the jump host, reviews session logs quarterly, and responds to anomalies.
- **IT/Engineering** provisions and revokes remote access requests within 24 hours of approval or termination.
- **Plant Manager** approves emergency remote access and maintenance windows.
- **Users** must report lost credentials or suspicious remote sessions immediately to the incident response team.

## 4. Incident Handling

Suspected remote access compromise follows the incident response process (`IR_PLAYBOOK_PLC_TAMPERING.md`): isolate the session at the gateway, preserve session logs, and initiate containment without sudden network cuts that could trigger PLC fail-safe states.

## 5. Compliance and Exceptions

- Non-compliance is reported to the OT Security Director; repeat violations result in revocation of remote access privileges.
- Exceptions require documented risk acceptance with compensating controls and a review date, recorded in the risk register.

---

**Approved By:** OT Security Director
**Review Date:** 2026-11-01
