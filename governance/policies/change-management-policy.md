# Change Management Policy - OT Environment (IEC 62443 Management of Change)

**Policy Owner:** Engineering Lead / OT Security Director
**Effective Date:** 2026-08-01
**Applies To:** All changes to OT assets: PLC logic, HMI/SCADA configuration, historian configuration, gateway firewall and IDS rules, firmware and software updates, network changes
**Alignment:** IEC 62443-3-3 SR_3.3 (security functionality verification), IEC 62443-2-1 Management of Change (MOC), IEC 62443-4-1 (secure product lifecycle)

## 1. Purpose

Industrial control systems tolerate no unplanned change: an untested logic modification or a misapplied firewall rule can interrupt production or create a safety condition (e.g., a valve command issued against a tank at overflow capacity). This policy establishes a Management of Change (MOC) process that guarantees every change to the OT environment is authorized, tested, documented, and reversible, consistent with the facility's IEC 62443 SL-2 target.

## 2. Change Classification

| Class | Definition | Approval | Examples |
| :--- | :--- | :--- | :--- |
| **Standard** | Pre-approved, low-risk, repeatable | Documented procedure + implementer | Password rotation, log retention change, rule tuning |
| **Normal** | Process-affecting or security-affecting | MOC review board | PLC logic change, firewall rule change, HMI update |
| **Emergency** | Required to protect safety or availability | Plant Manager + Security Director (retroactive MOC within 24 h) | Fail-safe correction, incident containment rule |

## 3. MOC Process (Normal Changes)

1. **Request:** The requester submits a change request describing the asset (e.g., PLC_Treatment 172.21.0.11), the current state, the proposed state, and the reason.
2. **Impact assessment:** A documented risk and impact analysis is performed, including effects on interlocks (e.g., the tank-level interlock monitored by PROCESS_SAFETY_VIOLATION), dependent assets, and the BIA (RTO/RPO in `governance/bia.md`).
3. **Approval:** The MOC review board (Engineering Lead, Plant Operations, Security) approves or rejects with justification.
4. **Test:** The change is validated in the test environment (e.g., OT-Security-Lab) where applicable, using the test cases in `governance/testing/CYBERSECURITY_TEST_PLAN.md`.
5. **Implementation:** The change is applied within the approved maintenance window, by an authorized engineer only.
6. **Verification:** Post-implementation, the change is verified: PLC logic is compared against the master logic hash; gateway rules are validated with `make compliance`; detection rules are exercised with the relevant attack simulation.
7. **Documentation:** The change record is updated with implementation details, verification evidence, and the rollback procedure. Records are retained for audit purposes.
8. **Rollback readiness:** Every change must have a defined rollback (prior logic file, prior rule set, configuration backup) available before implementation.

## 4. Security-Specific Requirements

- **PLC logic changes** are distributed only from the EWS (172.23.0.4) and must update the master logic hash; the PLC_LOGIC_TAMPERED detection rule (T0853) is the verification control.
- **Gateway changes** (firewall rules at 172.24.0.2) are reviewed by Security; a misconfiguration must not open a new conduit between zones.
- **Detection rule changes** (e.g., `detection/rules/*.py`) are treated as security-critical and are tested against the alert log to confirm expected alert types (UNAUTHORIZED_MODBUS_WRITE, OT_BRUTE_FORCE_SCAN, CROSS_ZONE_VIOLATION, PROCESS_SAFETY_VIOLATION, DNP3_WRITE_UNAUTHORIZED, PLC_LOGIC_TAMPERED).
- **Software/firmware updates** (e.g., Scada-LTS, InfluxDB, OpenPLC) require vendor security advisory review and validation in the test environment before production deployment.
- Changes that disable, modify, or bypass a security control are prohibited unless approved under an emergency class and registered in the risk register as an exception.

## 5. Roles and Responsibilities

- **Requester** prepares and justifies the change; **MOC review board** approves; **Authorized engineer** implements; **Plant operations** supervises process-affecting changes; **Security** verifies security functionality (SR_3.3) and maintains evidence.
- **Emergency changes:** the implementer must inform the Plant Manager and Security Director immediately; a retrospective MOC record must be completed within 24 hours.

## 6. Exceptions and Non-Compliance

- Unauthorized changes are investigated per the incident response process; PLC logic tampering is treated as a security incident (T0853) and escalated per `IR_PLAYBOOK_PLC_TAMPERING.md`.
- Repeat violations result in suspension of change privileges.

---

**Approved By:** OT Security Director / Plant Manager
**Review Date:** 2026-11-01
