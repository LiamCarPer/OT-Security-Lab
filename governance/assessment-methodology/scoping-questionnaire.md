# OT Security Assessment - Scoping Questionnaire

**Purpose:** Completed by the asset owner and the assessment engagement lead before any testing activity begins. Answers define the boundaries of the engagement and are recorded in the signed scope statement.

## A. Facility and Process Context

1. Describe the facility, its primary process (e.g., water treatment and filtration), and the stages of the process that are in scope.
2. Which production stages are safety-critical or regulated (e.g., chemical dosing, pressure systems), and what is the regulatory framework?
3. What are the operational hours, and are there any periods when process interruption is absolutely prohibited (e.g., peak delivery windows)?

## B. Asset and Architecture Scope

4. Provide the current asset inventory (PLCs, HMI, historian, engineering workstations, network appliances) with IP addresses and Purdue levels (refer to the lab inventory schema: `asset-inventory/inventory-schema.md`).
5. Which zones and conduits are in scope for this engagement (Control L1, Supervisory L2, Operations L3, Enterprise L4/5)?
6. Which assets are explicitly out of scope, and why (vendor-managed, legacy, no access)?
7. Are there wireless networks, remote access points, or third-party connections that touch the control network?

## C. Protocols and Systems

8. Which industrial protocols are in use (e.g., Modbus/TCP, DNP3, OPC-UA) and which protocol versions?
9. List the SCADA/HMI platform, historian, and their versions (e.g., Scada-LTS v2.7.0, InfluxDB 1.8.10), including patch status.
10. Is there a separate Safety Instrumented System (SIS), and is it logically or physically separated from the control system?

## D. Technical Testing Constraints

11. Which testing windows are permitted, and what is the maximum acceptable downtime for any single test?
12. Which tests are prohibited without additional approval (e.g., any write operation, firmware changes, logic uploads)?
13. Are passive monitoring points (port mirrors, TAPs, IDS sensors) available for traffic capture, and in which zones?
14. Who from plant operations must accompany testers during active testing, and what is the escalation path?

## E. Incident and Change Procedures

15. What is the current change management (MOC) process for PLC logic changes, and who approves them (reference: `governance/policies/change-management-policy.md`)?
16. Have any recent changes, incidents, or suspicious events been reported in the last 12 months? Provide timestamps and references (e.g., `detection/logs/alerts.json`).
17. What is the existing incident response procedure and who is on the call tree (reference: `governance/incident_response/IR_PLAYBOOK_PLC_TAMPERING.md`)?

## F. Compliance and Reporting

18. Which security standards or frameworks apply (IEC 62443, NERC CIP, ISO 27001, local regulation), and what SL target has been set per zone?
19. Who are the report recipients, and what format and language are required for the final report (technical findings report, executive summary)?
20. Are there prior assessments, penetration tests, or compliance audits whose findings should be re-validated?

## G. Logistics

21. Confirm the point of contact per zone, the test environment or staging system availability (e.g., the OT-Security-Lab environment), and the expected engagement timeline.
22. Confirm approval for the assessment team to retain evidence (logs, PCAPs, configuration exports) and the data retention period.

---

**Completed By:** Asset Owner
**Accepted By:** Engagement Lead
**Date:**
