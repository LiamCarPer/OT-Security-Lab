# OT Tabletop Exercise Kit

**Purpose:** Structured tabletop exercises (TTX) to validate the OT incident response capability without touching the live process.
**Reference:** `governance/incident_response/IR_PLAYBOOK_PLC_TAMPERING.md`, `governance/bia.md`, `governance/risk_register.csv`
**Scenario Basis:** Real detection evidence from `detection/logs/alerts.json`

## 1. How to Use This Kit

- **Duration per scenario:** 90 minutes (45 min play, 30 min discussion, 15 min debrief) plus a written after-action report within 5 working days.
- **Frequency:** at least two exercises per year; this kit provides two scenarios, one safety-centric and one availability/data-centric.
- **Participants:** 6-10 people minimum: Facilitator, Plant Operations, Control Engineer, IT/Engineering, Security/SOC analyst, Incident Commander, Communications/PR, Legal/Compliance (observer), Plant Manager (decision-maker).
- **Ground rules:** no real systems are touched; the process state is entirely inject-driven; participants act as if the scenario is real; decisions are recorded; "we will handle it" is not an acceptable answer without naming the action, owner, and time.

## 2. Participant Roles

| Role | Responsibilities in the TTX |
| :--- | :--- |
| Facilitator | Delivers injects, keeps time, does not solve problems for the team |
| Incident Commander | Runs the response, delegates, declares severity/level |
| SOC Analyst | Describes what detection artifacts would show (alerts, logs, MTTD) |
| Plant Operations | Advises on process impact, manual control feasibility, fail-safe behavior |
| Control Engineer | Handles PLC logic verification/restore, master hash checks |
| IT/Engineering | Handles infrastructure (historian, network), backup/restore feasibility |
| Communications | External/regulator messaging, transparency decisions |
| Plant Manager | Approves containment steps, declares emergency, accepts risk |

## 3. Scenario A: Safety-Integrity Violation via Compromised HMI

**Focus:** process safety (T0836), credential compromise, containment without process disruption.

### 3.1 Scenario Background

An operator account on the HMI (172.22.0.10) is compromised. The attacker uses the HMI's authorized conduit to issue a legitimate-looking command sequence against the Treatment stage (PLC_Treatment, 172.21.0.11). Detection is triggered when a valve-open command is issued while tank level is at 95% - the physics-aware monitor raises PROCESS_SAFETY_VIOLATION (T0836). The team must contain the threat while keeping the treatment process stable.

### 3.2 Inject Timeline (deliver one inject every 5-10 minutes)

| Min | Inject | Expected Team Action |
| :--- | :--- | :--- |
| 0 | SOC Analyst reports PROCESS_SAFETY_VIOLATION: source 172.22.0.10 (HMI), "Tank Level 95%, Command: OPEN Inlet Valve", plus 3 preceding UNAUTHORIZED_MODBUS_WRITE alerts to register 1 | Triage; confirm alert validity vs scheduled maintenance (MOC check); declare incident level |
| 10 | HMI session shows repeated login failures from a second operator account (OT_BRUTE_FORCE_SCAN pattern, 5+ exceptions) | Suspect credential compromise; isolate HMI account; begin password reset per access control policy |
| 20 | Plant Operations confirms the dosing pump cycled twice without operator action | Shift treatment to manual control per IR playbook; document process state |
| 30 | Gateway logs show the attacker source pivoting toward the Distribution PLC (172.21.0.12) | Contain at gateway: block offending source IP (`iptables -I FORWARD -s [SRC] -j DROP`); preserve PCAP for 5 minutes |
| 40 | Control Engineer finds EWS (172.23.0.4) history showing an attempted logic comparison (hash mismatch on Treatment logic) | Verify master logic hash; prepare golden image restore; coordinate with MOC board |
| 50 | Press inquiry arrives: local news asking about a "system malfunction" at the plant | Communications plan; regulatory notification decision (water authority) |
| 60 | Attacker activity ceases | Verify containment; begin eradication/recovery; document evidence chain |

### 3.3 Discussion Questions

1. When is it correct to break the HMI-to-PLC conduit entirely, and what process risk does that create (fail-safe behavior, water hammer)?
2. Who authorizes the shift to manual control, and is the operator staffing sufficient?
3. How do we prove the HMI itself was not backdoored before restoring normal operations?
4. What would the MTTD have to be for this class of alert to prevent the second write?
5. What regulatory disclosures are triggered, and by whom?

## 4. Scenario B: Ransomware Encrypting the Historian

**Focus:** data availability (RSK-008), recovery (SR_7.3), continuity of audit evidence.

### 4.1 Scenario Background

A phishing email reaches an operator workstation in the Enterprise zone (172.24.0.0/24). A scheduled task deploys ransomware that encrypts shares and then spreads toward the Operations zone, encrypting the InfluxDB historian (172.23.0.10, `ot_data`). The control network is not directly affected, but all audit and trending data are at risk. The team must decide: isolate, notify, and restore from backups - which are still being established.

### 4.2 Inject Timeline

| Min | Inject | Expected Team Action |
| :--- | :--- | :--- |
| 0 | SOC reports CROSS_ZONE_VIOLATION: 172.24.0.10 to 172.21.0.10 blocked at gateway; simultaneously Grafana shows historian write failures | Triage two incidents; assess whether this is the same event; verify no control-plane impact |
| 10 | IT confirms ransomware banner on the EWS (172.23.0.4) share; historian database appears partially encrypted | Declare incident; isolate Operations zone conduit; preserve forensic copies of encrypted files |
| 20 | Plant Operations confirms PLCs are running normally; production unaffected | Confirm control zone stability; focus response on data recovery and containment |
| 30 | Backup status check: scheduled backups exist but the last verified restore was a tabletop exercise 8 months ago | Determine restore feasibility; compute expected data loss against RPO (1 h) |
| 40 | Regulatory deadline appears: daily discharge report due in 6 hours; historian data required | Decide manual data collection fallback; prepare regulator communication |
| 50 | Ransomware demands payment; attacker claims deleted backups | Record extortion demand; reaffirm no-payment policy; continue recovery |
| 60 | Restore from offline media completes; 55 minutes of data lost | Validate restore; document gap; schedule root-cause and policy review |

### 4.3 Discussion Questions

1. Does the current backup arrangement satisfy the 1-hour RPO for the historian? If not, what data is permanently lost?
2. How long until the facility can prove compliance data integrity to the regulator?
3. When is it correct to cut the Operations zone off from the Enterprise zone entirely, given the SIEM lives in 172.24.0.0/24?
4. What compensating manual controls exist if trending data is unavailable during recovery?
5. What changes to the backup policy (offline media, cadence) does this scenario mandate?

## 5. Facilitator Guide

- **Before the exercise:** confirm participants, review the IR playbook and BIA, prepare inject cards and a wall clock; brief observers on note-taking (they produce the raw record).
- **During the exercise:** state each inject neutrally, allow 3-5 minutes of discussion per inject; track decisions on a decision log (decision, owner, time); do not reveal "the answer" - the objective is process validation.
- **After the exercise:** lead the debrief (below), then the team completes the after-action template; the OT Security Director accepts findings and assigns actions with owners and due dates.

## 6. Debrief and After-Action Template

| Item | Content |
| :--- | :--- |
| Exercise name / date / participants | |
| Scenario played | A or B |
| What went well (validated capabilities) | |
| What went poorly / gaps identified | |
| Key decisions taken (from decision log) | |
| Detection observations (alerts that would fire, MTTD expected) | |
| Recovery observations (RTO/RPO feasibility, backup readiness) | |
| Process/policy gaps discovered | |
| Corrective actions (action, owner, due date, KPI) | |
| Updates required to IR playbook / policies / risk register | |
| Facilitator approval / next exercise date | |

---

**Kit Owner:** OT Security Director
**Next Scheduled Exercise:** (per remediation roadmap RD-xx, at least one per half-year)
