# OT Incident Response Playbook: Unauthorized PLC Modification

**Standard Alignment:** NIST SP 800-61, ISA/IEC 62443-2-4
**Priority:** P1 — Critical (physical integrity at risk)
**Scenario:** SIEM alerts `UNAUTHORIZED_MODBUS_WRITE`, `PROCESS_SAFETY_VIOLATION`,
`PLC_LOGIC_TAMPERED`, or the protocol-control alerts (DNP3/OPC UA/S7comm).
**Assets:** PLCs `172.21.0.10/11/12` and the protocol endpoints `172.21.0.50-52`.

---

## 1. Detection & Initial Assessment
1. **Source verification:** identify the source IP and target register/function in
   `detection/logs/alerts.json`; correlate with the Loki alert and the SIEM.
2. **Change check:** cross-reference the HMI and change-management (MOC) records —
   was this a scheduled maintenance write?
3. **Process integrity:** check the historian (InfluxDB `process_state`) and the
   HMI — are values (tank level, pressure, chlorine) deviating from setpoints?
4. **Safety status:** if the process is out of control, proceed to Emergency
   Manual Shutdown via the physical button (L0/L1). Safety first.

## 2. Containment (OT-safe)
> **WARNING:** Do NOT power off the PLC or sever the network abruptly. Sudden
> loss of logic control can cause water hammer, pipe bursts or environmental
> spills (a "fail-safe" that is not "fail-safe" for the process).

1. **Inform Plant Operations** immediately; request a shift to Manual/Local
   control where available (PLC control selector Remote/Auto -> Local/Manual).
2. **Isolate at the gateway** (never at the controller): block the source on the
   `ot_gateway` FORWARD chain —
   ```bash
   docker exec ot_gateway iptables -I FORWARD -s <ATTACKER_IP> -j DROP
   ```
   The gateway-side responder (`detection/rules/responder.py`) automates this for
   repeat unauthorized writes when armed (`OT_RESPONDER_ENFORCE=1`).
3. **Preserve evidence:** capture traffic at the gateway (PCAP) for at least 5
   minutes before and after containment; keep the JSON alert log intact.
4. **Physical verification:** a technician must confirm the physical valve/pump
   state matches the HMI display.

## 3. Eradication & Remediation
1. **Logic verification:** use the EWS to compare the running PLC logic against
   the golden baseline (`plc/plc_integrity_check.py`, `plc/manifest.json`).
2. **Eradication:** re-deploy the verified program bundle from the offline vault
   (`plc/programs/`, re-uploaded by `ot_plc_bootstrap`).
3. **Credential rotation:** rotate SCADA/HMI and EWS credentials; audit the
   engineering workstation for malware.

## 4. Recovery
1. Re-enable the network path and, only with a verified program, transition the
   process back to Remote/Auto under close supervision while monitoring the
   safety interlocks.
2. Lower detection thresholds for the affected conduit for 72 hours (e.g.,
   `OT_BRUTE_FORCE_THRESHOLD=1`).

## 5. Post-Incident
- **Root cause:** how did the attacker reach the Supervisory/Operations zone?
  Was the DMZ or a conduit misconfigured?
- **Asset inventory:** was the attacker a previously unknown rogue device?
- **Risk review:** update `governance/risk_register.csv` (likelihood/residual)
  and MAGERIT factors.
- **Lessons learned:** update `hardening/HARDENING_CHECKLIST.md` and
  `LESSONS_LEARNED.md`.

---
**Approved By:** OT Security Director · **Revision:** 2.0
