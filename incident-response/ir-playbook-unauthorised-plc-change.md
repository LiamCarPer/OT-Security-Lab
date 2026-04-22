# OT Incident Response Playbook: Unauthorized PLC Configuration Change

**Scenario:** A high-severity alert (`UNAUTHORIZED_MODBUS_WRITE`) is detected on the industrial network.
**Asset:** `PLC-02` (Chemical Treatment/Filtration).
**Criticality:** **Safety (Level 1)** – Potential for toxic chemical dosing or physical overpressure.

---

## 1. Phase 1: Detection & Initial Assessment
1. **Source Verification:** Identify the **Source IP** and **Target Register** from `detection/logs/alerts.json`.
2. **Process Integrity:** Contact the Plant Operator. Are real-time values (e.g., pH, Chlorine, Pressure) deviating from the SCADA setpoints?
3. **Safety Status:** Is the physical process in a "Safe State"? If the process is out of control, proceed to **Emergency Manual Shutdown** via the physical button (L1).

## 2. Phase 2: Containment (OT-Safe Methodology)
**WARNING:** DO NOT shut down the PLC or disable its power. Sudden loss of logic control can cause water hammer, pipe bursts, or environmental spills.

1. **Network-Level Block:** Update the `ot_gateway` firewall to explicitly DROP all traffic from the Attacker's IP subnets.
   ```bash
   iptables -I FORWARD -s [ATTACKER_IP] -j DROP
   ```
2. **"Local Mode" Over-ride:** Instruct the local plant operator to switch the `PLC-02` control selector from **"Remote/Auto"** to **"Local/Manual."** 
   - This ensures the PLC continues to run its safety logic but ignores any Modbus/Network write commands.
3. **Physical Verification:** A technician must physically inspect the intake/output valves to ensure they match the HMI display.

## 3. Phase 3: Eradication & Remediation
1. **Logic Verification:** Use the Engineering Workstation (EWS) to perform a **"Compare"** between the running PLC logic and the "Gold Master" version stored in the EWS backups.
2. **Eradication:** Re-deploy the verified PLC ladder logic to overwrite any malicious changes made by the attacker.
3. **Credential Rotation:** Immediately rotate all SCADA/HMI administrative credentials and audit the Engineering Workstation for malware.

## 4. Phase 4: Recovery & Lessons Learned
1. **Process Restoration:** Once the logic is verified, switch the process back to "Remote/Auto" mode under close supervision.
2. **Monitoring Window:** Increase the `ERROR_THRESHOLD` in `ot_brute_force.py` to `1` for the compromised subnet for 72 hours.
3. **Post-Mortem:**
   - How did the attacker bypass the **Industrial DMZ**?
   - Did the **Zone-Conduit** firewall rules have a permissive "Any-Any" rule that should be revoked?
   - Update the `hardening/HARDENING_CHECKLIST.md` based on the incident findings.
