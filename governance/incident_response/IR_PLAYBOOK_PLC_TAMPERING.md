# Incident Response Playbook: Unauthorized PLC Modification
**Standard Alignment:** NIST SP 800-61, ISA/IEC 62443-2-4
**Priority:** P1 - Critical (Physical Integrity at Risk)

## 1. Detection and Analysis (The "Grafana Alert")
- **Trigger:** SIEM Alert `UNAUTHORIZED_MODBUS_WRITE` or `PROCESS_SAFETY_VIOLATION`.
- **Validation:** 
    - Verify timestamp in `alerts.json`.
    - Cross-reference with HMI logs: Was this a scheduled maintenance write?
    - Check Historian: Are physical process variables (tank level, pressure) deviating from normal?

## 2. Containment (OT-Specific Rules)
- **!!! CAUTION !!!:** Do NOT simply "Kill" the network connection. Sudden loss of communication can trigger PLC "Fail-Safe" modes that may cause physical damage (e.g., water hammer).
- **Step 2.1:** Inform Plant Operations immediately. Request a shift to "Manual Control" if available.
- **Step 2.2:** Isolate the attacker at the **Gateway**. Update `gateway_firewall.sh` to block the specific source IP:
    `iptables -I FORWARD -s [ATTACKER_IP] -j DROP`
- **Step 2.3:** Record a full traffic capture (PCAP) from the gateway for 5 minutes.

## 3. Eradication and Recovery
- **Step 3.1:** Verify the PLC Logic Integrity. Use the **Master Logic Hash** (if available) to ensure no persistent malicious code remains.
- **Step 3.2:** Reset the PLC to a known-good configuration from the **Offline Vault**.
- **Step 3.3:** Slowly transition back from Manual to Automatic control while monitoring safety interlocks.

## 4. Post-Incident Activities
- **Root Cause Analysis:** How did the attacker reach the Supervisory network?
- **Update Asset Inventory:** Was the attacker using a previously unknown rogue device?
- **Review MAGERIT Risks:** Update the likelihood of Threat T.01 based on this occurrence.

---
**Approved By:** OT Security Director
**Revision:** 1.2
