# Business Impact Analysis (BIA): Simulated Water Treatment Facility

**Document Owner:** IT/OT Security Engineer
**Date:** 2026-08-01
**Reference:** MAGERIT risk assessment (`governance/risk_assessment/OT_RISK_ASSESSMENT_MAGERIT.md`), asset inventory (`governance/asset_inventory.csv`)
**Alignment:** IEC 62443-3-2 (zones/conduits), NIST SP 800-34 (contingency planning)

## 1. Purpose and Scope

This Business Impact Analysis (BIA) identifies the criticality of each asset in the OT-Security-Lab water treatment and filtration environment, the operational and financial consequences of loss (confidentiality, integrity, availability), and the recovery objectives that drive business continuity and disaster recovery planning. The facility is a demonstration environment; all figures are engineering estimates used to validate the incident response and recovery capability of the architecture.

The facility processes raw water through three sequential stages controlled by the Level 1 PLCs: intake (PLC_Intake, 172.21.0.10), chemical treatment and filtration (PLC_Treatment, 172.21.0.11), and safe distribution (PLC_Distribution, 172.21.0.12). Because the plant cannot store finished water for extended periods, **availability of the control layer is the dominant business requirement**, followed by integrity of the process logic and of the audit data retained by the historian.

## 2. Per-Asset Criticality and Impact of Loss

| Asset | IP / Zone | Criticality | Confidentiality Impact | Integrity Impact | Availability Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| PLC_Intake | 172.21.0.10 / Control (L1) | High | Low | **High** - unauthorized register writes (T0831) can force unsafe inflow | **Critical** - loss stops water inflow; plant shutdown |
| PLC_Treatment | 172.21.0.11 / Control (L1) | High | Low | **Critical** - dosing manipulation (T0836) can produce toxic or under-treated water | **Critical** - outage halts chemical dosing and filtration |
| PLC_Distribution | 172.21.0.12 / Control (L1) | High | Low | High - wrong pump/valve states degrade delivery | High - outage stops distribution and pressurization |
| OT_HMI (Scada-LTS) | 172.22.0.10 / Supervisory (L2) | Medium | Medium - process data exposure | High - spoofed operator views mask unsafe states | High - operators lose situational awareness |
| OT_Historian (InfluxDB 1.8.10) | 172.23.0.10 / Operations (L3) | Medium | Medium - process records and audit data | High - falsified logs destroy compliance evidence | Medium - loss of trending/audit, not real-time control |
| Industrial Gateway | 172.24.0.2 / Boundary (L3.5) | **Critical** | Low | High - firewall/IDS bypass (T0886) | **Critical** - chokepoint loss severs all inter-zone traffic |
| Engineering Workstation (EWS) | 172.23.0.4 / Operations (L3) | High | Medium - logic source files | **Critical** - logic change tooling; master logic hashes | Medium - maintenance and recovery capability |
| SOC_Dashboard (Grafana) | 172.24.0.22 / Enterprise (L4) | Low | Low | Medium - alert manipulation hides incidents | Low - loss of visibility only |

## 3. Financial and Operational Impact of Loss

- **Availability loss (per hour of control layer outage):** Direct production loss from halted inflow, dosing and distribution; regulatory reporting obligations for service interruption; and overtime/emergency response costs. Estimated at **EUR 8,000-15,000 per hour** across the facility, with the Treatment stage (PLC_Treatment) incurring the highest rate because post-outage water must be discarded or re-treated.
- **Integrity loss (process logic tampering):** A manipulated dosing sequence may release under-treated water, triggering product recall, regulator fines and public-health liability. Integrity loss of the historian extends the exposure: falsified records impair root-cause analysis and can void compliance evidence, converting an engineering event into a legal event.
- **Confidentiality loss:** Exposure of process tags and flow rates through unencrypted Modbus/TCP sniffing (SR_4.1) has limited direct financial impact but informs attacker reconnaissance for later availability or safety attacks (T0846, T0886), so it is treated as a force multiplier rather than a standalone cost.

## 4. Recovery Objectives (RTO / RPO)

| Asset | RTO | RPO | Rationale |
| :--- | :--- | :--- | :--- |
| PLC_Intake | 1 h | 15 min (logic) | Inflow can be held by valve position briefly; logic must be restored from golden image |
| PLC_Treatment | 30 min | 15 min (logic) | Safety-critical; facility pauses dosing while logic verified against master hash |
| PLC_Distribution | 2 h | 1 h (logic) | Buffer stock in tanks permits longer recovery window |
| OT_HMI | 2 h | 1 h | Operator visibility can be partially replaced by local control |
| OT_Historian | 4 h | 1 h | Trending loss acceptable short term; audit continuity required |
| Industrial Gateway | 30 min | n/a (config) | Must restore segmentation before resuming inter-zone traffic |
| EWS | 4 h | Daily (source) | Logic source and hashes recoverable from vault |
| SOC_Dashboard | 8 h | 1 h | Detection visibility gap tolerated for one shift |

## 5. Dependencies and Single Points of Failure

- **OT_HMI depends on all three PLCs** over Modbus/TCP (HMI 172.21.0.20 to 172.21.0.10-12); loss of the gateway conduit breaks supervisory control.
- **OT_Historian collects from the PLCs** (and indirectly the HMI); historian loss does not affect control, but control loss halts data collection, creating an RPO gap on the historian during outages.
- **All inter-zone traffic transits the Industrial Gateway (172.24.0.2).** The gateway is the single point of failure for the entire architecture and is therefore the highest-priority recovery asset.
- **EWS (172.23.0.4) is the recovery asset:** master logic hashes, golden logic files and the change/restore toolchain all reside there; its loss delays every PLC recovery.

## 6. Recovery Strategies

1. **Control layer:** restore PLC logic from golden files held on the EWS and mirrored to an offline vault (SR_7.3), verify against the master logic hash, then return to automatic control under manual-override monitoring per `IR_PLAYBOOK_PLC_TAMPERING.md`.
2. **Boundary:** gateway configuration is versioned (firewall-rules.sh, IDS start script); redeploy from version control and validate with the compliance gate (`make compliance`).
3. **Historian:** restore InfluxDB `ot_data` from automated periodic backups once implemented (currently simulated); until then, backfill from Promtail-shipped logs in Loki.
4. **Visibility:** Grafana/Loki (172.24.0.20-22) rebuild from provisioning configs; alerting via Alertmanager (172.24.0.23) re-enabled first to close the detection gap.

## 7. Narrative Assessment

The facility operates as a just-in-time process: it holds minimal buffer, so the dominant impact class is **availability of the Level 1 control assets**, followed closely by **integrity of the Treatment logic** where failure produces a public-safety consequence rather than a purely economic one. This ordering drives the RTO hierarchy above: the gateway and the treatment PLC recover first, the historian and dashboard last. The investment case for the physics-aware IDS (PROCESS_SAFETY_VIOLATION shadowing of tank levels) is strongest precisely because it protects the highest-impact failure mode — an unsafe command issued against a full tank — without adding latency to legitimate operations.

From a continuity perspective the environment currently exhibits one material weakness: the **historian has no implemented backup** (SR_7.3 is rated Simulated), so a ransomware event (RSK-008) converts a recoverable availability incident into a permanent data loss incident. Similarly, the gateway's role as the sole chokepoint means its own compromise must be treated as a contingency-planning scenario, not just a detection scenario. The BIA therefore recommends elevating both items in the remediation roadmap and committing to quarterly restore exercises of the golden PLC logic and the historian dataset.

In summary, the facility is prepared to tolerate a **30-minute-to-2-hour control outage** with acceptable consequences, provided the gateway and Treatment PLC are prioritized in recovery sequencing and the historian backup gap is closed. These objectives are consistent with the IEC 62443 SL-2 target: the environment resists simple, low-resource intentional attack (SL-2) while the highest-value recovery processes are exercised and measured.

---

**Approved By:** Plant Manager / OT Security Director
**Next Review:** 2026-11-01 (or after any change to the control architecture)
