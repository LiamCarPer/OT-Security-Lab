# SIS vs BPCS Separation: Concept, Requirements, and Lab Demonstration

**Scope:** OT-Security-Lab — simulated Water Treatment & Filtration facility
**Reference Standards:** IEC 61511 (Functional Safety — Safety Instrumented Systems),
IEC 62443-3-3 (FR3: System Integrity, FR5: Network Segmentation)
**Related Lab Evidence:** ADR-06, `detection/rules/process_safety_violation.py`

---

## 1. Concept: Two Distinct Control Layers

| System | Full Name | Role | Objective | Standard |
| :--- | :--- | :--- | :--- | :--- |
| **BPCS** | Basic Process Control System | Operates the process within normal limits (regulate flow, dosing, levels) | Production efficiency and process control | IEC 61511 (host layer), IEC 62443 |
| **SIS** | Safety Instrumented System | Detects a hazardous condition and brings the process to a safe state (trip, shutdown, isolation) | Risk reduction to a tolerable level (Safety Integrity Level, SIL) | IEC 61511 |

The defining principle of IEC 61511 is **independence**: the safety functions must remain
functional even when the BPCS fails — including when the BPCS is compromised by an
attacker. A safety function shares the failure modes of the BPCS if it shares the BPCS's
controllers, networks, power supplies, or sensors. Independence is achieved through
separation: separate logic solvers, separate field wiring, and separate network segments.

## 2. Why Physical Separation Is Required in High-SIL Sites

In plants targeting SIL 2 or higher, the separation between SIS and BPCS is not merely a
best practice — it is an architectural requirement derived from the safety analysis:

- **Random failure independence (IEC 61511-1 clause 11.2.4):** SIS logic solvers must
  fail independently of the BPCS. A shared controller or shared network is a common-cause
  failure mode that destroys the SIL calculation.
- **Cyber-security integrity:** TRITON/TRISIS (2017, Saudi Arabia) demonstrated that when
  safety controllers are reachable on the same network as the BPCS, an attacker can
  re-engineer and weaponize safety logic directly. Separating the SIS network makes the
  attack surface physically (or at least logically, with compensating controls) smaller.
- **Availability of the safety layer:** If the SIS is disturbed by BPCS traffic storms,
  firmware updates, or maintenance, the plant operates without risk reduction. Separation
  ensures the safety layer is not a casualty of operational activity.
- **Standards position:** IEC 61511 requires a written justification (Hazard and Risk
  Assessment) when SIS and BPCS share any component; for high-SIL applications such
  sharing is typically not justifiable, so segregation becomes the norm.

## 3. The Lab Model: Compensating Controls for a Virtualized Environment

A Docker-based lab cannot provide true physical independence (no separate controllers,
no hardwired field devices). The lab therefore models the concept using **two independent,
mutually reinforcing layers** that do not share failure modes — a compensating-control
pattern aligned with IEC 61511's "proven in use" alternatives and IEC 62443 defense in
depth:

### 3.1 Layer 1 — Safety Interlocks inside the PLC Logic (BPCS-hosted, ST)

- The safety interlock (e.g., "do not open the inlet valve while tank level exceeds
  threshold") is implemented in Structured Text logic in the OpenPLC runtime at Level 1
  (`plc_intake`, 172.21.0.10).
- This models a *basic* protective function executed at the point of control, with
  minimal communication dependencies: it evaluates local register state and gates
  actuator commands regardless of network conditions.
- Limitation acknowledged by the design: as BPCS-hosted logic, it shares the PLC's
  processing platform. In the lab it represents the innermost layer of the safety onion,
  not the full IEC 61511 SIS.

### 3.2 Layer 2 — Network-Side Physics-Aware Shadow Monitor (Independent Observer)

- `detection/rules/process_safety_violation.py` passively shadows PLC register state
  (tank level register 5, inlet valve register 0) from Modbus read responses and
  evaluates every write command against the same interlock rule: opening the inlet valve
  above the 90% level threshold raises PROCESS_SAFETY_VIOLATION (T0836).
- This layer is **architecturally independent of the PLC**: it runs on the gateway
  (172.24.0.2), uses its own state model, and cannot be disabled by a write to the PLC.
  It models the *independent safety observer* pattern — the network analogue of a
  separate safety logic solver.
- It detects exactly the class of failure the interlock itself cannot report: the PLC
  logic being *bypassed or tampered* via a protocol-valid command, or a compromised HMI
  (172.22.0.10) issuing commands that the local interlock should have rejected.

### 3.3 Why This Is Defense in Depth, Not Redundancy

- **Redundancy** duplicates the same function; **defense in depth** layers *different*
  mechanisms so that a single failure or bypass does not compromise the outcome.
- If the PLC interlock fails (logic overwritten, TRITON-style), the shadow monitor still
  detects the unsafe command. If the network observer is lost, the PLC interlock still
  enforces safety locally. Neither layer alone is the SIS; together they reproduce the
  *behavior* of SIS/BPCS independence that IEC 61511 demands.
- ADR-06 extends the concept: PLC-03 (Distribution) is designated a simplified SIS proxy
  on a logically isolated segment with **no Modbus polling from the SCADA system**,
  modeling the air-gap requirement — the TRITON attack vector is blocked by construction.

## 4. Mapping to Standards

| Standard | Requirement | Lab Control |
| :--- | :--- | :--- |
| IEC 61511-1 clause 11.2 | Independence of safety functions | Shadow monitor runs on separate host with independent state (`process_safety_violation.py`) |
| IEC 61511-1 clause 5.2.4 (hazard analysis) | SIS vs BPCS sharing requires justification | ADR-06 documents the segregation decision and its rationale |
| IEC 62443-3-3 FR3 / SR 3.4 | Application / integrity monitoring | Physics-aware detection verifies control commands against process invariants |
| IEC 62443-3-3 FR5 | Zone segmentation | SIS-proxy PLC on isolated segment; no SCADA polling path (ADR-06) |
| MITRE ATT&CK for ICS T0836 | Modify Alarm/Safety Settings | PROCESS_SAFETY_VIOLATION rule detects interlock-bypass attempts |

## 5. Verification Evidence

- Live detection log entry (2026-04-25): PROCESS_SAFETY_VIOLATION raised with context
  "Current Tank Level: 95%, Command: OPEN Inlet Valve" — the exact interlock-violation
  case described above: `detection/logs/alerts.json`
- Sigma rule formalizing the detection for SIEM portability:
  `detection/sigma/process_safety_violation.yml`
- Simulation evidence: `evidence/physics_violation_demo.png`

## 6. Honest Limitations

- The lab uses one OpenPLC runtime per PLC; the "SIS" is not a certified IEC 61511
  safety logic solver, and SIL certification cannot be claimed for any component.
- Isolation between PLC-03 and the SCADA system is logical (Docker network isolation),
  not physical air-gap or hardwired safety relays.
- In a real high-SIL site, the SIS would be a certified device with its own wiring,
  power, and maintenance chain — the compensating controls here demonstrate the
  *security architecture pattern*, not functional safety compliance.
