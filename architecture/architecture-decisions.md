# Architecture Decision Records (ADR)

This document tracks the critical technical decisions made during the
design of the `ot-security-lab`. Each decision is grounded in
**IEC 62443** principles, the **Purdue Reference Model**, and
real-world industrial security best practices.

Each ADR follows the format:
- **Decision** — what was chosen
- **Rationale** — why it was chosen
- **Consequences** — what tradeoffs or constraints this introduces
- **Status** — Accepted / Superseded / Deprecated

---

## ADR-01: Multi-PLC Functional Separation

**Decision:** Implement three discrete PLCs representing three
sub-processes: Intake (PLC-01), Treatment/Filtration (PLC-02),
and Distribution (PLC-03).

**Rationale:** A single monolithic PLC would not reflect real
industrial environments, where functional separation is standard
practice for both operational reliability and security. Separate PLCs
allow demonstration of **East-West (PLC-to-PLC) traffic monitoring** —
a common blind spot in OT security where lateral movement can occur
entirely within Level 1 without crossing any IT/OT boundary.

**Consequences:** Requires defining inter-PLC communication rules
explicitly in the zone/conduit design. PLC-to-PLC traffic must be
treated as a conduit and monitored, not implicitly trusted. Adds
complexity to the Docker Compose topology.

**Status:** Accepted.

---

## ADR-02: Historian Placement at Level 3 (Operations)

**Decision:** Locate the process historian (InfluxDB) within the
Level 3 Operations zone, not Level 2.

**Rationale:** Placing the historian at Level 2 would expose it to
direct queries from corporate users, pulling IT-originated traffic
into the supervisory network. Level 3 placement creates a **tiered
data architecture**: Level 2 pushes data northbound to Level 3 via
a controlled conduit; corporate users at Level 4 query Level 3 only.
The supervisory and control networks are never directly reached by
IT-originated connections.

**Consequences:** Requires a one-way or tightly restricted conduit
from Level 2 to Level 3 for data push. Read access from Level 4 to
Level 3 must be scoped to specific ports and authenticated. Increases
data latency marginally but is operationally acceptable.

**Status:** Accepted.

---

## ADR-03: Engineering Workstation (EWS) Dedicated Enclave

**Decision:** Isolate the Engineering Workstation in a dedicated
sub-zone within Level 3, with restrictive ACLs separate from the
general Operations zone.

**Rationale:** The EWS is the highest-value target in an OT
environment — it holds PLC project files, ladder logic, and has
direct write access to field devices. It is the primary target of
sophisticated ICS malware (e.g., Stuxnet specifically targeted
Siemens Step 7 engineering software). Isolating it within a
**Privileged Access Management (PAM) enclave** ensures that a
compromise of the general Operations zone does not automatically
grant write access to PLCs without traversing an additional
security boundary.

**Consequences:** Remote engineering access must be explicitly
routed through the DMZ Jump Host → Operations zone → EWS enclave
(two hops). This adds access friction that must be documented
in the Remote Access policy. Direct connections from any zone
other than the EWS enclave to PLCs are blocked by default.

**Status:** Accepted.

---

## ADR-04: Industrial DMZ (iDMZ) with Jump Host and Reverse Proxy

**Decision:** Deploy an Industrial DMZ between Level 4 (Enterprise)
and Level 3 (Operations) containing two services: a Jump Host
(for remote engineering access) and a Reverse Proxy (for
web-based dashboard viewing).

**Rationale:** Implements the IEC 62443 "break in communication"
principle — no direct network sessions are permitted between the
business network and the industrial network. All connections must
terminate in the iDMZ and initiate a new session into the target
zone. This enforces **Zero Trust** at the network boundary:
"Never trust, always verify." The Jump Host provides controlled,
auditable access for engineers. The Reverse Proxy allows
Grafana/dashboard visibility to corporate users without exposing
Level 3 directly.

**Consequences:** All remote access now has a mandatory
iDMZ chokepoint — this is a feature, not a limitation. Requires
that the Jump Host itself be hardened and monitored (it becomes
a high-value target). Session recording on the Jump Host is
listed as a future enhancement.

**Status:** Accepted.

---

## ADR-05: Dedicated Gateway Container as Chokepoint Firewall

**Decision:** Implement a dedicated Linux container acting as the
zone gateway and firewall, through which all inter-zone traffic
must route. Docker's default bridge networking is not used for
security-critical zone boundaries.

**Rationale:** Default Docker bridge networking allows containers
on the same host to communicate freely with only host-level
iptables as a control. This does not reflect real OT environments
where inter-zone traffic passes through a **dedicated security
appliance** (e.g., Fortinet FortiGate, Cisco ISA, Palo Alto).
The gateway container — running iptables with explicit ACCEPT/DROP
rules per conduit — simulates this chokepoint architecture and
demonstrates understanding of **defense-in-depth at the network
boundary** rather than relying on implicit Docker isolation.

**Consequences:** All inter-zone traffic must be explicitly
permitted via firewall rules in `firewall-rules.sh`. Default
posture is DENY ALL. This increases the documentation burden
but is precisely what a production OT environment requires.
Any new conduit requires an explicit rule change — this is
intentional and auditable.

**Status:** Accepted.

---

## ADR-06: Safety PLC (SIS) Air-Gap Isolation

**Decision:** Designate PLC-03 (Distribution) as a simplified
Safety Instrumented System (SIS) proxy, placed on a logically
isolated segment with no network path to the HMI or historian.

**Rationale:** In real water treatment facilities, the Safety
Instrumented System (overpressure shutoffs, chemical dosing
limits, pump protection) operates independently from the Basic
Process Control System (BPCS) — this is a core requirement of
IEC 61511 and directly relevant to IEC 62443 zone design.
Placing the safety logic on the same network as the HMI creates
a scenario where a compromised HMI could interfere with safety
functions — exactly the attack vector used in the TRITON/TRISIS
malware incident (2017, Saudi Arabia). Even a simulated
separation demonstrates understanding of why **Availability
and Safety take precedence over Confidentiality** in OT, and
why OT security decisions are fundamentally different from IT.

**Consequences:** The SIS segment has no Modbus polling from
the SCADA system — it operates autonomously. This means no
historian data for the safety PLC, which is realistic.
Process values from the SIS are only readable via a dedicated
one-way data feed, not a bidirectional Modbus connection.

**Status:** Accepted.

---

## ADR-07: Passive Network Sensor for OT Visibility

**Decision:** Deploy a dedicated "Network Sensor" container
running `tcpdump` in promiscuous mode, with output piped to
`Suricata` for IDS alerting and forwarded to Grafana/Loki
for visualization.

**Rationale:** A core challenge in OT security is **visibility
without interference** — you cannot install agents on PLCs,
and active scanning can disrupt industrial processes. The
industry standard is **passive traffic monitoring** via a
mirror port (SPAN port on a managed switch). This sensor
container replicates that pattern: it observes all traffic
on the OT network segment without injecting any packets,
providing detection capability with zero process impact.
This mirrors the architecture of commercial OT monitoring
tools (Claroty, Nozomi Networks, Dragos Platform).

**Consequences:** The sensor container must be on a Docker
network that receives mirrored traffic from all OT segments.
Suricata rules must be OT-specific — standard IT IDS rules
will generate excessive false positives on industrial protocol
traffic. Custom rules are maintained in `detection/suricata-rules/`.

**Status:** Accepted.

---

## ADR-08: Simulated Internet Access at Level 4

**Decision:** The Level 4 Enterprise zone has simulated
outbound internet access, and the Attacker container operates
as an external threat actor with Command & Control (C2)
reach-back capability.

**Rationale:** Real-world OT attacks consistently follow the
pattern: internet-facing asset compromise → lateral movement
into IT network → pivot into OT network. Restricting the
simulation to a purely internal scenario would make the
threat model unrealistic and the detection rules trivial.
Simulating C2 reach-back (even as a simple HTTP callback to
the Attacker container) allows the detection rules to
demonstrate realistic **kill chain detection**, not just
anomaly detection in a sterile environment.

**Consequences:** The Attacker container must be network-isolated
from OT zones by default — it can only reach Level 4 directly.
Any path from the Attacker container to Level 3/2/1 must
traverse the iDMZ and gateway container, which is the point:
the detection rules validate that this traversal is caught.

**Status:** Accepted.