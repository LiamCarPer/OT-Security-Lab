# Lessons Learned: Building the OT Security Lab

This document tracks the technical challenges, troubleshooting steps, and engineering decisions encountered during the development of this project. It serves as a "Technical Post-Mortem" to demonstrate problem-solving skills and architectural maturity.

---

## 1. Virtualization & Infrastructure

### 1.1 Docker Compose V1 to V2 Migration
- **Problem:** Attempting to update the environment resulted in a `KeyError: 'ContainerConfig'` when using the legacy `docker-compose` (Python-based) tool.
- **Root Cause:** The legacy tool is deprecated and incompatible with modern Docker engine data structures, specifically when recreating containers with updated capabilities.
- **Solution:** Migrated the entire lab to **Docker Compose V2** (Go-based plugin). This involved installing `docker-compose-v2` and transitioning to the `docker compose` (no hyphen) command.
- **Engineering Judgment:** In a production environment, maintaining up-to-date orchestration tools is critical for security and stability. Legacy tools often fail silently or produce cryptic errors when underlying system APIs change.

### 1.2 The "Ghost Container" Conflict
- **Problem:** Recreating containers failed with "Conflict: Container name already in use" errors, even after running `docker rm`.
- **Root Cause:** Failed deployments left orphaned containers with non-standard names (e.g., hash prefixes) that were still "squatting" on Docker network resources and internal names.
- **Solution:** Performed a "Hard Reset" using `docker ps -aq` to identify and forcibly remove all project-related container IDs before restarting the environment.
- **Lesson:** Always verify the state of the Docker daemon after a failed deployment. Residual artifacts can cause cascaded failures in network and volume mounting.

---

## 2. Networking & Segmentation

### 2.1 Dynamic Subnet Assignment
- **Problem:** The `firewall-rules.sh` script initially failed because interface mapping (`eth0`, `eth1`, etc.) did not match the intended Purdue Zones.
- **Root Cause:** Docker assigns subnets and interfaces dynamically based on the order in which networks are initialized in the `docker-compose.yml`. Our assumption of alphabetical or sequential mapping was incorrect.
- **Solution:** Implemented a **Verification Protocol**: use `docker network inspect` to map subnets to zones, followed by `docker exec ip addr` inside the gateway to match interfaces to those subnets.
- **Lesson:** **Never assume interface mapping in a virtualized environment.** Always verify the runtime state before applying security policies.

### 2.2 Routing the "Pivot"
- **Problem:** The Attacker container could not reach the PLC even with the gateway in place.
- **Root Cause:** The Attacker did not have a route entry for the Control network. It attempted to send packets to its default gateway (the Docker host) rather than the `ot_gateway` container.
- **Solution:** Manually added a static route inside the Attacker container: `ip route add [Control_Subnet] via [Gateway_IP]`.
- **Requirement:** This required adding the `NET_ADMIN` capability to the Attacker's Docker configuration, mirroring the real-world need for an attacker to reconfigure a compromised host to act as a pivot.

---

## 3. Industrial Software (OT)

### 3.1 Deprecated Image Stewardship
- **Problem:** The original OpenPLC and ScadaBR images returned "Pull Access Denied" or were significantly outdated (v3 legacy).
- **Solution:** Research and transition to modern, actively maintained repositories:
    - **OpenPLC v4** (hosted on `ghcr.io/autonomy-logic`)
    - **Scada-LTS** (modern fork of ScadaBR)
- **Impact:** This required updating port mappings (OpenPLC v4 uses 8443/HTTPS) and adding specific Linux capabilities (`SYS_NICE`, `SYS_RESOURCE`) to the Docker configuration to allow real-time task scheduling.

---

## 4. Detection Engineering & Centralized Logging

### 4.1 Protocol-Aware Anomaly Detection
- **Problem:** Simple port-based detection generated too much noise and didn't catch malicious activity on authorized ports (e.g., Modbus Port 502).
- **Solution:** Implemented **Deep Packet Inspection (DPI)** logic using Python/Scapy to inspect the Modbus payload. By verifying the **MBAP header offsets** (Function Code at index 7), we could specifically alert on **Write Commands** (FC 6, 16) from unauthorized sources.
- **Strategy:** Adopted an **Allow-listing** approach. Rather than blacklisting attackers, we strictly defined the HMI and EWS as the only authorized "Write" sources.

### 4.2 Sliding-Window Brute Force Detection
- **Problem:** Tracking every single Modbus error was inefficient for high-speed scanners.
- **Solution:** Developed a sliding-window algorithm that tracks the frequency of **Modbus Exception Codes** (FC > 128). If a threshold (e.g., 5 errors in 60s) is exceeded, it triggers an alert.
- **Lesson:** Centralized logging to a **JSON format** (`alerts.json`) is essential for auditability. It transforms raw packet capture into machine-readable intelligence that a SIEM or Incident Responder can actually use.

### 4.3 Stateful vs. Stateless Analysis (The Physics-Aware Shift)
- **Problem:** Simple IP-based "Allow-listing" fails if an authorized host (like the HMI) is compromised or if an attacker uses "living-off-the-land" techniques with legitimate Modbus commands.
- **Solution:** Implemented **Stateful Process Shadowing**. The detection engine (`process_safety_violation.py`) tracks the "Physical State" of the plant by sniffing PLC-to-HMI responses. It builds an internal "shadow" of the tank level.
- **Engineering Judgment:** Even if a command is protocol-valid and IP-authorized, if it violates the safety logic of the physical process (e.g., opening an inlet valve when a tank is already full), it must be flagged. This moves the project's maturity from "IT-equivalent Network Security" to true "OT-specific Cyber-Safety."
### 4.4 The SIEM "Observability" Pivot
- **Challenge:** Transforming raw JSON logs (`alerts.json`) into an industry-standard monitoring stack without overwhelming local machine resources.
- **Solution:** Deployed a **Grafana/Loki** stack. Unlike heavyweight solutions like Splunk or ELK, Loki uses metadata-based indexing which is ideal for high-volume logs from a resource-constrained industrial gateway.

### 4.5 The "Multi-Homed" DNS Trap (Docker Networking)
- **Problem:** When the SIEM (Grafana) was connected to both the IT and Ops networks, it encountered "No route to host" and DNS resolution failures for the Loki backend.
- **The Lesson:** Multi-homed containers (bridging two subnets) often confuse the internal Docker DNS resolver (127.0.0.11), which may try to route requests out of the wrong interface.
- **Solution:** Consolidated the SIEM stack on the IT network exclusively. Promtail still ingests logs via host-mounted volumes, but network communication between Grafana and Loki is now confined to a single, stable bridge.
- **Engineering Judgment:** In a real-world OT environment, monitoring tools (Grafana) should ideally reside in the Corporate Zone (Level 4/5) and pull data from an Aggregation Zone (Level 3/DMZ), rather than having a foot in every isolated industrial subnet.

### 4.6 Dashboard Immutability (Infrastructure as Code)
- **Problem:** Manual changes made to the Grafana UI were being lost after container restarts.
- **Solution:** Switched to a full **Dashboard Provisioning** model using JSON templates stored in `siem/dashboards/`.
- **The Takeaway:** In high-compliance industrial environments, "Click-Ops" is a risk. Adopting an **Infrastructure as Code (IaC)** approach ensures that the SIEM state is reproducible, version-controlled, and immutable.

---

## 5. Hardening & Compliance Mindset

### 5.1 Compensating Controls
- **Challenge:** PLCs often lack built-in security features like antivirus or complex authentication.
- **Solution:** Implemented **Compensating Controls** at the network boundary. The lack of host-based security on the PLC is mitigated by the **Industrial DMZ** and the **Gateway Firewall**, enforcing the security requirements of **IEC 62443**.
- **Takeaway:** IT security is about the *host*; OT security is about the *perimeter and the process*.

---

## 6. Personal Reflection: The Mindset Shift

Building this project from scratch forced a fundamental shift in how I view security engineering. Coming from an IT background, my instinct was to "scan and patch." In this lab, I learned that **the network is the security**, and the **process is the priority**.

### Key Realizations:
- **Scans can be Attacks:** In IT, an Nmap scan is a standard audit tool. In OT, a high-speed scan can actually crash legacy PLC network stacks, causing a physical process failure. Detection of reconnaissance is therefore a "Safety" requirement.
- **Context is Everything:** An unauthorized "Write" to a PLC isn't just a security violation; it's a potential safety hazard. Mapping detection rules to **MITRE ATT&CK for ICS** provided the necessary context to understand *why* a specific packet matters.
- **The Power of Segmentation:** Implementing the **Purdue Model** isn't just about firewall rules; it's about building a predictable environment where "Normal" is strictly defined, making "Anomaly" much easier to catch.

This lab is not just a simulation; it is a demonstration of how **Engineering Judgment** and **Protocol-Awareness** are the most effective tools in securing critical infrastructure.

---

## 7. CI/CD Debugging: The Compliance Gate Saga

Adding a machine-verified pipeline (10 CI gates + a live Compliance Gate that boots the lab and replays attacks) produced some of the hardest bugs in this project — all of them invisible to local development. These are the traps and the reasoning that cracked each one.

### 7.1 The Yanked Image Trap
- **Problem:** The Trivy container-scan job failed instantly with no useful error; the Dockerfile-based action `aquasecurity/trivy-action@0.24.0` pulls `ghcr.io/aquasecurity/trivy:0.53.0`.
- **Root Cause:** The Trivy v0.53.0 release had been deleted upstream ("yanked"), so the image no longer existed and the action failed at pull time — a failure mode invisible in any local run.
- **Solution:** Inspected the action's `Dockerfile` via the raw GitHub URL to discover the hidden image pin, then moved to `trivy-action@v0.36.0`, a composite action that uses the runner's own Trivy binary.
- **The Lesson:** Docker-based GitHub Actions pin images you cannot see from your workflow file. Verify action tags and their Dockerfiles before pinning, and prefer composite (non-container) actions.

### 7.2 The Nonexistent Action
- **Problem:** The shellcheck job failed instantly; the workflow referenced `koalaman/shellcheck-action`.
- **Root Cause:** That repository does not exist (HTTP 404). The maintained action is `ludeeus/action-shellcheck`.
- **Solution:** Verified candidate repos and their release tags through the GitHub API before repinning.
- **The Lesson:** Treat third-party action names and tags as untrusted input; validate them against the API rather than assuming they exist.

### 7.3 checkov's Phantom Framework
- **Problem:** The IaC scan failed with `Invalid frameworks specified: docker_compose`.
- **Root Cause:** `docker_compose` is not a checkov framework; compose files are scanned under `all` (CKV_DOCKER checks).
- **Solution:** Switched to `framework: all`, which surfaced real findings (CKV_DOCKER_2/3/7) on the new Dockerfiles: added HEALTHCHECKs, pinned the kali base image by digest (kali publishes only rolling tags), and added inline `# checkov:skip` with explicit reasons for the rootful gateway (legitimate for iptables/NET_ADMIN, with compensating controls).
- **The Lesson:** A "fixing" a gate by pointing it at nothing is worse than failing it loudly. Use the failure annotations to find the real findings and fix those.

### 7.4 The Race Hidden by Slow Boot Installs
- **Problem:** After baking dependencies into images (no runtime apt/pip installs), the Compliance Gate boot started failing at container start.
- **Root Cause:** The original attacker container added its pivot routes *minutes* into startup, after apt installs — long after the gateway was ready. Prebuilt images made the container add routes in the first seconds, racing the gateway's network readiness; a failed `ip route add` terminated the `&&` chain and the container exited.
- **Solution:** A retry loop (`until ip route add ...; do sleep 2; done`) plus `depends_on: gateway`.
- **The Lesson:** Eliminating slow runtime setup exposes latent ordering assumptions. Deterministic images are correct — but the ordering logic they reveal must be made explicit.

### 7.5 cap_drop: ALL Silently Strips DAC_OVERRIDE
- **Problem:** The gateway healthcheck reported unhealthy and `docker compose --wait` failed with `container ot_gateway is unhealthy`; all five IDS rules had "Started" but no `.out` log files existed.
- **Root Cause:** `cap_drop: ALL` removes CAP_DAC_OVERRIDE. Even as root, the gateway could not write the bind-mounted `detection/logs` (owned by uid 1001 on the runner, mode 755). Every rule died at its first log write; the missing `.out` files were the forensic clue.
- **Solution:** Re-add only the needed capabilities: `cap_add: NET_ADMIN, NET_RAW, DAC_OVERRIDE`, keeping `no-new-privileges` and the dropped set otherwise.
- **The Lesson:** Root without capabilities is not root. When hardening containers with capability discipline, audit every filesystem the process must write — including bind mounts owned by other UIDs.

### 7.6 The pgrep Self-Match
- **Problem:** The gateway healthcheck passed while the IDS rules were dead.
- **Root Cause:** `pgrep -f /detection/rules` matches its own command line, so the healthcheck always succeeded.
- **Solution:** The bracket trick — `pgrep -f "[d]etection/rules/"` — the character class prevents the pattern from matching the healthcheck's own command line.
- **The Lesson:** A healthcheck you have never seen fail is not a healthcheck. Prove the failure path before trusting the green state.

### 7.7 The Invisible Webhook Crash
- **Problem:** The alert webhook container crash-looped with exit 1 and *zero* output for several runs; diagnostics showed nothing.
- **Root Cause:** A module-level default `Path(__file__).resolve().parents[2]` raises `IndexError` when the script lives at `/app/` (only two path levels deep). The crash happened before the first print, so logs were empty. Secondary confusion: `python:3.12-slim` has **no** ENTRYPOINT, and exec'ing a non-executable mounted script directly yields 126.
- **Solution:** Environment-driven default path, the script baked into its own image with an explicit `CMD`, and a verbose startup wrapper (`echo`, `ls`, `python3 -V`) so the next failure prints its own autopsy.
- **The Lesson:** Path-derived defaults break silently when the deployment layout changes. Make startup logging loud enough that a crash explains itself.

### 7.8 The Workflow YAML Heredoc Trap
- **Problem:** The Compliance Gate run appeared with the workflow *filename* as its name and zero jobs.
- **Root Cause:** A heredoc body written at column 0 inside a `run: |` block scalar terminated the YAML block early — the workflow failed at load time.
- **Solution:** Indented the heredoc body within the block scalar and validated every workflow with `yaml.safe_load` before pushing.
- **The Lesson:** A workflow that fails to parse produces a run with no jobs and a filename as its title. Parse-check workflow YAML locally; that signature is the tell.

### 7.9 Self-Reporting Diagnostics
- **Problem:** Step logs were unreadable (no token), and every attempt to publish failure diagnostics — GitHub issue posts, commit statuses, paste services — failed silently, leaving each failed run unexplained.
- **Solution:** On failure, the pipeline commits its own diagnostics (boot log, container states, gateway/webhook logs) to a dedicated `ci-diagnostics` branch. An `--allow-empty` commit made the step itself observable, and the branch was readable from the public API. This channel finally produced the tracebacks that cracked 7.5 and 7.7.
- **The Lesson:** When a remote pipeline is a black box, make it publish its own post-mortem to a channel you can read. Self-reporting CI is a feature, not a hack.

### 7.10 Evidence-Refresh Loop Control
- **Problem:** The Compliance Gate commits fresh evidence back to `main` on every green run; unguarded, that push would re-trigger the workflows forever.
- **Solution:** `[skip ci]` in the evidence commit message (Actions honors the convention for push events), plus a rebase-and-retry loop so the evidence push survives races with other writers (e.g., the release workflow's CHANGELOG commit).
- **The Lesson:** Self-modifying pipelines need an explicit loop breaker, and every push to `main` from a workflow must account for concurrent writers.

---

## 8. Making the Process Real: OpenPLC v4 & Scada-LTS

The first iteration of this lab "demonstrated" the physics-aware rule by injecting
spoofed Modbus packets. That was a detection-engineering demo, not an OT lab: the
PLCs ran no logic and the HMI polled nothing. Replacing the simulation with real
infrastructure exposed three hard truths about modern OpenPLC and Scada-LTS.

### 8.1 The Headless Runtime (v4 Is Not v3)
- **Problem:** We assumed we could bind-mount the `.st` files (or the compiled C)
  into the runtime, as many OpenPLC v3 tutorials do.
- **Root Cause:** OpenPLC Runtime v4 is a **dual-process, headless service** (a
  Flask REST API on 8443 that supervises a C/C++ real-time core). There is no web
  UI, no always-on Modbus server, and no hot-folder: programs arrive as an
  authenticated `program.zip`, are compiled on-device to `libplc_*.so`, and
  loaded via `dlopen`.
- **Solution:** A dedicated one-shot deployer (`plc-bootstrap`) drives the full
  lifecycle over the API — `create-user → login → upload-file → poll
  compilation-status → start-plc` — and asserts `RUNNING`.
- **The Lesson:** "OpenPLC" is not one thing. v3 and v4 have incompatible
  deployment models; porting a lab means re-reading the API, not the old guide.

### 8.2 The program.zip Packaging Wall
- **Problem:** `program.zip` is not a folder of `.st` files. The runtime rejects
  MatIEC-era artifacts (`Config0.c`, `glueVars.c`) outright and requires
  STruC++-generated sources (`generated.hpp`, `defines.h`, `configuration.cpp`,
  `pou_*.cpp`) plus the bundled `strucpp_runtime/include/` headers.
- **Root Cause:** The bundle is assembled by the **OpenPLC Editor** (a desktop
  app), not the STruC++ CLI. The CLI compiles ST→C++ but does not emit the
  project configuration, `defines.h` MD5, debug map, or protocol JSON.
- **Solution:** Treat the bundle as an **editor-built, committed artifact** (like
  a compiled firmware image). The `.st` remain the canonical source; the zips are
  produced once by the Editor, committed, and deployed automatically. The runtime
  image is pinned by digest so bundle and runtime versions cannot drift.
- **The Lesson:** Not everything can be generated headlessly. When a vendor's
  build happens in a GUI, version-control the *output* and document the
  regeneration procedure rather than reverse-engineering the codegen.

### 8.3 Scada-LTS Is Not IaC-Friendly (Configuration Lives in a Blob)
- **Problem:** We wanted the HMI to be a *real* Modbus master, provisioned like
  code. Direct SQL seeding looked like the obvious answer.
- **Root Cause:** Scada-LTS stores datasources/datapoints as **Java-serialized
  BLOBs** (`longblob`), and only `id/xid/name` are plain columns. SQL inserts are
  version-fragile and effectively impossible to author by hand.
- **Solution:** Use the session-authenticated **REST API** (datasource type `3` =
  Modbus/IP) from an idempotent provisioner container, and persist the MySQL
  volume. This is the only reproducible path.
- **The Lesson:** "Configuration as code" often means calling an application API,
  not writing to its database. Inspect the storage model before committing to SQL.

### 8.4 Detection Threshold vs. Safety Interlock (Defense in Depth)
- **Design choice:** The SIS-style hard interlock in `intake.st` trips at 95%,
  while the network-side IDS envelope is 90%. The IDS flags a forced valve write
  in the 90–95% band *before* the controller's own interlock has to act.
- **The Lesson:** Two independent controls at different thresholds turn a single
  failure into a detectable, survivable event — the core idea of ICS defense in
  depth.


---

## 9. Multi-Protocol Integration: Four Bugs Real Traffic Exposed

Adding real DNP3, OPC UA and S7comm endpoints (and a compromised-EWS emulation)
took the lab from "detections fire on raw packets" to "detections fire on real
protocol sessions". Getting there surfaced bugs that no synthetic fixture could
have caught — the kind that only appear when traffic must actually traverse a
router, complete a handshake, and be written to disk by a sniffing process.

### 9.1 The Firewall That Only Ever Denied
- **Symptom:** Real protocol clients from the Operations zone timed out against
  controllers in the Control zone, yet the Windows-style scenario "looked"
  secure: the firewall was dropping everything.
- **Root Cause:** `get_iface()` parsed `ip addr` output and captured `$2`, which
  inside a container is `eth3@if194:` (the veth peer index is part of the name).
  Stripping only the trailing colon left `eth3@if194`, so **every conduit rule
  bound a non-existent interface and never matched**. The gateway had never
  forwarded a single legitimate packet; it was a deny-only wall.
- **Solution:** Strip the `@peer` suffix too (`sub(/@.*/, "", iface)`). The
  conduit counters finally moved.
- **The Lesson:** An "allow-list firewall" with zero accepted packets is not a
  control, it is an outage waiting to be labelled a security feature. Counter
  checks (or a positive test) belong in every firewall change.

### 9.2 The Sniffer That Watched One Interface
- **Symptom:** The firewall now forwarded traffic and the endpoints answered,
  but the gateway IDS produced no protocol alerts.
- **Root Cause:** Every rule used `scapy.sniff(iface=None)`, which binds only the
  **default-route interface**, not all interfaces. It happened to work before
  because the attacker's traffic arrived on the default (Enterprise) interface;
  Operations→Control traffic arrives on a different interface and was invisible.
- **Solution:** A shared `capture_interfaces()` helper returns every non-loopback
  interface and all rules sniff that list.
- **The Lesson:** "It detected the attacker" can hide a scoping bug. Multi-homed
  choke points need explicit, deliberate capture scope.

### 9.3 Asymmetric Routing: Replies That Bypass the Choke Point
- **Symptom:** TCP handshakes stalled even with correct conduits: the SYN
  traversed the gateway, but the SYN-ACK took the destination's default route
  straight to the Docker host.
- **Root Cause:** Docker sets each container's default route to its bridge
  gateway and silently drops inter-network forwarding on the host. A request
  routed through the gateway got a reply that never came back.
- **Solution:** Give the control-zone endpoints a default route via the gateway,
  so the return path is symmetric and traverses the same stateful chokepoint.
- **The Lesson:** A stateful firewall only works when **both** directions cross
  it. Verify return-path symmetry, not just the outbound rule.

### 9.4 `dnp3-python` Master: A pybind11 Callback/GIL Crash
- **Symptom:** The opendnp3 master executed one Direct Operate, printed the
  command result, then aborted with
  `PyThreadState_Get: the function must be called with the GIL held`.
- **Root Cause:** The master's command callbacks are invoked from C++ worker
  threads; in a headless script this races the Python interpreter and dies.
- **Solution:** Keep the real opendnp3 **outstation** as the endpoint, but drive
  the attack with a minimal raw DNP3 master that builds CRC-16/DNP-correct link
  frames. The outstation accepts them and responds; the detection is unchanged.
- **The Lesson:** A library that works in an interactive REPL is not necessarily
  usable headless. When a binding is unstable, a protocol-correct raw client is a
  legitimate, documented fallback — and it keeps the test deterministic.

### 9.5 The Warnings That Were Really Exceptions
- **Symptom:** The new DPI producers logged
  `Socket ... failed with 'No such file or directory: /detection/rules/logs/alerts.json'`
  and produced no alerts.
- **Root Cause:** `otdpi/common.py` sits one directory deeper than the rule
  modules, so its two-`dirname` default log path resolved to
  `detection/rules/logs/` instead of `detection/logs/`. Scapy surfaces an
  exception raised inside `prn` as a "socket failure", which disguised a plain
  `FileNotFoundError` as a capture problem.
- **Solution:** Go up three levels from `otdpi/common.py`; the alert log is now
  correct and the same for every producer.
- **The Lesson:** A sniffer that "fails to capture" may simply be throwing in its
  packet handler. Read the exception, not the word "Socket".

### 9.6 One Contract, Many Protocols
- **Design:** DNP3, OPC UA and S7comm each get a real endpoint, a real client
  emulation from a compromised EWS, and a live Scapy decoder that emits the same
  normalized telemetry contract (`ot_ndr`) the generated Loki ruler rules
  consume. The compliance suite asserts both the raw `alert_type` evidence and
  that the generated rules reach `state=firing`.
- **The Takeaway:** Protocol breadth is only credible when each protocol has a
  live producer, a live consumer, and a test that proves the rule actually fired
  — not a curated capture replayed for the camera.

---

## 10. Wiring the L2/L3 Historian Path

The historian was a stock InfluxDB with zero measurements: no collector existed,
and the HMI's datasources had nothing to read because the OpenPLC runtimes were
unprogrammed. Closing the path exposed three more environment realities.

### 10.1 `internal: true` Networks Do Not Publish Ports
- **Symptom:** After adding the historian, `localhost:8086` (InfluxDB) and
  `localhost:8080` (Scada-LTS) refused connections, while `localhost:3000`
  (Grafana) worked.
- **Root Cause:** `ops_network`, `supervisory_network` and `control_network` are
  Docker `internal` networks. Docker skips host port publishing for services
  attached only to internal networks (`NetworkSettings.Ports` was empty), so the
  L2/L3 services are unreachable from the host by design.
- **Solution:** Verify the historian with `docker exec` (the `influx` CLI) and
  Scada-LTS through its container, and reach the data visually through Grafana
  (Enterprise zone, not internal) via conduit C4.
- **The Lesson:** Segmentation has a usability cost. "Publish a port" and "make
  the zone internal" are mutually exclusive; decide which control wins and test
  the access path, don't assume the README's `:8080` still works.

### 10.2 A Labelled Data-Source Stand-In Beats a Dead Pipeline
- **Problem:** The requested path is `OpenPLC → poller → InfluxDB`, but OpenPLC
  v4 only starts its Modbus server after a program with a Modbus server is
  uploaded, and the editor-built `program.zip` bundles are not committed — so
  port 502 was dark and the historian could never fill.
- **Solution:** A documented **Modbus process stand-in** serves the canonical
  register map on 502 and runs the same `plc/intake.st` level controller. The
  collector probes the real controllers first and uses the stand-in only when
  they do not answer, so it upgrades itself the moment the bundles are deployed
  — no code change.
- **The Lesson:** A stand-in used to keep a pipeline *live and testable* is not
  the same as spoofing a detection. Label it, scope it to the missing dependency,
  and make the switch automatic and observable.

### 10.3 Scada-LTS Provisioning Quirks (History and Views)
- **Findings:** Point history is set through `/point_properties/updateProperties`,
  but the handler must be addressed by numeric **id** (the `xid` route returns
  400) and requires `purgeStrategy` in the body (a missing value NPEs into a 400
  with an empty body). `GET /point_properties/getProperties` reports
  `loggingType` as `0` even after a successful save, yet history *is* recorded —
  so verify history with `point_value/getValuesFromTimePeriod`, not the
  properties echo. A view is created with `POST /view/createView` only if
  `imagePath` is the sentinel `"null.png"`.
- **The Lesson:** Application APIs lie in small ways. Trust the observed effect
  (recorded history), not the read-back field, and encode the quirks in the
  provisioner with comments so the next person does not rediscover them.
