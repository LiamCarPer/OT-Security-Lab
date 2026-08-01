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
