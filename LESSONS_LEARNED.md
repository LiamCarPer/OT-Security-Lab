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
