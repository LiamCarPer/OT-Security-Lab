# Deployment & Validation Guide

This document explains how to deploy the `ot-security-lab` and verify its
security configurations. The environment is fully automated: **firewall rules
and IDS rules are applied automatically when the gateway container boots** — no
manual `docker cp` / `docker exec` steps are required.

## 1. Prerequisites

- **Docker Engine** with **Compose V2** (`docker compose` plugin).
- ~4 GB of available memory for the full stack.

## 2. Deployment

```bash
cd lab-environment
sudo docker compose up -d
```

This starts: 3 OpenPLC runtimes (L1), Scada-LTS HMI (L2), InfluxDB historian (L3),
the zone gateway (firewall + persistent IDS), the Kali attacker (L4), and the
Grafana/Loki/Promtail SIEM stack.

### What happens on boot

1. The gateway and attacker images are **pre-baked** (Dockerfiles in
   `gateway/` and `attacker/`) — no runtime package installs; containers are
   ready in seconds.
2. `ot_gateway` applies `firewall-rules.sh`: it **auto-detects** its interfaces
   by subnet (never assume `ethX` ordering — see `LESSONS_LEARNED.md` §2.1) and
   applies default-DROP zone/conduit rules (IEC 62443-3-2).
3. `start_ids.sh` launches all `detection/rules/*.py` as persistent background
   services, writing alerts to `/detection/logs/alerts.json`.
4. `ot_attacker` adds its pivot routes to the OT zones via the gateway.

## 3. Network Topology Verification

```bash
# Container status and IPs
sudo docker ps
sudo docker inspect ot_gateway

# Firewall policy as applied
sudo docker exec ot_gateway iptables -L -n

# IDS rules running?
sudo docker exec ot_gateway sh -c "pgrep -af python3"
sudo docker exec ot_gateway sh -c "tail -5 /detection/logs/*.out"
```

## 4. Detection Verification (Simulated Attacks)

The attacker container includes automated simulation scripts:

| Script | Triggers |
| :--- | :--- |
| `simulate_attack.py` | `CROSS_ZONE_VIOLATION`, `UNAUTHORIZED_MODBUS_WRITE`, `OT_BRUTE_FORCE_SCAN` |
| `simulate_lateral_movement.py` | Sequential `CROSS_ZONE_VIOLATION` (Intake → Treatment → Distribution) |
| `simulate_process_violation.py` | `PROCESS_SAFETY_VIOLATION` (spoofed high tank level + unsafe valve command) |

```bash
sudo docker exec ot_attacker python3 /attacker/simulate_attack.py
sudo docker exec ot_attacker python3 /attacker/simulate_process_violation.py
tail -f detection/logs/alerts.json
```

### Automated Compliance Test

From the repository root, run the full validation suite (it archives the
previous evidence, replays every simulation, and asserts each expected alert):

```bash
python3 governance/testing/run_security_tests.py --reset
```

## 5. SIEM Access

- **Grafana:** http://localhost:3000 (anonymous admin access enabled for the lab)
- **Loki:** http://localhost:3100 (metrics/health only)

## 6. Maintenance

```bash
sudo docker compose down          # stop everything
sudo docker compose down -v       # stop + remove volumes/networks
sudo docker compose up -d --build # rebuild
```
