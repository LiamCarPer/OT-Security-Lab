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

This starts: 3 OpenPLC runtimes (L1), real DNP3/OPC UA/S7comm endpoints (L1),
Scada-LTS HMI + MySQL config store (L2), an Industrial DMZ with a reverse proxy
and bastion (L3.5), InfluxDB historian (L3), the EWS/plc-bootstrap deployer (L3),
a compromised-EWS insider (L3), the zone gateway (firewall + persistent IDS),
the Kali attacker (L4), a corporate workstation (L4), and the
Grafana/Loki/Promtail SIEM stack.

### What happens on boot

1. The gateway, attacker, bootstrap, and provisioner images are **pre-baked**
   (Dockerfiles in `gateway/`, `attacker/`, `plc-bootstrap/`, `scada/`), ready in
   seconds.
2. `ot_gateway` applies `firewall-rules.sh`: it **auto-detects** its interfaces
   by subnet (never assume `ethX` ordering — see `LESSONS_LEARNED.md` §2.1) and
   applies default-DROP zone/conduit rules (IEC 62443-3-2), including conduit C5
   (EWS → PLC runtime API 8443).
3. `start_ids.sh` launches all `detection/rules/*.py` as persistent background
   services, writing alerts to `/detection/logs/alerts.json`.
4. `ot_plc_bootstrap` deploys the committed `plc/programs/*/program.zip` bundles
   to each runtime over the OpenPLC REST API (create-user → login → upload →
   compile → start) and asserts `RUNNING`. Bundles that are not committed are
   skipped so the lab still boots (see `plc/programs/README.md`).
5. `ot_scada_provisioner` waits for Scada-LTS and creates the Modbus/TCP
   datasources + datapoints (HR 0,1,2,5,6 per PLC) via its REST API, so the HMI
   is a genuine Modbus master, not a simulation.
6. `ot_attacker` adds its pivot routes to the OT zones via the gateway.
7. The DNP3/OPC UA/S7comm endpoints (`dnp3-outstation/`, `opcua-server/`,
   `s7-plc/`) start on the Control network and route their replies back through
   the gateway, so the circuit is symmetric across the chokepoint (see
   `LESSONS_LEARNED.md` §9.3).
8. `ot_insider` (a compromised EWS) starts in the Operations zone, routes
   Control-zone traffic via the gateway, and carries the real protocol clients
   used by `simulate_{dnp3,opcua,s7comm}_attack.py`.
9. The Modbus **process stand-in** (`modbus-sim-*`, Control zone) serves the
   canonical register map with the ST-level controller logic, so the historian
   path has a real source until the OpenPLC program bundles are committed.
10. `ot_historian_poller` (Supervisory) reads the controllers over C1 and writes
    InfluxDB northbound over C3; `ot_grafana_route` puts Grafana's L3 route in
    its network namespace so the historian dashboard traverses C4.
11. The **DMZ** reverse proxy publishes the HMI on host `:8080`; `ot_bastion` is
    the SSH jump host; `ot_hmi_login_monitor` raises `HMI_LOGIN_FAILURE` for
    repeated failed logins.
12. `ot_scada_provisioner` rotates the Scada-LTS factory password to
    `OT_SCADA_PASS` (default `ot-lab-scada`) on first login.

### Historian data path

`(OpenPLC | stand-in) -C1-> historian-poller -C3-> InfluxDB -C4-> Grafana`

- Verify it: `python3 governance/testing/check_historian.py` (also run as the
  final step of `make compliance`).
- The collector prefers the OpenPLC controllers `172.21.0.10/11/12` and falls
  back to the stand-in `172.21.0.60/61/62`; both serve the same register map.
- Point history is enabled on the Scada-LTS datapoints and a `VIEW_WATER` view
  scaffold is created. Note the OT zones are Docker `internal` networks, so
  Scada-LTS/InfluxDB are not published on the host; query them with
  `docker exec` or through the gateway (Grafana is host-accessible on `:3000`).


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
| `simulate_process_violation.py` | `PROCESS_SAFETY_VIOLATION` (real Modbus FC6 open-valve write against the live, HMI-shadowed process) |
| `simulate_process_violation_spoof.py` | `PROCESS_SAFETY_VIOLATION` (legacy simulated stimulus, used only when no bundles are committed) |
| `simulate_dnp3_attack.py` | `DNP3_UNAUTHORIZED_CONTROL`, `DNP3_RESTART_COMMAND`, `DNP3_UNSOLICITED_DISABLED` (run from `ot_insider`) |
| `simulate_opcua_attack.py` | `OPCUA_BROWSE_REQUEST`, `OPCUA_WRITE_REQUEST`, `OPCUA_METHOD_CALL` (run from `ot_insider`) |
| `simulate_s7comm_attack.py` | `S7COMM_PROGRAM_DOWNLOAD`, `S7COMM_PROGRAM_UPLOAD`, `S7COMM_CHANGE_OPERATING_MODE` (run from `ot_insider`) |

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
