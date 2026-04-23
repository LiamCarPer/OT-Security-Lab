# Deployment & Validation Guide

This document explains how to deploy the `ot-security-lab` and verify its security configurations.

## 1. Deployment
Ensure you have **Docker Compose V2** installed.

```bash
cd lab-environment
sudo docker compose up -d
```

## 2. Network Topology Verification
Verify the IP addresses and interface mapping for the Purdue zones:
```bash
# Check container statuses and IPs
sudo docker ps
sudo docker inspect ot_gateway
```

## 3. Applying the Firewall
The `ot_gateway` must be manually configured with the zone-based firewall rules:
```bash
sudo docker cp network-config/firewall-rules.sh ot_gateway:/firewall-rules.sh
sudo docker exec ot_gateway chmod +x /firewall-rules.sh
sudo docker exec ot_gateway /firewall-rules.sh
```

### 4. Detection Verification (Simulating an Attack)
To verify that the detection scripts and centralized logging are working, follow these steps:

#### 4.1. Start the Detection Monitor
In one terminal, run one of the detection scripts (e.g., Modbus IDS):
```bash
sudo docker exec -it ot_gateway python3 /detection/rules/modbus_anomaly.py
```

#### 4.2. Run the Automated Attack Simulation
In a second terminal, execute the automated attack script from the `ot_attacker` container. This script is designed to trigger all three detection rules:
```bash
# 1. Copy the simulation script to the attacker
sudo docker cp attacker/simulate_attack.py ot_attacker:/simulate_attack.py

# 2. Run the simulation
sudo docker exec -it ot_attacker python3 /simulate_attack.py
```

#### 4.3. Verify the Logs
Check the centralized JSON log file to see the alerts being captured in real-time:
```bash
cat detection/logs/alerts.json
```
**Expected Result:** You will see timestamped JSON entries for `CROSS_ZONE_VIOLATION`, `UNAUTHORIZED_MODBUS_WRITE`, and `OT_BRUTE_FORCE_SCAN`.


## 5. Maintenance
To stop and clean up the environment:
```bash
sudo docker compose down
```
