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

## 4. Detection Verification (Simulating an Attack)
To verify that the detection scripts and centralized logging are working, follow these steps:

### 4.1. Start the Detection Monitor
In one terminal, run the Modbus IDS:
```bash
sudo docker exec -it ot_gateway python3 /detection/rules/modbus_anomaly.py
```

### 4.2. Simulate the Breach (Attacker Container)
In a second terminal, enter the attacker container and attempt a Modbus write:
```bash
# 1. Access the attacker
sudo docker exec -it ot_attacker bash

# 2. Add the route to the control network (if not already done)
ip route add 172.21.0.0/16 via 172.24.0.3

# 3. Simulate a malicious Modbus write using nmap or a python script
nmap -Pn -p 502 --script modbus-discover 172.21.0.2
```

### 4.3. Verify the Logs
Check the centralized JSON log file for the alert:
```bash
cat detection/logs/alerts.json
```
**Expected Result:** A JSON entry with `alert_type: "UNAUTHORIZED_MODBUS_WRITE"` and `mitre_id: "T0831"`.

## 5. Maintenance
To stop and clean up the environment:
```bash
sudo docker compose down
```
