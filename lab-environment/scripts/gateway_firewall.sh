#!/bin/sh

echo "[INIT] Applying ISA/IEC 62443 Industrial Firewall Rules..."

# 1. Clear existing rules
iptables -F
iptables -X

# 2. Default Policy: DROP EVERYTHING
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Allow Loopback
iptables -A INPUT -i lo -j ACCEPT

# 4. Allow Established Connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- CONDUIT DEFINITIONS ---

# Conduit 1: HMI (Ops Zone) to PLCs (Control Zone) for Modbus (502)
# HMI: 172.22.0.10, PLCs: 172.21.0.10-12
iptables -A FORWARD -p tcp -s 172.22.0.10 -d 172.21.0.0/24 --dport 502 -j ACCEPT

# Conduit 2: Historian (Ops Zone) to Plcs for Data (8086/etc) - Just in case
iptables -A FORWARD -p tcp -s 172.23.0.21 -d 172.21.0.0/24 -j ACCEPT

# Conduit 3: Management Zone (IT) to Gateway for SIEM/Monitoring (if needed)
iptables -A INPUT -p tcp -s 172.24.0.0/24 -j ACCEPT

# 5. Logging Dropped Traffic (For IDS visibility)
iptables -A FORWARD -j LOG --log-prefix "[IPTABLES_DROP] " --log-level 4

echo "[DONE] Firewall Rules Applied. Gateway is now a secure boundary."
