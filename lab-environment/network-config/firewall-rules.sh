#!/bin/sh

# CORRECTED Interface mapping (verified via 'ip addr')
IF_IT="eth0"           # Level 4/5: Business (172.24.0.x)
IF_OPS="eth1"          # Level 3: Operations (172.23.0.x)
IF_SUPERVISORY="eth2"  # Level 2: Supervisory (172.22.0.x)
IF_CONTROL="eth3"      # Level 1: Control (172.21.0.x)

# 1. Clean up existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# 2. Set default policy: DROP ALL
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Allow internal loopback
iptables -A INPUT -i lo -j ACCEPT

# 4. Global Rule: Allow return traffic (Stateful Inspection)
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- 5. OT Conduits (Allow explicit traffic) ---

# Conduit C1: HMI (Supervisory) to PLC (Control)
# Protocol: Modbus/TCP (502)
iptables -A FORWARD -i $IF_SUPERVISORY -o $IF_CONTROL -p tcp --dport 502 -j ACCEPT

# Conduit C2: PLC (Control) to Historian (Operations)
# Protocol: InfluxDB (8086)
iptables -A FORWARD -i $IF_CONTROL -o $IF_OPS -p tcp --dport 8086 -j ACCEPT

# Conduit C3: HMI (Supervisory) to Historian (Operations)
# Protocol: InfluxDB (8086)
iptables -A FORWARD -i $IF_SUPERVISORY -o $IF_OPS -p tcp --dport 8086 -j ACCEPT

# Conduit C4: Business (IT) to Historian (Operations)
# Protocol: HTTP/Influx Query (8086)
iptables -A FORWARD -i $IF_IT -o $IF_OPS -p tcp --dport 8086 -j ACCEPT

# --- 6. Monitoring & Logging ---
iptables -A FORWARD -j LOG --log-prefix "FW_REJECT: "
