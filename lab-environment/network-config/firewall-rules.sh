#!/bin/sh

# OT Security Lab - Zone Firewall (single source of truth)
# Enforces IEC 62443-3-2 zones & conduits at L3/L4 on the industrial gateway.
# Interfaces are AUTO-DETECTED from the container's assigned subnets. Never
# assume ethX ordering in Docker (see LESSONS_LEARNED.md, section 2.1).

get_iface() {
    # $1 = expected inet (e.g. 172.24.0.2/24)
    # Inside Docker, `ip addr` prints veth names with a peer suffix
    # (e.g. "eth3@if194:"), so strip both the trailing colon and the @peer.
    ip addr show 2>/dev/null | awk -v want="$1" '
        /^[0-9]+: / { iface = $2; sub(/:$/, "", iface); sub(/@.*/, "", iface) }
        /inet / && $2 == want { print iface; exit }
    '
}

IF_IT=$(get_iface "172.24.0.2/24")            # Level 4/5: Enterprise (IT)
IF_OPS=$(get_iface "172.23.0.2/24")           # Level 3: Operations (Historian)
IF_SUPERVISORY=$(get_iface "172.22.0.2/24")   # Level 2: Supervisory (HMI)
IF_CONTROL=$(get_iface "172.21.0.2/24")       # Level 1: Control (PLCs)
IF_DMZ=$(get_iface "172.25.0.2/24")           # Level 3.5: Industrial DMZ

for zone in IT OPS SUPERVISORY CONTROL DMZ; do
    eval "iface=\${IF_$zone}"
    if [ -z "$iface" ]; then
        echo "[FIREWALL] ERROR: could not auto-detect interface for zone $zone"
        ip addr show
        exit 1
    fi
    echo "[FIREWALL] Zone $zone -> $iface"
done

# 1. Reset all rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# 2. Default policy: deny everything
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Loopback + stateful return traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 4. Gateway management from Level 4 only
# ICMP: connectivity troubleshooting. TCP 22: future bastion/jump-host role.
iptables -A INPUT -i "$IF_IT" -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i "$IF_IT" -p tcp --dport 22 -j ACCEPT

# --- 5. OT Conduits (explicit, zone-to-zone) ---

# Conduit C1: HMI/collector (L2) -> PLCs (L1): Modbus/TCP 502
iptables -A FORWARD -i "$IF_SUPERVISORY" -o "$IF_CONTROL" -p tcp --dport 502 -j ACCEPT

# Conduit C3: HMI/collector (L2) -> Historian (L3): InfluxDB 8086
iptables -A FORWARD -i "$IF_SUPERVISORY" -o "$IF_OPS" -p tcp --dport 8086 -j ACCEPT

# Conduit C4: IT (L4) -> Historian (L3): InfluxDB 8086 (read-only reporting)
iptables -A FORWARD -i "$IF_IT" -o "$IF_OPS" -p tcp --dport 8086 -j ACCEPT

# Conduit C5: EWS (L3 172.23.0.4) -> PLCs (L1): OpenPLC runtime API 8443.
# Source-restricted: only the engineering workstation may deploy logic.
iptables -A FORWARD -i "$IF_OPS" -o "$IF_CONTROL" -s 172.23.0.4 -p tcp --dport 8443 -j ACCEPT

# --- 5b. Multi-protocol conduits (compromised EWS -> controllers) ---
# Source-restricted to the EWS/insider host (172.23.0.20). The historian host
# has no L3 -> L1 path; it receives data northbound on C3 only.

# Conduit C6: insider (L3) -> DNP3 outstation (L1): DNP3/TCP 20000
iptables -A FORWARD -i "$IF_OPS" -o "$IF_CONTROL" -s 172.23.0.20 -p tcp --dport 20000 -j ACCEPT

# Conduit C7: insider (L3) -> OPC UA server (L1): OPC UA/TCP 4840
iptables -A FORWARD -i "$IF_OPS" -o "$IF_CONTROL" -s 172.23.0.20 -p tcp --dport 4840 -j ACCEPT

# Conduit C8: insider (L3) -> S7comm server (L1): S7comm/TCP 102
iptables -A FORWARD -i "$IF_OPS" -o "$IF_CONTROL" -s 172.23.0.20 -p tcp --dport 102 -j ACCEPT

# --- 5c. DMZ conduits (Enterprise <-> DMZ <-> Supervisory) ---

# Conduit C9: Enterprise (L4) -> DMZ: reverse proxy 80 and bastion 22
iptables -A FORWARD -i "$IF_IT" -o "$IF_DMZ" -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i "$IF_IT" -o "$IF_DMZ" -p tcp --dport 22 -j ACCEPT

# Conduit C10: DMZ -> Supervisory (L2): reverse proxy to the HMI 8080
iptables -A FORWARD -i "$IF_DMZ" -o "$IF_SUPERVISORY" -p tcp --dport 8080 -j ACCEPT

# --- 6. Denied-traffic logging (rate-limited, consumed by the SIEM) ---
iptables -A FORWARD -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "FW_DROP: " --log-level 4

echo "[FIREWALL] Rules applied. IT=$IF_IT OPS=$IF_OPS SUPERVISORY=$IF_SUPERVISORY CONTROL=$IF_CONTROL"
