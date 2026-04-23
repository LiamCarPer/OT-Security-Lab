# Detection script for Cross-Zone Traffic Violation
import scapy.all as scapy
import ipaddress
import json
from datetime import datetime

# 1. Configuration
IT_ZONE_SUBNET = ipaddress.ip_network("172.24.0.0/16")
CONTROL_ZONE_SUBNET = ipaddress.ip_network("172.21.0.0/16")
LOG_FILE = "detection/logs/alerts.json"

def log_alert(alert_type, src_ip, dst_ip, mitre_id, description):
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "mitre_id": mitre_id,
        "description": description
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert_data) + "\n")
    
    print(f"[ALERT] {alert_type} | Src: {src_ip} -> Dst: {dst_ip}")

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        try:
            src_ip_obj = ipaddress.ip_address(src_ip)
            dst_ip_obj = ipaddress.ip_address(dst_ip)
        except ValueError:
            return

        if src_ip_obj in IT_ZONE_SUBNET and dst_ip_obj in CONTROL_ZONE_SUBNET:
            log_alert(
                "CROSS_ZONE_VIOLATION",
                src_ip,
                dst_ip,
                "T0886",
                "Unauthorized direct communication from IT to Control zone detected."
            )

print("Starting Cross-Zone Traffic Monitor (Logging to JSON)...")
scapy.sniff(iface=None, filter="ip", prn=process_packet, store=0)
