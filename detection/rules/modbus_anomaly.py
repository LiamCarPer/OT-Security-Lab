# Detection script for Modbus Anomaly Detection
import scapy.all as scapy
import ipaddress
import json
import time
from datetime import datetime

# 1. Configuration
HMI_IP = "172.22.0.10"
EWS_IP = "172.23.0.10"
LOG_FILE = "detection/logs/alerts.json"

def log_alert(alert_type, src_ip, target_register, mitre_id, description):
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": src_ip,
        "target_register": target_register,
        "mitre_id": mitre_id,
        "description": description
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert_data) + "\n")
    
    # Still print to console for live monitoring
    print(f"[ALERT] {alert_type} | Src: {src_ip} | Target: {target_register}")

def process_packet(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 502:
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if len(payload) >= 8:
                function_code = payload[7]
                src_ip = packet[scapy.IP].src
                
                # Check for WRITE operations
                if function_code in [6, 16]:
                    if src_ip != HMI_IP and src_ip != EWS_IP:
                        reg_addr = int.from_bytes(payload[8:10], byteorder='big')
                        log_alert(
                            "UNAUTHORIZED_MODBUS_WRITE",
                            src_ip,
                            reg_addr,
                            "T0831",
                            "Unauthorized Modbus write command detected from an untrusted source."
                        )

print("Starting Modbus Anomaly Detection (Logging to JSON)...")
scapy.sniff(iface=None, filter="tcp port 502", prn=process_packet, store=0)
