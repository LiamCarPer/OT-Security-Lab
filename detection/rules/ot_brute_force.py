import scapy.all as scapy
from collections import defaultdict
import time
import json
from datetime import datetime

# 1. Configuration
ERROR_THRESHOLD = 5 
WINDOW_SECONDS = 60 
LOG_FILE = "detection/logs/alerts.json"

error_tracker = defaultdict(list)

def log_alert(alert_type, src_ip, count, mitre_id, description):
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": src_ip,
        "error_count": count,
        "mitre_id": mitre_id,
        "description": description
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert_data) + "\n")
    
    print(f"!!! [ALERT] {alert_type} | Src: {src_ip} | Count: {count} !!!")

def process_packet(packet):
    if packet.haslayer(scapy.Raw):
        payload = bytes(packet[scapy.Raw].load)
        if len(payload) >= 8:
            function_code = payload[7]
            src_ip = packet[scapy.IP].src

            # Modbus Exception Code detection (FC > 128)
            if function_code > 128:
                current_time = time.time()
                error_tracker[src_ip].append(current_time)
                error_tracker[src_ip] = [t for t in error_tracker[src_ip] if t > current_time - WINDOW_SECONDS]

                if len(error_tracker[src_ip]) >= ERROR_THRESHOLD:
                    log_alert(
                        "OT_BRUTE_FORCE_SCAN",
                        src_ip,
                        len(error_tracker[src_ip]),
                        "T0846",
                        "Excessive Modbus exceptions detected. Possible scanning or brute-force activity."
                    )
                    error_tracker[src_ip] = []

print("Starting OT Brute-Force Detection (Logging to JSON)...")
scapy.sniff(iface=None, filter="tcp port 502", prn=process_packet, store=0)
