# Detection script for Modbus Anomaly Detection
import ipaddress
import json
import os
from datetime import datetime

import scapy.all as scapy

# 1. Configuration
HMI_IP = os.getenv("OT_HMI_IP", "172.22.0.10")
EWS_IP = os.getenv("OT_EWS_IP", "172.23.0.4")
LOG_FILE = os.getenv(
    "OT_ALERT_LOG",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "alerts.json"),
)
AUTHORIZED_WRITERS = {ipaddress.ip_address(HMI_IP), ipaddress.ip_address(EWS_IP)}
MODBUS_WRITE_FC = {6, 16}

def log_alert(alert_type, src_ip, target_register, mitre_id, description):
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": str(src_ip),
        "target_register": target_register,
        "mitre_id": mitre_id,
        "description": description
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert_data) + "\n")

    print(f"[ALERT] {alert_type} | Src: {src_ip} | Target: {target_register}")

def process_packet(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 502:
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if len(payload) >= 8:
                function_code = payload[7]
                src_ip = packet[scapy.IP].src

                if function_code in MODBUS_WRITE_FC:
                    try:
                        is_authorized = ipaddress.ip_address(src_ip) in AUTHORIZED_WRITERS
                    except ValueError:
                        is_authorized = False
                    if not is_authorized:
                        reg_addr = int.from_bytes(payload[8:10], byteorder='big')
                        log_alert(
                            "UNAUTHORIZED_MODBUS_WRITE",
                            src_ip,
                            reg_addr,
                            "T0831",
                            "Unauthorized Modbus write command detected from an untrusted source."
                        )

def main():
    print("Starting Modbus Anomaly Detection (Logging to JSON)...")
    print(f"Authorized write sources: {[str(ip) for ip in AUTHORIZED_WRITERS]}")
    scapy.sniff(iface=None, filter="tcp port 502", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
