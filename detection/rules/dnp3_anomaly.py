# DNP3 Anomaly Detection Rule
# Protocol breadth: DNP3 over TCP (port 20000) is common in critical
# infrastructure (electric/water). Frame layout:
#   [0x05 0x64] [LEN] [CTRL] [DST(2)] [SRC(2)] [CRC(2)] [APP_CTRL] [FC] ...
# Function codes that mutate state: 3 (write), 4/5 (direct operate),
# 6-9 (freeze variants), 23 (direct operate unsolicited).
import ipaddress
import json
import os
from datetime import datetime

import scapy.all as scapy

HMI_IP = os.getenv("OT_HMI_IP", "172.22.0.10")
EWS_IP = os.getenv("OT_EWS_IP", "172.23.0.4")
LOG_FILE = os.getenv(
    "OT_ALERT_LOG",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "alerts.json"),
)
AUTHORIZED_OPERATORS = {ipaddress.ip_address(HMI_IP), ipaddress.ip_address(EWS_IP)}
DNP3_WRITE_FC = {3, 4, 5, 6, 7, 8, 9, 23}
DNP3_PORT = 20000

def log_alert(alert_type, src_ip, dst_ip, function_code, mitre_id, description):
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": str(src_ip),
        "dest_ip": str(dst_ip),
        "function_code": function_code,
        "mitre_id": mitre_id,
        "description": description
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert_data) + "\n")

    print(f"[ALERT] {alert_type} | Src: {src_ip} -> Dst: {dst_ip} | FC: {function_code}")

def process_packet(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == DNP3_PORT:
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if len(payload) < 12:
                return
            if payload[0] != 0x05 or payload[1] != 0x64:
                return
            function_code = payload[11]
            if function_code in DNP3_WRITE_FC:
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                try:
                    is_authorized = ipaddress.ip_address(src_ip) in AUTHORIZED_OPERATORS
                except ValueError:
                    is_authorized = False
                if not is_authorized:
                    log_alert(
                        "DNP3_WRITE_UNAUTHORIZED",
                        src_ip,
                        dst_ip,
                        function_code,
                        "T0831",
                        "Unauthorized DNP3 write/operate command detected from an untrusted source."
                    )

def main():
    print("Starting DNP3 Anomaly Detection (Logging to JSON)...")
    print(f"Authorized operator sources: {[str(ip) for ip in AUTHORIZED_OPERATORS]}")
    scapy.sniff(iface=None, filter=f"tcp port {DNP3_PORT}", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
