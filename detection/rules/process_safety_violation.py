# Physics-Aware Detection Rule
# Scenario: Tank Overflow Prevention (Scenario #1)
# Logic: Alert if Inlet Valve (Reg 0) is OPENED while Tank Level (Reg 5) is > 90%.
import json
import os
from datetime import datetime

import scapy.all as scapy

# 1. Configuration
PLC_IP = os.getenv("OT_PLC_IP", "172.21.0.10")
HMI_IP = os.getenv("OT_HMI_IP", "172.22.0.10")
INLET_VALVE_REG = 0
TANK_LEVEL_REG = 5
LEVEL_THRESHOLD = int(os.getenv("OT_LEVEL_THRESHOLD", "90"))
LOG_FILE = os.getenv(
    "OT_ALERT_LOG",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "alerts.json"),
)

# Internal State (Shadowing the PLC registers)
shadow_registers = {
    INLET_VALVE_REG: 0,
    TANK_LEVEL_REG: 0
}

def log_alert(alert_type, src_ip, details, mitre_id, description):
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": src_ip,
        "details": details,
        "mitre_id": mitre_id,
        "description": description
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert_data) + "\n")

    print(f"\n[CRITICAL ALERT] {alert_type}")
    print(f"Description: {description}")
    print(f"Process Context: {details}")
    print(f"MITRE ID: {mitre_id}\n")

def reset_state():
    global shadow_registers
    shadow_registers = {
        INLET_VALVE_REG: 0,
        TANK_LEVEL_REG: 0
    }

def process_packet(packet):
    global shadow_registers

    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Raw):
        payload = bytes(packet[scapy.Raw].load)
        if len(payload) < 8:
            return

        func_code = payload[7]
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # --- PART 1: STATE SHADOWING (Passive Monitoring) ---
        if src_ip == PLC_IP and func_code == 3:
            byte_count = payload[8]
            if byte_count >= (TANK_LEVEL_REG + 1) * 2:
                level_val = int.from_bytes(payload[19:21], byteorder='big')
                shadow_registers[TANK_LEVEL_REG] = level_val

        # --- PART 2: SAFETY LOGIC ENFORCEMENT ---
        if dst_ip == PLC_IP and func_code == 6:
            reg_addr = int.from_bytes(payload[8:10], byteorder='big')
            reg_value = int.from_bytes(payload[10:12], byteorder='big')

            if reg_addr == INLET_VALVE_REG:
                if reg_value == 1:
                    current_level = shadow_registers[TANK_LEVEL_REG]
                    if current_level > LEVEL_THRESHOLD:
                        log_alert(
                            "PROCESS_SAFETY_VIOLATION",
                            src_ip,
                            f"Current Tank Level: {current_level}%, Command: OPEN Inlet Valve",
                            "T0836",
                            "Safety Interlock Violation: Attempted to open inlet valve while container is at overflow capacity."
                        )

                shadow_registers[INLET_VALVE_REG] = reg_value

def main():
    print("--- Starting Physics-Aware Process Monitor ---")
    print(f"Monitoring PLC {PLC_IP} for Tank Overflow conditions (Threshold: {LEVEL_THRESHOLD}%)...")
    scapy.sniff(iface=None, filter="tcp port 502", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
