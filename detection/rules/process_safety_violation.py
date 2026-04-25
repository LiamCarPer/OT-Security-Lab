# Physics-Aware Detection Rule
# Scenario: Tank Overflow Prevention (Scenario #1)
# Logic: Alert if Inlet Valve (Reg 0) is OPENED while Tank Level (Reg 5) is > 90%.
import scapy.all as scapy
import json
import time
from datetime import datetime

# 1. Configuration
PLC_IP = "172.21.0.10"
HMI_IP = "172.22.0.10"
INLET_VALVE_REG = 0
TANK_LEVEL_REG = 5
LEVEL_THRESHOLD = 90
LOG_FILE = "detection/logs/alerts.json"

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

def process_packet(packet):
    global shadow_registers

    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Raw):
        payload = bytes(packet[scapy.Raw].load)
        if len(payload) < 8:
            return

        # Modbus TCP Header (MBAP) is 7 bytes: [TransID(2), ProtoID(2), Len(2), UnitID(1)]
        # Function Code is at index 7
        func_code = payload[7]
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # --- PART 1: STATE SHADOWING (Passive Monitoring) ---
        # Case A: Observe HMI/PLC synchronization (Read Responses)
        # If the PLC (src) is sending a response to a Read Holding Registers (FC 3)
        if src_ip == PLC_IP and func_code == 3:
            # Response format: [MBAP(7), FC(1), ByteCount(1), RegData(N*2)]
            byte_count = payload[8]
            # If the response contains enough data to include our Tank Level register
            # (Assuming standard polling of multiple registers starting from 0)
            if byte_count >= (TANK_LEVEL_REG + 1) * 2:
                # Reg 5 is at bytes 9 + (5*2) = 19
                level_val = int.from_bytes(payload[19:21], byteorder='big')
                shadow_registers[TANK_LEVEL_REG] = level_val

        # --- PART 2: SAFETY LOGIC ENFORCEMENT ---
        # Case B: Observe Write commands to Inlet Valve
        if dst_ip == PLC_IP and func_code == 6:
            # Write Single Register: [MBAP(7), FC(1), RegAddr(2), RegValue(2)]
            reg_addr = int.from_bytes(payload[8:10], byteorder='big')
            reg_value = int.from_bytes(payload[10:12], byteorder='big')

            if reg_addr == INLET_VALVE_REG:
                # If command is to OPEN the valve (1)
                if reg_value == 1:
                    current_level = shadow_registers[TANK_LEVEL_REG]
                    if current_level > LEVEL_THRESHOLD:
                        log_alert(
                            "PROCESS_SAFETY_VIOLATION",
                            src_ip,
                            f"Current Tank Level: {current_level}%, Command: OPEN Inlet Valve",
                            "T0836", # MITRE: Modify Parameter
                            "Safety Interlock Violation: Attempted to open inlet valve while container is at overflow capacity."
                        )
                
                # Update shadow state for the valve too
                shadow_registers[INLET_VALVE_REG] = reg_value

print("--- Starting Physics-Aware Process Monitor ---")
print(f"Monitoring PLC {PLC_IP} for Tank Overflow conditions (Threshold: {LEVEL_THRESHOLD}%)...")
scapy.sniff(iface=None, filter=f"tcp port 502", prn=process_packet, store=0)
