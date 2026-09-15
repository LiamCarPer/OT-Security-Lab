# Physics-Aware Detection Rule
# Scenario: Tank Overflow Prevention (Scenario #1)
# Logic: Alert if the Inlet Valve (HR 0) is OPENED while the Tank Level (HR 5)
# is above the safety envelope.
#
# State shadowing: the process image is learned passively from real PLC -> HMI
# Modbus FC 3 responses (no injected/spoofed state). The register map is
# documented in plc/register-map.md and is overridable via OT_* env vars.
import json
import os
from datetime import datetime

import scapy.all as scapy

# 1. Configuration
PLC_IP = os.getenv("OT_PLC_IP", "172.21.0.10")
PLC_ASSET = os.getenv("OT_PLC_ASSET", "PLC-01")
INLET_VALVE_REG = int(os.getenv("OT_REG_INLET_VALVE", "0"))
TANK_LEVEL_REG = int(os.getenv("OT_REG_TANK_LEVEL", "5"))
LEVEL_THRESHOLD = int(os.getenv("OT_LEVEL_THRESHOLD", "90"))
MODBUS_WRITE_FC = {6, 16}
MBAP_LEN = 7
LOG_FILE = os.getenv(
    "OT_ALERT_LOG",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "alerts.json"),
)

# Internal State (Shadowing the PLC holding registers)
shadow_registers = {
    INLET_VALVE_REG: 0,
    TANK_LEVEL_REG: 0,
}

def log_alert(alert_type, src_ip, details, mitre_id, description, tank_level):
    alert_data = {
        # backward-compatible evidence fields
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": src_ip,
        "details": details,
        "mitre_id": mitre_id,
        "description": description,
        # normalized fields consumed by the SIEM rule
        "event_type": alert_type.lower(),
        "asset": PLC_ASSET,
        "actor": src_ip,
        "register": f"HR{INLET_VALVE_REG}",
        "value": 1,
        "tank_level_pct": tank_level,
        "response": "none",
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
        TANK_LEVEL_REG: 0,
    }

def _iter_writes(payload, func_code):
    """Yield (register, value) pairs from a Modbus write PDU.

    MBAP header is 7 bytes; the PDU starts at index 7:
      FC6 : [FC][addr:2][value:2]
      FC16: [FC][start:2][qty:2][byte count:1][values...]
    """
    if func_code == 6 and len(payload) >= 12:
        register = int.from_bytes(payload[8:10], byteorder="big")
        value = int.from_bytes(payload[10:12], byteorder="big")
        yield register, value
    elif func_code == 16 and len(payload) >= 13:
        start = int.from_bytes(payload[8:10], byteorder="big")
        quantity = int.from_bytes(payload[10:12], byteorder="big")
        byte_count = payload[12]
        data_start = 13
        available = byte_count // 2
        for index in range(min(quantity, available)):
            offset = data_start + index * 2
            if offset + 2 > len(payload):
                break
            value = int.from_bytes(payload[offset:offset + 2], byteorder="big")
            yield start + index, value

def process_packet(packet):
    global shadow_registers

    if not (packet.haslayer(scapy.IP) and packet.haslayer(scapy.Raw)):
        return

    payload = bytes(packet[scapy.Raw].load)
    if len(payload) < 8:
        return

    func_code = payload[7]
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst

    # --- PART 1: STATE SHADOWING (passive, from real PLC responses) ---
    if src_ip == PLC_IP and func_code == 3 and len(payload) >= 9:
        byte_count = payload[8]
        register_count = byte_count // 2
        if register_count > TANK_LEVEL_REG:
            data_start = MBAP_LEN + 2  # MBAP + FC + byte count
            offset = data_start + TANK_LEVEL_REG * 2
            shadow_registers[TANK_LEVEL_REG] = int.from_bytes(
                payload[offset:offset + 2], byteorder="big"
            )

    # --- PART 2: SAFETY LOGIC ENFORCEMENT ---
    if dst_ip == PLC_IP and func_code in MODBUS_WRITE_FC:
        for register, value in _iter_writes(payload, func_code):
            if register != INLET_VALVE_REG:
                continue
            if value == 1:
                current_level = shadow_registers[TANK_LEVEL_REG]
                if current_level > LEVEL_THRESHOLD:
                    log_alert(
                        "PROCESS_SAFETY_VIOLATION",
                        src_ip,
                        f"Current Tank Level: {current_level}%, Command: OPEN Inlet Valve",
                        "T0836",
                        "Safety Interlock Violation: Attempted to open inlet valve while "
                        "container is at overflow capacity.",
                        current_level,
                    )
            shadow_registers[INLET_VALVE_REG] = value

def main():
    print("--- Starting Physics-Aware Process Monitor ---")
    print(f"Monitoring PLC {PLC_IP} for Tank Overflow conditions (Threshold: {LEVEL_THRESHOLD}%)...")
    scapy.sniff(iface=None, filter="tcp port 502", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
