#!/usr/bin/env python3
"""
OT Security Lab - Automated Attack Simulation Script
Fulfills 'Enhancement 1' - Fires all 3 detection rules:
1. Cross-Zone Traffic (IT -> Control)
2. Modbus Anomaly (Unauthorized Write)
3. Brute Force (High Exception Rate)
"""
import time
from scapy.all import IP, TCP, Raw, send

# 1. Configuration: Target IPs based on the Purdue Model
PLC_IP = "172.21.0.10"   # Target: Intake PLC (Level 1)
HMI_IP = "172.22.0.10"   # Target: HMI (Level 2)
MODBUS_PORT = 502

def send_modbus_packet(target, function_code, unit_id=1, payload=b"\x00\x01\x00\x01"):
    """Sends a raw Modbus/TCP packet using Scapy."""
    # MBAP Header: Trans ID (2), Proto ID (2), Length (2), Unit ID (1)
    # Followed by Function Code (1) and Payload
    mbap = b"\x00\x01\x00\x00\x00\x06" + bytes([unit_id])
    modbus_data = bytes([function_code]) + payload
    
    packet = IP(dst=target)/TCP(dport=MODBUS_PORT)/Raw(load=mbap + modbus_data)
    send(packet, verbose=False)
    print(f"[ATTACK] Sent Modbus FC {function_code} to {target}")

print("--- Starting OT Security Lab: Automated Attack Simulation ---")
print("Targeting: " + PLC_IP)

# ATTACK 1: Trigger 'Cross-Zone Traffic' Rule
# Simply sending a packet from IT subnet (where this runs) to Control subnet.
print("\n[STEP 1] Triggering Cross-Zone Detection...")
send_modbus_packet(PLC_IP, 3) # Simple Read (FC 3)
time.sleep(1)

# ATTACK 2: Trigger 'Modbus Anomaly' Rule
# Sending a WRITE command (FC 6) from an unauthorized IP (Attacker).
print("\n[STEP 2] Triggering Modbus Anomaly (Unauthorized Write)...")
send_modbus_packet(PLC_IP, 6) # Write Single Register (FC 6)
time.sleep(1)

# ATTACK 3: Trigger 'OT Brute Force' Rule
# Sending a burst of packets to trigger exceptions (requires the PLC to be reachable).
# Even if blocked by the firewall, the gateway's IDS will see the attempts.
print("\n[STEP 3] Triggering Brute Force (High Exception Rate)...")
for i in range(7):
    # To simulate errors, we can send invalid Function Codes (> 128)
    # A real error from a PLC would be FC + 128.
    send_modbus_packet(PLC_IP, 131) # Exception for Read (3 + 128)
    time.sleep(0.5)

print("\n--- Simulation Complete. Check detection/logs/alerts.json for alerts. ---")
