#!/usr/bin/env python3
"""
OT Security Lab - Lateral Movement Simulation Script
Demonstrates an attacker pivoting across functional sub-processes (Intake -> Treatment -> Distribution).
Fulfills ADR-01 by proving the value of functional separation and multi-PLC monitoring.
"""
import time
import sys

try:
    from scapy.all import IP, TCP, Raw, send
except ImportError:
    print("Error: Scapy not found. Install it with: sudo apt install python3-scapy")
    sys.exit(1)

# Configuration: Static IPs assigned in docker-compose.yml
PLC_INTAKE = "172.21.0.10"
PLC_TREATMENT = "172.21.0.11"
PLC_DISTRIBUTION = "172.21.0.12"
MODBUS_PORT = 502

def send_modbus_read(target, description):
    """Sends a Modbus Read Holding Registers (FC 3) packet."""
    # MBAP Header: Trans ID (2), Proto ID (2), Length (2), Unit ID (1)
    # Unit ID 1, FC 3 (Read), Start 0, Quantity 1
    mbap = b"\x00\x01\x00\x00\x00\x06\x01" 
    modbus_data = b"\x03\x00\x00\x00\x01"
    
    packet = IP(dst=target)/TCP(dport=MODBUS_PORT)/Raw(load=mbap + modbus_data)
    send(packet, verbose=False)
    print(f"[LATERAL] {description} -> Targeting {target}")

print("--- Starting OT Security Lab: Lateral Movement Simulation ---")
print("Scenario: Attacker has bypassed the DMZ and is mapping the Level 1 Control Zone.")
print("-" * 60)

# Step 1: Discover and probe Intake (PLC-01)
time.sleep(1)
send_modbus_read(PLC_INTAKE, "STEP 1: Probing Intake System")

# Step 2: Lateral Movement to Treatment (PLC-02)
# Simulating the search for downstream process controllers
time.sleep(2)
send_modbus_read(PLC_TREATMENT, "STEP 2: Moving Laterally to Treatment/Filtration")

# Step 3: Final Stage Targeting (PLC-03)
# Reaching the Distribution PLC to prepare for process-wide sabotage
time.sleep(2)
send_modbus_read(PLC_DISTRIBUTION, "STEP 3: Escalating to Distribution Control")

print("-" * 60)
print("\n--- Simulation Complete. ---")
print("Evidence: Check 'detection/logs/alerts.json' for sequential CROSS_ZONE_VIOLATION alerts.")
