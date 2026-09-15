#!/usr/bin/env python3
"""
OT Security Lab - Physics-Aware Violation Simulator (legacy simulated stimulus)

Fallback used only when the real process is unavailable (no committed OpenPLC
program bundles / Scada-LTS not provisioned). It fabricates the state so the
detection pipeline can still be exercised in CI:

1. Spoofs a PLC response indicating the tank level is dangerously high (95%).
2. Sends a 'Write' command to open the inlet valve, which would cause an overflow.

Once `plc/programs/*/program.zip` are committed and the HMI is polling, the
compliance runner uses `simulate_process_violation.py` (real Modbus) instead.
"""
import sys
import time

try:
    from scapy.all import IP, TCP, Raw, send
except ImportError:
    print("Error: Scapy not found.")
    sys.exit(1)

# Configuration
PLC_IP = "172.21.0.10"
HMI_IP = "172.22.0.10"
MODBUS_PORT = 502

def send_raw_modbus(src, dst, sport, dport, payload):
    """Sends a raw TCP/Modbus packet."""
    packet = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport)/Raw(load=payload)
    send(packet, verbose=False)

print("--- Starting Physics-Aware Violation Simulation (simulated fallback) ---")

# --- STEP 1: INJECT 'HIGH LEVEL' STATE ---
# Spoof a Modbus response FROM the PLC TO the HMI to update the IDS shadow-state.
# FC 3 (Read), ByteCount 12 (6 regs), Values: [0, 0, 0, 0, 0, 95]
print("[STEP 1] Injecting process state: Tank Level = 95% (DANGER)...")
mbap_resp = b"\x00\x01\x00\x00\x00\x0f\x01" # TransID 1, Len 15, Unit 1
fc_resp = b"\x03\x0c"                      # FC 3, Byte Count 12
reg_data = b"\x00\x00" * 5 + b"\x00\x5f"   # Regs 0-4=0, Reg 5=95
send_raw_modbus(PLC_IP, HMI_IP, MODBUS_PORT, 45000, mbap_resp + fc_resp + reg_data)

time.sleep(2)

# --- STEP 2: SEND UNSAFE COMMAND ---
print("[STEP 2] Sending unsafe command: OPEN Inlet Valve while level is high...")
mbap_write = b"\x00\x02\x00\x00\x00\x06\x01" # TransID 2, Len 6, Unit 1
fc_write = b"\x06\x00\x00\x00\x01"           # FC 6, Reg 0, Value 1
send_raw_modbus(HMI_IP, PLC_IP, 45000, MODBUS_PORT, mbap_write + fc_write)

print("\n--- Simulation Complete. Check logs for PROCESS_SAFETY_VIOLATION. ---")
