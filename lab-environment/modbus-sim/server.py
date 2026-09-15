#!/usr/bin/env python3
"""Modbus process stand-in for the historian path.

Serves the canonical register map (``plc/register-map.md``) on TCP/502 for one
asset and runs the same level-controller logic as ``plc/intake.st`` so the
historian records a real process curve. This is a **data-source stand-in** for
the OpenPLC controllers until the editor-built ``program.zip`` bundles are
committed; the historian poller switches to the real controllers automatically
when they answer on 502.
"""
import os
import threading
import time

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
from pymodbus.server import StartTcpServer

ASSET = os.getenv("OT_SIM_ASSET", "intake")
INTERVAL = float(os.getenv("OT_SIM_INTERVAL", "1"))
UNIT_ID = int(os.getenv("OT_SIM_UNIT", "1"))
REGISTER_COUNT = 16

# Per-asset field names (holding-register offsets) from plc/register-map.md.
FIELDS = {
    "intake": {0: "valve", 1: "pump", 5: "level", 6: "alarm"},
    "treatment": {0: "flow", 1: "dosing", 2: "rate", 5: "chlorine", 6: "alarm"},
    "distribution": {0: "pump", 1: "pressure", 2: "speed", 5: "runtime", 6: "alarm"},
}


class ProcessModel:
    """Minimal physical model mirroring the OpenPLC ST programs."""

    def __init__(self, asset):
        self.asset = asset
        self.registers = {offset: 0 for offset in FIELDS[asset]}

    def step(self):
        registers = self.registers
        if self.asset == "intake":
            if registers[5] < 20:
                registers[0] = 1
            registers[5] += 1 if registers[0] == 1 else -1
            registers[5] = max(0, min(100, registers[5]))
            if registers[5] > 95:
                registers[0] = 0
                registers[6] = 1
            else:
                registers[6] = 0
            registers[1] = 60 if registers[0] else 0
        elif self.asset == "treatment":
            registers[0] = 40
            registers[5] = registers[5] - 1 if registers[5] > 0 else 0
            if registers[5] < 20:
                registers[1], registers[2] = 1, 50
                registers[5] = min(100, registers[5] + 3)
            elif registers[5] >= 40:
                registers[1], registers[2] = 0, 0
            registers[6] = 1 if registers[5] > 60 or (registers[0] > 0 and registers[5] == 0) else 0
        else:
            if registers[1] > 0:
                registers[1] = max(0, registers[1] - 2)
            else:
                registers[1] = min(10, registers[1] + 1)
                registers[5] = (registers[5] + 1) % 24
            registers[0] = 1 if registers[1] < 2 else 0
            registers[6] = 1 if registers[0] == 1 and registers[1] < 2 else 0
        return registers


def updater(context, model):
    while True:
        registers = model.step()
        for offset, value in registers.items():
            context[UNIT_ID].setValues(3, offset, [int(value) & 0xFFFF])
        if INTERVAL:
            time.sleep(INTERVAL)


def main():
    fields = ", ".join(f"HR{offset}={name}" for offset, name in FIELDS[ASSET].items())
    print(f"Modbus process stand-in: asset={ASSET} tcp/0.0.0.0:502 ({fields})", flush=True)
    block = ModbusSequentialDataBlock(0, [0] * REGISTER_COUNT)
    context = ModbusServerContext(
        slaves=ModbusSlaveContext(hr=block, zero_mode=True), single=True
    )
    model = ProcessModel(ASSET)
    threading.Thread(target=updater, args=(context, model), daemon=True).start()
    StartTcpServer(context=context, address=("0.0.0.0", 502))


if __name__ == "__main__":
    main()
