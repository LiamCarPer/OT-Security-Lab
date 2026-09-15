#!/usr/bin/env python3
"""OPC UA server endpoint for the lab.

A real ``asyncua`` server (security policy ``None`` so the service layer is
observable by the passive DPI) exposing the intake process: a writable tank
level and inlet valve, plus a callable ``OpenValve`` method.
"""
import asyncio
import os

from asyncua import Server, ua
from asyncua.common.methods import uamethod

ENDPOINT = os.getenv("OT_OPCUA_ENDPOINT", "opc.tcp://0.0.0.0:4840/freeopcua/server/")
NAMESPACE = "http://ot-security-lab.local/water"


async def main():
    server = Server()
    await server.init()
    server.set_endpoint(ENDPOINT)
    server.set_server_name("OT Security Lab - Intake PLC")

    index = await server.register_namespace(NAMESPACE)
    tank = await server.nodes.objects.add_object(index, "IntakeTank")
    level = await tank.add_variable(index, "TankLevel", 0)
    valve = await tank.add_variable(index, "InletValve", 0)
    alarm = await tank.add_variable(index, "InterlockAlarm", 0)
    await level.set_writable()
    await valve.set_writable()
    await alarm.set_writable()

    @uamethod
    def OpenValve(parent, value):
        return value

    await tank.add_method(
        ua.NodeId("OpenValve", index),
        ua.QualifiedName("OpenValve", index),
        OpenValve,
        [ua.VariantType.Int64],
        [ua.VariantType.Int64],
    )

    print(f"OPC UA server listening on {ENDPOINT} (plaintext None policy)", flush=True)
    async with server:
        await asyncio.sleep(1)
        while True:
            current = await level.get_value()
            await level.write_value((current + 1) % 100)
            await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())
