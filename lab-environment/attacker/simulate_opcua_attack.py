#!/usr/bin/env python3
"""
OT Security Lab - OPC UA adversary emulation from a compromised workstation.

Uses the real ``asyncua`` client over a legitimate Operations -> Control conduit
against an OPC UA server with a plaintext (None) security policy, so the service
layer is visible to the passive DPI. Browsing, writing a node and calling a
method exercise the three OPC UA detections.
"""
import asyncio
import os

from asyncua import Client

URL = os.getenv("OT_OPCUA_ENDPOINT", "opc.tcp://172.21.0.51:4840/freeopcua/server/")
NAMESPACE = "http://ot-security-lab.local/water"


async def main():
    print(f"--- OPC UA emulation against {URL} ---", flush=True)
    client = Client(url=URL)
    await client.connect()
    try:
        index = await client.get_namespace_index(NAMESPACE)

        print("[OPCUA] BrowseRequest: enumerating the address space...", flush=True)
        children = await client.nodes.objects.get_children()
        print(f"[OPCUA]   {len(children)} child nodes visible", flush=True)

        tank = await client.nodes.objects.get_child([f"{index}:IntakeTank"])
        valve = await tank.get_child([f"{index}:InletValve"])

        print("[OPCUA] WriteRequest: setting InletValve = 1...", flush=True)
        await valve.write_value(1)

        print("[OPCUA] CallRequest: invoking OpenValve(1)...", flush=True)
        result = await tank.call_method(f"{index}:OpenValve", 1)
        print(f"[OPCUA]   OpenValve returned {result}", flush=True)
    finally:
        await client.disconnect()
    print("--- OPC UA emulation complete ---", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
