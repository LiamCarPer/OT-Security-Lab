#!/usr/bin/env python3
"""Benign, read-only polling for the OT protocols the attack scripts exercise.

Runs from the approved engineering client (ot_insider, 172.23.0.20) and only
reads:

- DNP3: integrity poll (FC1) from master link address 1;
- OPC UA: read TankLevel / InletValve / InterlockAlarm by NodeId, no browse;
- S7comm: DB read.

The point is to give the Sigma rules real benign input instead of only seeing
these protocols during attacks. No write, control, restart or browse operation
is issued.
"""
from __future__ import annotations

import argparse
import asyncio
import socket
import time

DNP3_HOST = "172.21.0.50"
DNP3_PORT = 20000
DNP3_MASTER = 1
DNP3_OUTSTATION = 10
OPCUA_URL = "opc.tcp://172.21.0.51:4840/freeopcua/server/"
OPCUA_NODES = ("ns=2;i=2", "ns=2;i=3", "ns=2;i=4")  # level, valve, interlock
S7_HOST = "172.21.0.52"
S7_PORT = 102
S7_DB = 1


def crc16_dnp(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def dnp3_frame(application: bytes, control: int = 0xC4) -> bytes:
    user_data = b"\xC0" + application
    length = 5 + len(user_data)
    header = (
        bytes([length, control])
        + DNP3_OUTSTATION.to_bytes(2, "little")
        + DNP3_MASTER.to_bytes(2, "little")
    )
    frame = b"\x05\x64" + header + crc16_dnp(header).to_bytes(2, "little")
    for index in range(0, len(user_data), 16):
        block = user_data[index : index + 16]
        frame += block + crc16_dnp(block).to_bytes(2, "little")
    return frame


def poll_dnp3() -> None:
    with socket.create_connection((DNP3_HOST, DNP3_PORT), timeout=5) as sock:
        # Integrity poll: application control C0 (FIR/FIN/seq0), FC1, class 0/1/2/3.
        sock.sendall(dnp3_frame(b"\xC0\x01\x3C\x02\x06"))
        sock.settimeout(2)
        try:
            sock.recv(4096)
        except OSError:
            pass
    print("[dnp3] integrity poll", flush=True)


async def poll_opcua() -> None:
    from asyncua import Client

    client = Client(url=OPCUA_URL)
    await client.connect()
    try:
        for node_id in OPCUA_NODES:
            value = await client.get_node(node_id).read_value()
            print(f"[opcua] {node_id}={value}", flush=True)
    finally:
        await client.disconnect()


def poll_s7() -> None:
    from snap7.client import Client

    client = Client()
    client.connect(S7_HOST, 0, 1, tcp_port=S7_PORT)
    try:
        data = client.db_read(S7_DB, 0, 4)
        print(f"[s7] DB{S7_DB}={bytes(data).hex()}", flush=True)
    finally:
        client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["dnp3", "opcua", "s7", "all"], default="all")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--duration", type=float, default=0.0, help="0 runs forever")
    args = parser.parse_args()
    deadline = time.time() + args.duration if args.duration else None
    while deadline is None or time.time() < deadline:
        if args.mode in {"dnp3", "all"}:
            try:
                poll_dnp3()
            except OSError as error:
                print(f"[dnp3] {error}", flush=True)
        if args.mode in {"opcua", "all"}:
            try:
                asyncio.run(poll_opcua())
            except Exception as error:  # noqa: BLE001 - report and continue
                print(f"[opcua] {error}", flush=True)
        if args.mode in {"s7", "all"}:
            try:
                poll_s7()
            except Exception as error:  # noqa: BLE001
                print(f"[s7] {error}", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
