#!/usr/bin/env python3
"""S7comm server endpoint for the lab.

Runs the pure-Python S7 server from ``python-snap7`` on TCP/102, exposing data
block DB1 so read/write and PLC control stop work against a real S7 peer. The
memory-card program download/upload service (FC 26-31) is exercised as raw S7
jobs by the emulation client.
"""
import logging
import os
import time
from ctypes import c_char

from snap7.server import Server
from snap7.type import SrvArea

PORT = int(os.getenv("OT_S7COMM_PORT", "102"))
DB_NUMBER = int(os.getenv("OT_S7COMM_DB", "1"))
DB_SIZE = int(os.getenv("OT_S7COMM_DB_SIZE", "128"))


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s\t%(levelname)s\t%(message)s")
    server = Server(log=True)
    server.register_area(SrvArea.DB, DB_NUMBER, (c_char * DB_SIZE).from_buffer(bytearray(DB_SIZE)))
    server.register_area(SrvArea.PE, 0, (c_char * 16).from_buffer(bytearray(16)))
    server.register_area(SrvArea.PA, 0, (c_char * 16).from_buffer(bytearray(16)))
    server.register_area(SrvArea.MK, 0, (c_char * 16).from_buffer(bytearray(16)))
    server.start(tcp_port=PORT)
    print(f"S7comm server listening on tcp/0.0.0.0:{PORT} (DB{DB_NUMBER}, {DB_SIZE} bytes)", flush=True)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
