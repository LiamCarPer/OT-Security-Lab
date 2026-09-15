"""S7comm decoder: TPKT + COTP + classic S7 header -> normalized event.

S7comm has no application-layer parser in Sigma or Suricata, so the function
code (read/write, program download/upload, PLC control/stop) and the PDU
reference are decoded natively and emitted as the ``ot_ndr`` / ``s7comm``
telemetry contract. S7comm Plus (protocol id ``0x72``) is not decoded and is
ignored rather than mis-parsed.
"""
from __future__ import annotations

FUNCTION_NAMES = {
    0x00: "CPU Services",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PLC Control",
    0x29: "PLC Stop",
    0xF0: "Setup Communication",
}

ROSCTR_NAMES = {1: "Job", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}


def function_name(function_code: int) -> str:
    return FUNCTION_NAMES.get(function_code, f"Unknown ({function_code})")


def decode(payload: bytes) -> dict | None:
    """Decode one TPKT/COTP/S7 message, or return ``None``."""
    if len(payload) < 6 or payload[0] != 0x03 or payload[1] != 0x00:
        return None

    cotp_length = payload[4]
    cotp_type = payload[5]
    if cotp_type != 0xF0:  # connection setup/confirm carries no S7 header
        return {"cotp_type": cotp_type}

    s7_offset = 5 + cotp_length
    if s7_offset + 10 > len(payload) or payload[s7_offset] != 0x32:
        return None

    rosctr = payload[s7_offset + 1]
    pdu_reference = int.from_bytes(payload[s7_offset + 4:s7_offset + 6], byteorder="big")
    parameter_length = int.from_bytes(payload[s7_offset + 6:s7_offset + 8], byteorder="big")
    data_length = int.from_bytes(payload[s7_offset + 8:s7_offset + 10], byteorder="big")

    event = {
        "direction": "request" if rosctr == 1 else "response",
        "rosctr": rosctr,
        "pdu_reference": pdu_reference,
        "parameter_length": parameter_length,
        "data_length": data_length,
        "cotp_type": cotp_type,
    }

    if s7_offset + 10 < len(payload):
        function_code = payload[s7_offset + 10]
        event["function_code"] = function_code
        event["function_name"] = function_name(function_code)
    return event
