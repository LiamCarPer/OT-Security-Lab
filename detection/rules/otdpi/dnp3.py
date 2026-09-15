"""DNP3 decoder: link + transport + application header -> normalized event.

DNP3 confuses Sigma because the interesting fields (function code, link source,
control object) live below the application header. This decoder emits one
normalized event per application message, matching the telemetry contract
``ot_ndr`` / ``dnp3``. It decodes the first object header only (enough to tell a
control operation from monitoring data), which is the documented limit of the
reference decoders too.
"""
from __future__ import annotations

import os

AUTHORIZED_MASTERS = {
    int(value) for value in os.getenv("OT_DNP3_AUTHORIZED_MASTERS", "1,2").split(",") if value
}
CONTROL_FUNCTIONS = {3, 4, 5, 6}
RESTART_FUNCTIONS = {13, 14}
UNSOLICITED_DISABLE = {21}

FUNCTION_NAMES = {
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate No Ack",
    7: "Immediate Freeze",
    8: "Immediate Freeze No Ack",
    9: "Freeze Clear",
    10: "Freeze Clear No Ack",
    11: "Freeze At Time",
    12: "Freeze At Time No Ack",
    13: "Cold Restart",
    14: "Warm Restart",
    20: "Enable Unsolicited",
    21: "Disable Unsolicited",
    22: "Assign Class",
    23: "Delay Measure",
    24: "Record Current Time",
}


def function_name(function_code: int) -> str:
    return FUNCTION_NAMES.get(function_code, f"Unknown ({function_code})")


def decode(payload: bytes) -> dict | None:
    """Decode one DNP3/TCP application message, or return ``None``."""
    if len(payload) < 12 or payload[0] != 0x05 or payload[1] != 0x64:
        return None

    control = payload[3]
    link_destination = int.from_bytes(payload[4:6], byteorder="little")
    link_source = int.from_bytes(payload[6:8], byteorder="little")
    transport = payload[10]
    application = payload[11:]
    if len(application) < 2:
        return None

    application_control = application[0]
    function_code = application[1]

    object_group = application[2] if len(application) > 2 else None
    object_variation = application[3] if len(application) > 3 else None
    object_count = application[5] if len(application) > 5 else None
    control_code = application[6] if object_group == 12 and len(application) > 6 else None

    return {
        "direction": "request" if control & 0x80 else "response",
        "function_code": function_code,
        "function_name": function_name(function_code),
        "link_source": link_source,
        "link_destination": link_destination,
        "link_function": control & 0x0F,
        "transport_sequence": transport & 0x3F,
        "application_sequence": application_control & 0x0F,
        "object_group": object_group,
        "object_variation": object_variation,
        "object_count": object_count,
        "control_code": control_code,
    }
