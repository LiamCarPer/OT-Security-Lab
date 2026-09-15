"""OPC UA decoder: TCP message + secure conversation + service NodeId.

OPC UA is deliberately hard to inspect: the service layer lives inside the
message body and is only readable on plaintext (``None`` / ``Sign``) channels.
This decoder emits the normalized telemetry contract ``ot_ndr`` / ``opcua``;
on ``SignAndEncrypt`` channels only the header fields are available, which is a
documented limit of passive inspection rather than a parser failure.
"""
from __future__ import annotations

REQUEST_SERVICES = {
    422: "CloseSessionRequest",
    446: "FindServersRequest",
    452: "GetEndpointsRequest",
    461: "CreateSessionRequest",
    473: "ActivateSessionRequest",
    487: "RegisterServerRequest",
    527: "BrowseRequest",
    533: "BrowseNextRequest",
    554: "TranslateBrowsePathsToNodeIdsRequest",
    631: "ReadRequest",
    673: "WriteRequest",
    712: "CallRequest",
}
RESPONSE_SERVICES = {
    425: "CloseSessionResponse",
    449: "FindServersResponse",
    455: "GetEndpointsResponse",
    464: "CreateSessionResponse",
    476: "ActivateSessionResponse",
    530: "BrowseResponse",
    536: "BrowseNextResponse",
    634: "ReadResponse",
    676: "WriteResponse",
    715: "CallResponse",
}

MESSAGE_TYPES = {b"HEL", b"ACK", b"ERR", b"RHE", b"OPN", b"MSG", b"CLO"}


def _read_node_id(body: bytes, offset: int):
    """Return ``(namespace, identifier, next_offset)`` for a NodeId, or ``None``."""
    if offset >= len(body):
        return None
    encoding = body[offset]
    offset += 1
    if encoding == 0x00 and offset + 1 <= len(body):  # TwoByte
        return 0, body[offset], offset + 1
    if encoding == 0x01 and offset + 3 <= len(body):  # FourByte
        namespace = body[offset]
        identifier = int.from_bytes(body[offset + 1:offset + 3], byteorder="little")
        return namespace, identifier, offset + 3
    if encoding == 0x02 and offset + 6 <= len(body):  # Numeric
        namespace = int.from_bytes(body[offset:offset + 2], byteorder="little")
        identifier = int.from_bytes(body[offset + 2:offset + 6], byteorder="little")
        return namespace, identifier, offset + 6
    return None


def _read_string(data: bytes, offset: int):
    if offset + 4 > len(data):
        return None, offset
    length = int.from_bytes(data[offset:offset + 4], byteorder="little")
    offset += 4
    if length == 0xFFFFFFFF or length > len(data) - offset:
        return None, offset
    return data[offset:offset + length].decode("utf-8", "replace"), offset + length


def decode(payload: bytes) -> dict | None:
    """Decode one OPC UA/TCP message, or return ``None``."""
    if len(payload) < 8:
        return None
    message_type = payload[0:3]
    if message_type not in MESSAGE_TYPES:
        return None

    chunk_type = chr(payload[3])
    event = {
        "message_type": message_type.decode("ascii"),
        "chunk_type": chunk_type,
    }

    if message_type in (b"HEL", b"ACK", b"ERR", b"RHE"):
        return event

    secure_channel_id = int.from_bytes(payload[8:12], byteorder="little")
    event["secure_channel_id"] = secure_channel_id

    if message_type == b"OPN":
        policy, _ = _read_string(payload, 12)
        if policy is not None:
            event["security_policy_uri"] = policy
        return event

    if message_type == b"CLO":
        event["token_id"] = int.from_bytes(payload[12:16], byteorder="little")
        return event

    # MSG: secure conversation header then the service request NodeId.
    if len(payload) < 24:
        return event
    event["token_id"] = int.from_bytes(payload[12:16], byteorder="little")
    event["sequence_number"] = int.from_bytes(payload[16:20], byteorder="little")
    event["request_id"] = int.from_bytes(payload[20:24], byteorder="little")

    node_id = _read_node_id(payload, 24)
    if node_id is None:
        return event
    namespace, identifier, _ = node_id
    if namespace == 0 and identifier in REQUEST_SERVICES:
        event["service_id"] = identifier
        event["opcua_service"] = REQUEST_SERVICES[identifier]
        event["direction"] = "request"
    elif namespace == 0 and identifier in RESPONSE_SERVICES:
        event["service_id"] = identifier
        event["opcua_service"] = RESPONSE_SERVICES[identifier]
        event["direction"] = "response"
    return event
