from boofuzz import (
    s_initialize,
    s_group,
    s_static,
    s_get,
    s_random,
    s_byte,
)

# =============================================================================
# WebTransport over HTTP/3 Constants
# https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-14
# =============================================================================

# Stream Type / Signal Constants (VarInt encoded)
WT_STREAM_TYPE_UNI = b"\x40\x54"  # 0x54 = 84, unidirectional WebTransport stream type
WT_STREAM_TYPE_BIDI = b"\x40\x41"  # 0x41 = 65, bidirectional WT_STREAM signal value

# Capsule Type Constants (VarInt encoded per RFC 9000 §16)
# 0x2843 = 10307 -> 2-byte VarInt: (0x40 | (10307 >> 8)), (10307 & 0xFF) = 0x68, 0x43
CAPSULE_CLOSE_SESSION = b"\x68\x43"  # WT_CLOSE_SESSION (0x2843)

# 0x78AE = 30894 -> 4-byte VarInt: (0x80 | (30894 >> 24)), ...
CAPSULE_DRAIN_SESSION = b"\x80\x00\x78\xae"  # WT_DRAIN_SESSION (0x78AE)

# Flow Control Capsules (correct 4-byte VarInt encoding, 0x190B4D** values)
# 0x190B4D3D -> first byte: (0x19 | 0x80) = 0x99
CAPSULE_MAX_DATA = b"\x99\x0b\x4d\x3d"  # WT_MAX_DATA (0x190B4D3D)
CAPSULE_MAX_STREAMS_BIDI = b"\x99\x0b\x4d\x3f"  # WT_MAX_STREAMS bidi (0x190B4D3F)
CAPSULE_MAX_STREAMS_UNI = b"\x99\x0b\x4d\x40"  # WT_MAX_STREAMS uni (0x190B4D40)
CAPSULE_DATA_BLOCKED = b"\x99\x0b\x4d\x41"  # WT_DATA_BLOCKED (0x190B4D41)
CAPSULE_STREAMS_BLOCKED_BIDI = (
    b"\x99\x0b\x4d\x43"  # WT_STREAMS_BLOCKED bidi (0x190B4D43)
)
CAPSULE_STREAMS_BLOCKED_UNI = b"\x99\x0b\x4d\x44"  # WT_STREAMS_BLOCKED uni (0x190B4D44)

# Note: WT_MAX_STREAM_DATA (0x190B4D3E) and WT_STREAM_DATA_BLOCKED (0x190B4D42) are
# explicitly PROHIBITED in draft-ietf-webtrans-http3-14 §5.4: per-stream flow control
# is handled by QUIC natively; receipt MUST be treated as a session error.
# WT_RESET_STREAM and WT_STOP_SENDING are QUIC-level frames, not WebTransport capsules.

import struct


def encode_quic_varint(value):
    """Encode an integer as a QUIC Variable-Length Integer (RFC 9000)."""
    if value <= 63:
        return bytes([value])
    elif value <= 16383:
        return bytes([(value >> 8) | 0x40, value & 0xFF])
    elif value <= 1073741823:
        return bytes(
            [
                (value >> 24) | 0x80,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            ]
        )
    elif value <= 4611686018427387903:
        return struct.pack(">Q", value | (0xC0 << 56))
    raise ValueError(f"Value too large for QUIC VarInt: {value}")


# =============================================================================
# Value Collections for Fuzzing
# =============================================================================

# 1. Valid Canonical Capsule Types (only those defined in draft-ietf-webtrans-http3-14)
VALID_CAPSULE_TYPES = [
    CAPSULE_CLOSE_SESSION,  # WT_CLOSE_SESSION (0x2843)
    CAPSULE_DRAIN_SESSION,  # WT_DRAIN_SESSION (0x78AE)
    CAPSULE_MAX_DATA,  # WT_MAX_DATA (0x190B4D3D)
    CAPSULE_MAX_STREAMS_BIDI,  # WT_MAX_STREAMS bidi (0x190B4D3F)
    CAPSULE_MAX_STREAMS_UNI,  # WT_MAX_STREAMS uni (0x190B4D40)
    CAPSULE_DATA_BLOCKED,  # WT_DATA_BLOCKED (0x190B4D41)
    CAPSULE_STREAMS_BLOCKED_BIDI,  # WT_STREAMS_BLOCKED bidi (0x190B4D43)
    CAPSULE_STREAMS_BLOCKED_UNI,  # WT_STREAMS_BLOCKED uni (0x190B4D44)
    b"\x00",  # Type 0 (unknown, must be ignored per RFC 9297)
]

# 2. Interesting Numeric Boundaries (QUIC VarInt Encoded)
# Boofuzz tests some of these natively for standard integers, but because
# QUIC uses a custom Variable-Length format, we must encode them manually.
# Negative numbers aren't supported by QUIC VarInts (it's strictly unsigned).
INTERESTING_NUMBERS = [
    0,
    1,
    2,  # Small values
    62,
    63,  # 1-byte max
    64,
    65,  # 2-byte min
    16382,
    16383,  # 2-byte max
    16384,
    16385,  # 4-byte min
    8191,
    8192,
    8193,  # WT_CLOSE_SESSION application error max
    65535,
    65536,  # 16-bit boundaries
    1073741822,
    1073741823,  # 4-byte max
    1073741824,
    1073741825,  # 8-byte min
    4294967295,
    4294967296,  # 32-bit boundaries
    4611686018427387902,
    4611686018427387903,  # Max QUIC VarInt (2^62 - 1)
]
VALID_VARINT_ENC = [encode_quic_varint(v) for v in INTERESTING_NUMBERS]

# 3. Malformed / Edge Case Byte Sequences
MALFORMED_VARINTS = [
    # Overlong encodings of valid capsule types (valid value, non-canonical encoding)
    b"\x80\x00\x28\x43",  # CLOSE (0x2843) as overlong 4-byte VarInt
    b"\xc0\x00\x00\x00\x00\x00\x28\x43",  # CLOSE (0x2843) as overlong 8-byte VarInt
    b"\xc0\x00\x00\x00\x00\x00\x78\xae",  # DRAIN (0x78AE) as overlong 8-byte VarInt
    b"\xc0\x00\x00\x00\x19\x0b\x4d\x3d",  # WT_MAX_DATA (0x190B4D3D) as 8-byte VarInt
    b"\xc0\x00\x00\x00\x19\x0b\x4d\x3f",  # WT_MAX_STREAMS bidi as 8-byte VarInt
    # Raw bytes without correct VarInt prefix (would be misread as different values)
    b"\x78\xae",  # DRAIN raw bytes (parsed as 2-byte VarInt for 0x38AE, not 0x78AE)
    b"\x28\x43",  # CLOSE raw bytes (parsed as 1-byte 0x28 + extra, not 0x2843)
    # Boundary / truncation cases
    b"\x3f",  # Max 1-byte VarInt (63)
    b"\x7f\xff",  # Invalid: top bits 01 but MSB of second byte set (not a standard VarInt)
    b"\xff",  # Invalid: 8-byte prefix (0xC0) but only 1 byte provided
    b"\x80\x00",  # Truncated 4-byte VarInt (only 2 of 4 bytes)
    b"\xc0\x00\x00\x00",  # Truncated 8-byte VarInt (only 4 of 8 bytes)
    b"\xc0\x00\x00\x00\x00\x00\x00\x00",  # Valid 8-byte encoding of zero
    b"\xff\xff\xff\xff\xff\xff\xff\xff",  # 8 bytes of 0xFF (value exceeds 2^62-1, invalid)
    b"",  # Completely omitted field
]

# 4. QUIC and HTTP/3 Frame Types encoded as VarInts
# These are NOT WebTransport capsule types. Injecting them as a capsule type
# tests that the target treats the stream as capsule data and does NOT dispatch
# them as QUIC or HTTP/3 control frames (layer confusion / type confusion attack).
INCORRECT_QUIC_FRAMES = [
    # QUIC frame types (RFC 9000 §19) — all single-byte VarInts
    b"\x00",  # PADDING
    b"\x01",  # PING
    b"\x02",  # ACK (no ECN)
    b"\x03",  # ACK (with ECN)
    b"\x04",  # RESET_STREAM
    b"\x05",  # STOP_SENDING
    b"\x06",  # CRYPTO
    b"\x07",  # NEW_TOKEN
    b"\x08",  # STREAM (base type; 0x08-0x0f are STREAM variants)
    b"\x0f",  # STREAM (all flags set)
    b"\x10",  # MAX_DATA
    b"\x11",  # MAX_STREAM_DATA
    b"\x12",  # MAX_STREAMS (bidi)
    b"\x13",  # MAX_STREAMS (uni)
    b"\x14",  # DATA_BLOCKED
    b"\x15",  # STREAM_DATA_BLOCKED
    b"\x16",  # STREAMS_BLOCKED (bidi)
    b"\x17",  # STREAMS_BLOCKED (uni)
    b"\x18",  # NEW_CONNECTION_ID
    b"\x19",  # RETIRE_CONNECTION_ID
    b"\x1a",  # PATH_CHALLENGE
    b"\x1b",  # PATH_RESPONSE
    b"\x1c",  # CONNECTION_CLOSE (QUIC error)
    b"\x1d",  # CONNECTION_CLOSE (app error)
    b"\x1e",  # HANDSHAKE_DONE
    # HTTP/3 frame types (RFC 9114 §7.2)
    # 0x00 and 0x01 overlap with QUIC above; add the distinct ones
    b"\x03",  # CANCEL_PUSH
    b"\x04",  # SETTINGS
    b"\x05",  # PUSH_PROMISE
    b"\x07",  # GOAWAY
    b"\x0d",  # MAX_PUSH_ID
    b"\x0c",  # ORIGIN (RFC 9412)
    b"\x40\x4d",  # METADATA (0x4d, provisional)
    b"\x80\x0f\x07\x00",  # PRIORITY_UPDATE (0xf0700, RFC 9218)
    # HTTP/3 reserved "grease" frame types: 0x1f*N+0x21 for N=0,1,...
    # These must be ignored by implementations; using them as capsule type
    # should also be gracefully ignored, not crash.
    b"\x21",  # N=0: 0x21
    b"\x40\x40",  # N=1: 0x40
    b"\x40\x5f",  # N=2: 0x5f
    b"\x40\x7e",  # N=3: 0x7e
    b"\x40\x9d",  # N=4: 0x9d
    b"\x40\xbc",  # N=5: 0xbc
    b"\x40\xdb",  # N=6: 0xdb
    b"\x40\xfa",  # N=7: 0xfa
]

# Merge everything to ensure crossover fuzzing.
# By feeding capsule types into length, and lengths into type, we test unexpected state transitions.
ALL_INTERESTING_BYTES = list(
    dict.fromkeys(
        VALID_CAPSULE_TYPES
        + VALID_VARINT_ENC
        + MALFORMED_VARINTS
        + INCORRECT_QUIC_FRAMES
    )
)

# =============================================================================
# One-Shot Capsule Fuzzing Definition
#
# Single boofuzz node: [CapsuleType][CapsuleLength][Payload]
# =============================================================================


def define_oneshot_capsule(session_name="wt_oneshot"):
    """
    One-shot capsule fuzzer.
    Format: [CapsuleType (fuzzed)][CapsuleLength (fuzzed)][Payload (optional)]
    """
    s_initialize(session_name)

    # 1. Capsule Type — Use all merged interesting bytes
    s_group(values=ALL_INTERESTING_BYTES, name="CapsuleType")

    # 2. & 3. Capsule Length + Payload combined to ensure valid lengths for bodies
    length_and_payload = []

    # Half cases WITHOUT body: length is fuzzed, body is empty
    for length_bytes in ALL_INTERESTING_BYTES:
        length_and_payload.append(length_bytes + b"")

    # Half cases WITH body: length is valid, body is an "interesting" payload
    for payload_bytes in ALL_INTERESTING_BYTES:
        valid_length = encode_quic_varint(len(payload_bytes))
        length_and_payload.append(valid_length + payload_bytes)

    s_group(values=length_and_payload, name="LengthAndPayload")

    return s_get(session_name)
