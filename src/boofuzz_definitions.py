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

# Stream Type Constants (VarInt encoded)
WT_STREAM_TYPE_UNI = b"\x40\x54"       # 0x54 = 84, unidirectional WebTransport stream
WT_STREAM_TYPE_BIDI = b"\x41"          # 0x41 = 65, server-initiated bidi header

# Capsule Type Constants (VarInt encoded per RFC 9000 §16)
# 0x2843 = 10307 -> 2-byte VarInt: (0x40 | (10307 >> 8)), (10307 & 0xFF) = 0x68, 0x43
CAPSULE_CLOSE_SESSION = b"\x68\x43"    # WT_CLOSE_SESSION (0x2843)

# 0x78AE = 30894 -> 4-byte VarInt: 0x80 prefix for values >= 16384
CAPSULE_DRAIN_SESSION = b"\x80\x00\x78\xAE"    # WT_DRAIN_SESSION (0x78AE)

# Flow Control Capsules (4-byte VarInt, 0x190B4D** values)
CAPSULE_MAX_DATA = b"\x80\x19\x0B\x4D\x3D"            # WT_MAX_DATA (0x190B4D3D)
CAPSULE_MAX_STREAM_DATA = b"\x80\x19\x0B\x4D\x3E"     # WT_MAX_STREAM_DATA (0x190B4D3E)
CAPSULE_MAX_STREAMS_BIDI = b"\x80\x19\x0B\x4D\x3F"    # WT_MAX_STREAMS bidi (0x190B4D3F)
CAPSULE_MAX_STREAMS_UNI = b"\x80\x19\x0B\x4D\x40"     # WT_MAX_STREAMS uni (0x190B4D40)
CAPSULE_DATA_BLOCKED = b"\x80\x19\x0B\x4D\x41"        # WT_DATA_BLOCKED (0x190B4D41)
CAPSULE_STREAM_DATA_BLOCKED = b"\x80\x19\x0B\x4D\x42" # WT_STREAM_DATA_BLOCKED (0x190B4D42)
CAPSULE_STREAMS_BLOCKED_BIDI = b"\x80\x19\x0B\x4D\x43" # WT_STREAMS_BLOCKED bidi (0x190B4D43)
CAPSULE_STREAMS_BLOCKED_UNI = b"\x80\x19\x0B\x4D\x44"  # WT_STREAMS_BLOCKED uni (0x190B4D44)

# Stream Control Capsules
CAPSULE_RESET_STREAM = b"\x80\x19\x0B\x4D\x39"        # WT_RESET_STREAM (0x190B4D39)
CAPSULE_STOP_SENDING = b"\x80\x19\x0B\x4D\x3A"        # WT_STOP_SENDING (0x190B4D3A)

import struct

def encode_quic_varint(value):
    """Encode an integer as a QUIC Variable-Length Integer (RFC 9000)."""
    if value <= 63:
        return bytes([value])
    elif value <= 16383:
        return bytes([(value >> 8) | 0x40, value & 0xFF])
    elif value <= 1073741823:
        return bytes([(value >> 24) | 0x80, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
    elif value <= 4611686018427387903:
        return struct.pack(">Q", value | (0xc0 << 56))
    raise ValueError(f"Value too large for QUIC VarInt: {value}")


# =============================================================================
# Value Collections for Fuzzing
# =============================================================================

# 1. Valid Canonical Capsule Types
VALID_CAPSULE_TYPES = [
    CAPSULE_CLOSE_SESSION,              # WT_CLOSE_SESSION (0x2843)
    CAPSULE_DRAIN_SESSION,              # WT_DRAIN_SESSION (0x78AE)
    CAPSULE_RESET_STREAM,               # WT_RESET_STREAM
    CAPSULE_STOP_SENDING,               # WT_STOP_SENDING
    CAPSULE_MAX_DATA,                   # WT_MAX_DATA
    CAPSULE_MAX_STREAM_DATA,            # WT_MAX_STREAM_DATA
    CAPSULE_MAX_STREAMS_BIDI,           # WT_MAX_STREAMS bidi
    CAPSULE_MAX_STREAMS_UNI,            # WT_MAX_STREAMS uni
    CAPSULE_DATA_BLOCKED,               # WT_DATA_BLOCKED
    CAPSULE_STREAM_DATA_BLOCKED,        # WT_STREAM_DATA_BLOCKED
    CAPSULE_STREAMS_BLOCKED_BIDI,       # WT_STREAMS_BLOCKED bidi
    CAPSULE_STREAMS_BLOCKED_UNI,        # WT_STREAMS_BLOCKED uni
    b"\x00",                            # Type 0 (unknown)
]

# 2. Interesting Numeric Boundaries (QUIC VarInt Encoded)
# Boofuzz tests some of these natively for standard integers, but because 
# QUIC uses a custom Variable-Length format, we must encode them manually.
# Negative numbers aren't supported by QUIC VarInts (it's strictly unsigned).
INTERESTING_NUMBERS = [
    0, 1, 2,                              # Small values
    62, 63,                               # 1-byte max
    64, 65,                               # 2-byte min
    16382, 16383,                         # 2-byte max
    16384, 16385,                         # 4-byte min
    8191, 8192, 8193,                     # WT_CLOSE_SESSION application error max
    65535, 65536,                         # 16-bit boundaries
    1073741822, 1073741823,               # 4-byte max
    1073741824, 1073741825,               # 8-byte min
    4294967295, 4294967296,               # 32-bit boundaries
    4611686018427387902, 4611686018427387903 # Max QUIC VarInt (2^62 - 1)
]
VALID_VARINT_ENC = [encode_quic_varint(v) for v in INTERESTING_NUMBERS]

# 3. Malformed / Edge Case Byte Sequences
MALFORMED_VARINTS = [
    b"\x80\x00\x28\x43",                 # CLOSE type as overlong 4-byte VarInt
    b"\xC0\x00\x00\x00\x00\x00\x28\x43", # CLOSE type as overlong 8-byte VarInt
    b"\xC0\x00\x00\x00\x00\x00\x78\xAE", # DRAIN type as overlong 8-byte VarInt
    b"\x78\xAE",                         # DRAIN raw bytes (invalid VarInt, misses 0x80 prefix)
    b"\x28\x43",                         # CLOSE raw bytes (invalid VarInt, misses 0x40 prefix)
    b"\x3F",                             # Max 1-byte VarInt (63)
    b"\x7F\xFF",                         # Max 2-byte VarInt (16383)
    b"\xFF",                             # Invalid prefix (11 indicates 8-byte length, but only 1 byte provided)
    b"\x80\x00",                         # truncated 4-byte VarInt
    b"\xc0\x00\x00\x00",                 # truncated 8-byte VarInt
    b"\xc0\x00\x00\x00\x00\x00\x00\x00", # Technically valid 8-byte encoded zero
    b"\xff\xff\xff\xff\xff\xff\xff\xff", # 8 bytes of 0xFF (Acts as an invalid oversized/negative encoding)
    b"",                                 # Empty byte string to test completely omitted fields
]

# Merge everything to ensure crossover fuzzing.
# By feeding capsule types into length, and lengths into type, we test unexpected state transitions.
ALL_INTERESTING_BYTES = list(dict.fromkeys(VALID_CAPSULE_TYPES + VALID_VARINT_ENC + MALFORMED_VARINTS))

# =============================================================================
# One-Shot Capsule Fuzzing Definition
#
# Single boofuzz node: [CapsuleType][CapsuleLength][Payload]
# =============================================================================

def define_oneshot_capsule(session_name="wt_oneshot", fuzz_payload=False):
    """
    One-shot capsule fuzzer.
    Format: [CapsuleType (fuzzed)][CapsuleLength (fuzzed)][Payload (optional)]
    """
    s_initialize(session_name)

    # 1. Capsule Type — Use all merged interesting bytes
    s_group(values=ALL_INTERESTING_BYTES, name="CapsuleType")

    # 2. Capsule Length — Use all merged interesting bytes
    s_group(values=ALL_INTERESTING_BYTES, name="CapsuleLength")

    # 3. Capsule Payload
    if fuzz_payload:
        # Capsule Payload — random content
        s_random(value=b"", name="PayloadData",
                 min_length=0, max_length=256, num_mutations=128, fuzzable=True)
    else:
        s_static(value=b"", name="PayloadData")

    return s_get(session_name)
