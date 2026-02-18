from boofuzz import (
    s_initialize,
    s_group,
    s_static,
    s_get,
    s_random,
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

# VarInt encoding helper for 2-byte values (0x40 prefix)
def encode_varint_2byte(value):
    """Encode a value 64-16383 as 2-byte VarInt."""
    return bytes([(0x40 | (value >> 8)), value & 0xFF])


# =============================================================================
# One-Shot Capsule Fuzzing Definition
#
# Single boofuzz node: [CapsuleType][CapsuleLength][Payload]
#
# CapsuleType cycles through all known WT capsule types + invalid/overlong
# encodings. CapsuleLength and Payload use s_random with min_length=0 so
# the fuzzer naturally produces no-payload requests (e.g. bare header
# b'\x78\xae\x00') alongside payloaded ones.
# =============================================================================

def define_oneshot_capsule(session_name="wt_oneshot", fuzz_payload=False):
    """
    One-shot capsule fuzzer.
    Format: [CapsuleType (fuzzed)][CapsuleLength (fuzzed)][Payload (optional)]

    Covers:
    - All known WT capsule types (close, drain, reset, stop, flow control)
    - Overlong VarInt encodings of known types
    - Invalid/unknown type values
    - No-payload requests (header + zero length) via min_length=0
    """
    s_initialize(session_name)

    # 1. Capsule Type — cycle through known types + edge cases
    s_group(values=[
        # Valid canonical encodings
        CAPSULE_CLOSE_SESSION,              # WT_CLOSE_SESSION (0x2843)
        CAPSULE_DRAIN_SESSION,              # WT_DRAIN_SESSION (0x78AE)
        CAPSULE_RESET_STREAM,               # WT_RESET_STREAM (0x190B4D39)
        CAPSULE_STOP_SENDING,               # WT_STOP_SENDING (0x190B4D3A)
        CAPSULE_MAX_DATA,                   # WT_MAX_DATA
        CAPSULE_MAX_STREAM_DATA,            # WT_MAX_STREAM_DATA
        CAPSULE_MAX_STREAMS_BIDI,           # WT_MAX_STREAMS bidi
        CAPSULE_MAX_STREAMS_UNI,            # WT_MAX_STREAMS uni
        CAPSULE_DATA_BLOCKED,               # WT_DATA_BLOCKED
        CAPSULE_STREAM_DATA_BLOCKED,        # WT_STREAM_DATA_BLOCKED
        CAPSULE_STREAMS_BLOCKED_BIDI,       # WT_STREAMS_BLOCKED bidi
        CAPSULE_STREAMS_BLOCKED_UNI,        # WT_STREAMS_BLOCKED uni
        # Overlong VarInt encodings (should be rejected by strict parsers)
        b"\x80\x00\x28\x43",               # CLOSE as 4-byte VarInt
        b"\xC0\x00\x00\x00\x00\x00\x28\x43", # CLOSE as 8-byte VarInt
        b"\xC0\x00\x00\x00\x00\x00\x78\xAE", # DRAIN as 8-byte VarInt
        b"\x78\xAE",                        # DRAIN raw bytes (invalid VarInt)
        b"\x28\x43",                        # CLOSE raw bytes (invalid VarInt)
        # Invalid / unknown types
        b"\x00",                            # Type 0 (unknown)
        b"\x3F",                            # Max 1-byte VarInt (63)
        b"\x7F\xFF",                        # Max 2-byte VarInt (16383)
        b"\xFF",                            # Invalid VarInt prefix
    ], name="CapsuleType")

    # 2. Capsule Length — random VarInt-ish (0-4 bytes)
    #    min_length=0 allows omitting length entirely (malformed)
    s_random(value=b"\x00", name="CapsuleLength", min_length=0, max_length=4,
             num_mutations=64, fuzzable=True)

    # 3. Capsule Payload — random content (optional)
    #    min_length=0 naturally produces no-payload requests
    if fuzz_payload:
        s_random(value=b"", name="PayloadData",
                 min_length=0, max_length=256, num_mutations=128, fuzzable=True)
    else:
        s_static(value=b"", name="PayloadData")

    return s_get(session_name)
