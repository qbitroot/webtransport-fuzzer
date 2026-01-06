from boofuzz import (
    s_initialize,
    s_string,
    s_bytes,
    s_group,
    s_static,
    s_size,
    s_block_start,
    s_block_end,
    s_get,
    s_byte,
    s_word,
    s_dword,
    s_random,
    s_delim,
)
from src.callbacks import callback_fill_session_id

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

# VarInt encoding helper for 2-byte values (0x40 prefix)
def encode_varint_2byte(value):
    """Encode a value 64-16383 as 2-byte VarInt."""
    return bytes([(0x40 | (value >> 8)), value & 0xFF])


# =============================================================================
# Data Stream Definitions (existing)
# =============================================================================

def define_webtransport_protocol(session_name="webtransport_proto", fuzz_payload=False):
    """Unidirectional stream: [0x54][Session ID][Payload]"""
    s_initialize(session_name)
    
    if s_block_start("UniStreamHeader"):
        # Optimized StreamType: Valid, Zero, Max, Invalid
        if s_block_start("StreamTypeGroup"):
            s_group(values=[
                WT_STREAM_TYPE_UNI,       # Valid (0x4054)
                b"\x00",                  # Zero (Invalid for Uni)
                b"\xff\xff",              # Max 2-byte
                b"\x55",                  # Off-by-one/Invalid
            ], name="StreamType")
        s_block_end("StreamTypeGroup")

        # Session ID: Fuzz interesting values (0, Max Int)
        if s_block_start("SessionIDGroup"):
            s_group(values=[
                b"\xAA",                  # Standard Placeholder
                b"\x00",                  # Zero
                b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", # Max Int
            ], name="SessionID")
        s_block_end("SessionIDGroup")
    s_block_end("UniStreamHeader")

    if s_block_start("Payload"):
        # Optimized Payload Fuzzing: Empty, 1 byte, Edge cases, Huge
        if fuzz_payload:
            s_group(values=[
                b"",                    # Empty
                b"A",                   # 1 Byte
                b"A" * 100,             # Medium
                b"A" * 2000,            # Large (Oversized for some contexts)
                b"\x00" * 10,           # Nulls
                b"\xFF" * 10,           # All ones
            ], name="PayloadData")
        else:
             s_string(value="FuzzPayload", name="PayloadData", fuzzable=False, max_len=2000)
    s_block_end("Payload")
    
    return s_get(session_name)


def define_bidirectional_stream(session_name="webtransport_bidi", fuzz_payload=False):
    """Bidirectional stream: [0x41][Session ID][Payload]"""
    s_initialize(session_name)
    
    if s_block_start("BidiStreamHeader"):
        # Optimized StreamType
        if s_block_start("StreamTypeGroup"):
             s_group(values=[
                WT_STREAM_TYPE_BIDI,      # Valid (0x41)
                b"\x00",                  # Zero
                b"\xff",                  # Max byte
            ], name="StreamType")
        s_block_end("StreamTypeGroup")

        if s_block_start("SessionIDGroup"):
            s_group(values=[
                b"\xAA",
                b"\x00",
                b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            ], name="SessionID")
        s_block_end("SessionIDGroup")
    s_block_end("BidiStreamHeader")

    if s_block_start("Payload"):
        if fuzz_payload:
            s_group(values=[
                b"",
                b"A",
                b"A" * 100,
                b"A" * 2000,
                b"\x00" * 10,
            ], name="PayloadData")
        else:
            s_string(value="BidiPayload", name="PayloadData", fuzzable=False, max_len=2000)
    s_block_end("Payload")
    
    return s_get(session_name)


def define_datagram(session_name="webtransport_datagram", fuzz_payload=False):
    """Datagram: [Context ID][Payload]"""
    s_initialize(session_name)
    
    if s_block_start("DatagramHeader"):
        # Optimized ContextID
        if s_block_start("ContextIDGroup"):
             s_group(values=[
                b"\x00",      # Valid
                b"\x01",      # Invalid Context
                b"\xff",      # Max byte
                b"",          # Empty/Missing
            ], name="ContextID")
        s_block_end("ContextIDGroup")
    s_block_end("DatagramHeader")

    if s_block_start("Payload"):
        if fuzz_payload:
             s_group(values=[
                b"",
                b"A",
                b"A" * 100,
                b"A" * 1100,            # Near MTU
                b"A" * 2000,            # Over MTU
            ], name="PayloadData")
        else:
            s_bytes(value=b"DatagramPayload", name="PayloadData", fuzzable=False, max_len=1200)
    s_block_end("Payload")
    
    return s_get(session_name)


def define_malformed_frames(session_name="webtransport_malformed", fuzz_payload=False):
    """Raw malformed bytes for edge case testing."""
    s_initialize(session_name)
    
    s_bytes(
        value=b"\x40\x54\xAA\x48\x65\x6C\x6C\x6F",
        name="MalformedData",
        fuzzable=True,
        max_len=200,
    )
    
    return s_get(session_name)


def define_stream_dos(session_name="webtransport_dos", fuzz_payload=False):
    """
    Stream Denial of Service (DoS) - Attempt to open 10,000 streams.
    Uses s_repeat to send many small streams in one go.
    """
    s_initialize(session_name)
    
    # Repeat the whole stream block 10,000 times
    if s_block_start("StreamDoSBlock"):
        # Header
        # We manually construct a repeating pattern here because typical s_repeat usage
        # varies and we want a static huge block.
        # Actually s_repeat is tricky. Let's just generate a large static block of 10k streams
        # since we want to overwhelm the server.
        pass
    s_block_end("StreamDoSBlock")
    
    # Generate 10k streams essentially statically
    # [StreamType: 2][SessionID: 1][Payload: 3] = 6 bytes * 10000 = 60KB
    payload = (WT_STREAM_TYPE_UNI + b"\xAA" + b"DoS") * 10000
    s_static(value=payload, name="DoSFlood")

    return s_get(session_name)


# =============================================================================
# Control Capsule Definitions (NEW)
# Format: [Type (VarInt)][Length (VarInt)][Payload]
# =============================================================================

def define_capsule_generic(session_name="capsule_generic", fuzz_payload=False):
    """
    Generic HTTP/3 Capsule for fuzzing.
    Format: [Type (VarInt)][Length (VarInt)][Payload]
    
    Optimized to fuzz specific interesting VarInt values (edge cases + known types)
    rather than brute-forcing all byte combinations.
    """
    s_initialize(session_name)
    
    # 1. Capsule Type (VarInt)
    # We use s_group to strictly select from interesting values
    if s_block_start("CapsuleTypeGroup"):
        # Known types
        s_group(values=[
            b"\x68\x43",          # WT_CLOSE_SESSION (0x2843)
            b"\x80\x00\x78\xAE",  # WT_DRAIN_SESSION (0x78AE)
            b"\x19\x0B\x4D\x38",  # PADDING (0x190B4D38) - Note: should be encoded as VarInt
            # Flow control types (0x190B4D3D...44) - pre-encoded as 4-byte VarInts
            b"\x99\x0B\x4D\x3D",  # WT_MAX_DATA (VarInt 0x190B4D3D -> 0x99...)
            b"\x99\x0B\x4D\x3E",  # WT_MAX_STREAM_DATA
        ], name="KnownTypes")
        
        # Edge case VarInts
        s_group(values=[
            b"\x00",              # Min 1-byte (0)
            b"\x3F",              # Max 1-byte (63)
            b"\x40\x40",          # Min 2-byte (64)
            b"\x7F\xFF",          # Max 2-byte (16383)
            b"\x80\x00\x40\x00",  # Min 4-byte (16384)
            b"\xBF\xFF\xFF\xFF",  # Max 4-byte (1073741823)
            b"\xC0\x00\x00\x00\x40\x00\x00\x00", # Min 8-byte
            b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", # Max 8-byte (Max Int)
        ], name="EdgeCaseTypes")

        # Random Unknown Types (Simulated by random bytes that look like VarInts)
        s_group(values=[
            b"\x50\x00",          # Random 2-byte unknown
            b"\x90\x00\x00\x01",  # Random 4-byte unknown
        ], name="RandomTypes")
    s_block_end("CapsuleTypeGroup")
    
    # 2. Capsule Length (VarInt)
    # Target specific lengths: 0, small, large, boundary
    if s_block_start("CapsuleLengthGroup"):
         s_group(values=[
            b"\x00",      # Empty
            b"\x01",      # 1 byte
            b"\x40\x64",  # 100 bytes (2-byte encoding)
            b"\x44\x00",  # 1024 bytes (2-byte encoding)
            b"\x80\x01\x00\x00", # 65536 bytes (4-byte encoding, oversize)
         ], name="InterestingLengths")
    s_block_end("CapsuleLengthGroup")
    
    # 3. Capsule Payload
    if s_block_start("CapsulePayload"):
        # Fuzz the content if requested
        s_string(value="FuzzPayload", name="PayloadData", fuzzable=fuzz_payload, max_len=1500)
    s_block_end("CapsulePayload")
    
    return s_get(session_name)


def define_capsule_drain(session_name="capsule_drain", fuzz_payload=False):
    """
    DRAIN_WEBTRANSPORT_SESSION Capsule (0x78AE).
    Used for graceful session shutdown.
    Format: [0x78AE][0x00] (empty payload)
    
    Optimized for structure/encoding fuzzing.
    """
    s_initialize(session_name)
    
    # 1. Capsule Type (VarInt) - 0x78AE (30894)
    # Must be 4-byte (40..3F) or 8-byte (80..) VarInt
    if s_block_start("DrainTypeGroup"):
        s_group(values=[
            b"\x80\x00\x78\xAE",          # Canonical 4-byte encoding
            b"\xC0\x00\x00\x00\x00\x00\x78\xAE", # Overlong 8-byte encoding
            b"\x78\xAE",                  # Invalid 2-byte (as raw bytes, not VarInt encoded)
            b"\xFF",                      # Invalid 1-byte
        ], name="CapsuleType")
    s_block_end("DrainTypeGroup")
    
    # 2. Length (VarInt) - Should be 0
    if s_block_start("DrainLengthGroup"):
        s_group(values=[
            b"\x00",      # Valid (0)
            b"\x01",      # Invalid (> 0)
            b"\x40\x01",  # Invalid (2-byte encoded 1)
        ], name="CapsuleLength")
    s_block_end("DrainLengthGroup")
    
    return s_get(session_name)


def define_capsule_close(session_name="capsule_close", fuzz_payload=False):
    """
    CLOSE_WEBTRANSPORT_SESSION Capsule (0x2843).
    Used for immediate session termination.
    Format: [0x2843][Length][Error Code (VarInt)][Reason Phrase]
    
    Optimized for structure/encoding fuzzing.
    """
    s_initialize(session_name)
    
    # 1. Capsule Type (VarInt) - 0x2843 (10307)
    # Must be 2-byte (40..7F), 4-byte (80..), or 8-byte (C0..)
    if s_block_start("CloseTypeGroup"):
        s_group(values=[
            b"\x68\x43",          # Canonical 2-byte encoding
            b"\x80\x00\x28\x43",  # Overlong 4-byte encoding
            b"\xC0\x00\x00\x00\x00\x00\x28\x43", # Overlong 8-byte encoding
            b"\x28\x43",          # Invalid 2-byte (raw)
            b"\xFF",              # Invalid 1-byte
        ], name="CapsuleType")
    s_block_end("CloseTypeGroup")
    
    # 2. Length (VarInt) - Starts with reasonable default
    # Note: s_size can auto-calculate, but s_group forces specific bad values
    if s_block_start("CloseLengthGroup"):
        s_group(values=[
            b"\x07",      # Correct for 0 code + "closed" (1 + 6 bytes)
            b"\x00",      # Invalid (too short for ErrorCode)
            b"\x80\x00\x00\x07", # Overlong 4-byte encoding of 7
            b"\x44\x00",  # Large length (1024) - potential buffer overflow
        ], name="CapsuleLength")
    s_block_end("CloseLengthGroup")
    
    if s_block_start("ClosePayload"):
        # 3. Error Code (VarInt)
        if s_block_start("ErrorCodeGroup"):
            s_group(values=[
                b"\x00",              # 0 (No Error)
                b"\x01",              # 1 (Internal Error)
                b"\x80\xFF\xFF\xFF",  # Max 32-bit (common application error limit)
            ], name="ErrorCode")
        s_block_end("ErrorCodeGroup")
        
        # 4. Reason Phrase
        s_group(values=[
            b"closed",            # Standard
            b"",                  # Empty
            b"A" * 256,           # Long string (reduced from 1024 to avoid timeouts)
            b"\xFF\xFE\x00\x00",  # Invalid UTF-8
        ], name="ReasonPhrase")
    s_block_end("ClosePayload")
    
    return s_get(session_name)


# =============================================================================
# Validation (Health Check)
# =============================================================================

def define_valid_webtransport_packet(session_name="webtransport_valid"):
    """Valid packet for health check / validation mode."""
    s_initialize(session_name)
    s_static(WT_STREAM_TYPE_UNI, name="StreamType")
    s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=False)
    s_string("HelloValidWorld", name="Payload", fuzzable=False)
    return s_get(session_name)
