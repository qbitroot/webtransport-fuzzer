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
# https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-02.html
# =============================================================================

# Stream Type Constants (VarInt encoded)
# VarInt encoding: values 0-63 fit in 1 byte, 64-16383 fit in 2 bytes (0x40 prefix)
WT_STREAM_TYPE_UNI = b"\x40\x54"       # 0x54 = 84, unidirectional WebTransport stream
WT_STREAM_TYPE_BIDI = b"\x41"          # Bidirectional stream (client-initiated)

# Fuzz-worthy stream type mutations
STREAM_TYPE_MUTATIONS = [
    b"\x00",                   # Zero - invalid
    b"\x01",                   # 1 - HTTP/3 control stream  
    b"\x02",                   # 2 - QPACK encoder
    b"\x03",                   # 3 - QPACK decoder
    b"\x40\x54",               # Valid WebTransport uni (0x54)
    b"\x41",                   # Valid bidirectional
    b"\xFF",                   # Max 1-byte value
    b"\x40\x00",               # 2-byte encoding of 0 (wasteful)
    b"\x40\xFF",               # 2-byte max (255)
    b"\x80\x00\x00\x00",       # 4-byte VarInt prefix
    b"\xC0\x00\x00\x00\x00\x00\x00\x00",  # 8-byte VarInt prefix (max)
    b"\x54",                   # Wrong encoding (should be 2-byte)
    b"",                       # Empty - truncated
    b"\x40",                   # Truncated 2-byte VarInt
    b"\x80\x00",               # Truncated 4-byte VarInt
]

# Session ID mutations (VarInt encoded)
SESSION_ID_MUTATIONS = [
    b"\x00",                   # Session 0
    b"\x01",                   # Session 1
    b"\x04",                   # Common session ID
    b"\x3F",                   # Max 1-byte VarInt (63)
    b"\x40\x40",               # 2-byte: value 64
    b"\x40\xFF",               # 2-byte: value 255
    b"\x7F\xFF",               # 2-byte: max (16383)
    b"\x80\x00\x00\x01",       # 4-byte: value 1
    b"\xBF\xFF\xFF\xFF",       # 4-byte: max value
    b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",  # 8-byte: huge value
    b"",                       # Empty - missing session ID
    b"\xAA",                   # Placeholder (will be replaced)
]


def define_webtransport_protocol(session_name="webtransport_proto", fuzz_payload=False):
    """
    Defines enhanced WebTransport unidirectional stream for fuzzing.
    
    Args:
        session_name: Boofuzz session name
        fuzz_payload: If True, fuzz the payload content. If False, only fuzz structure.
    """
    s_initialize(session_name)
    
    # --- Stream Type with mutations ---
    if s_block_start("UniStreamHeader"):
        # Fuzz stream type - use s_bytes with fuzzable=True for good coverage
        s_bytes(value=WT_STREAM_TYPE_UNI, name="StreamType", size=2, fuzzable=True)
        
        # Session ID: VarInt placeholder (replaced by callback) - NOT fuzzed because it must match the session
        s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=False)
    s_block_end("UniStreamHeader")

    # --- Payload ---
    if s_block_start("Payload"):
        s_string(
            value="FuzzPayload",
            name="PayloadData",
            fuzzable=fuzz_payload,  # Controlled by flag
            max_len=2000,
        )
    s_block_end("Payload")
    
    return s_get(session_name)


def define_bidirectional_stream(session_name="webtransport_bidi", fuzz_payload=False):
    """
    Defines WebTransport bidirectional stream for fuzzing.
    
    Args:
        session_name: Boofuzz session name
        fuzz_payload: If True, fuzz the payload content. If False, only fuzz structure.
    """
    s_initialize(session_name)
    
    if s_block_start("BidiStreamHeader"):
        # Stream type for bidirectional
        s_bytes(value=WT_STREAM_TYPE_BIDI, name="StreamType", size=1, fuzzable=True)
        
        # Session ID - NOT fuzzed because it must match the session
        s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=False)
    s_block_end("BidiStreamHeader")

    if s_block_start("Payload"):
        s_string(
            value="BidiPayload",
            name="PayloadData",
            fuzzable=fuzz_payload,  # Controlled by flag
            max_len=2000,
        )
    s_block_end("Payload")
    
    return s_get(session_name)


def define_datagram(session_name="webtransport_datagram", fuzz_payload=False):
    """
    Defines WebTransport datagram for fuzzing.
    
    Args:
        session_name: Boofuzz session name
        fuzz_payload: If True, fuzz the payload content. If False, only fuzz structure.
    """
    s_initialize(session_name)
    
    if s_block_start("DatagramHeader"):
        # Quarter Stream ID (session_id / 4)
        # VarInt encoded context ID
        s_bytes(value=b"\x00", name="ContextID", size=1, fuzzable=True)
    s_block_end("DatagramHeader")

    if s_block_start("Payload"):
        s_bytes(
            value=b"DatagramPayload",
            name="PayloadData",
            fuzzable=fuzz_payload,  # Controlled by flag
            max_len=1200,
        )
    s_block_end("Payload")
    
    return s_get(session_name)


def define_malformed_frames(session_name="webtransport_malformed", fuzz_payload=False):
    """
    Defines intentionally malformed WebTransport frames.
    Tests edge cases and error handling.
    
    Note: fuzz_payload is ignored here since this is all raw bytes.
    """
    s_initialize(session_name)
    
    # Raw bytes with various malformed patterns - use s_bytes for raw data fuzzing
    s_bytes(
        value=b"\x40\x54\xAA\x48\x65\x6C\x6C\x6F",  # Valid-ish default (header + "Hello")
        name="MalformedData",
        fuzzable=True,
        max_len=200,
    )
    
    return s_get(session_name)


def define_valid_webtransport_packet(session_name="webtransport_valid"):
    """
    Defines a VALID packet for health check / validation mode.
    """
    s_initialize(session_name)
    s_static(WT_STREAM_TYPE_UNI, name="StreamType")
    s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=False)
    s_string("HelloValidWorld", name="Payload", fuzzable=False)
    return s_get(session_name)
