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
WT_STREAM_TYPE_UNI = b"\x40\x54"       # 0x54 = 84, unidirectional WebTransport stream
WT_STREAM_TYPE_BIDI = b"\x41"          # Bidirectional stream (client-initiated)

# Capsule Type Constants (VarInt encoded)
# https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-02.html#section-4.5
CAPSULE_DRAIN_SESSION = b"\x78\xAE"    # DRAIN_WEBTRANSPORT_SESSION (0x78AE = 30894)
CAPSULE_CLOSE_SESSION = b"\x28\x43"    # CLOSE_WEBTRANSPORT_SESSION (0x2843 = 10307)

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
        s_bytes(value=WT_STREAM_TYPE_UNI, name="StreamType", size=2, fuzzable=True)
        s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=False)
    s_block_end("UniStreamHeader")

    if s_block_start("Payload"):
        s_string(value="FuzzPayload", name="PayloadData", fuzzable=fuzz_payload, max_len=2000)
    s_block_end("Payload")
    
    return s_get(session_name)


def define_bidirectional_stream(session_name="webtransport_bidi", fuzz_payload=False):
    """Bidirectional stream: [0x41][Session ID][Payload]"""
    s_initialize(session_name)
    
    if s_block_start("BidiStreamHeader"):
        s_bytes(value=WT_STREAM_TYPE_BIDI, name="StreamType", size=1, fuzzable=True)
        s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=False)
    s_block_end("BidiStreamHeader")

    if s_block_start("Payload"):
        s_string(value="BidiPayload", name="PayloadData", fuzzable=fuzz_payload, max_len=2000)
    s_block_end("Payload")
    
    return s_get(session_name)


def define_datagram(session_name="webtransport_datagram", fuzz_payload=False):
    """Datagram: [Context ID][Payload]"""
    s_initialize(session_name)
    
    if s_block_start("DatagramHeader"):
        s_bytes(value=b"\x00", name="ContextID", size=1, fuzzable=True)
    s_block_end("DatagramHeader")

    if s_block_start("Payload"):
        s_bytes(value=b"DatagramPayload", name="PayloadData", fuzzable=fuzz_payload, max_len=1200)
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


# =============================================================================
# Control Capsule Definitions (NEW)
# Format: [Type (VarInt)][Length (VarInt)][Payload]
# =============================================================================

def define_capsule_generic(session_name="capsule_generic", fuzz_payload=False):
    """
    Generic HTTP/3 Capsule for fuzzing.
    Format: [Type (VarInt)][Length (VarInt)][Payload]
    """
    s_initialize(session_name)
    
    # Capsule Type - fuzz with various VarInt values
    s_bytes(value=b"\x00", name="CapsuleType", size=1, fuzzable=True)
    
    # Capsule Length - fuzz with various values
    s_bytes(value=b"\x05", name="CapsuleLength", size=1, fuzzable=True)
    
    # Capsule Payload
    if s_block_start("CapsulePayload"):
        s_bytes(value=b"Hello", name="PayloadData", fuzzable=fuzz_payload, max_len=500)
    s_block_end("CapsulePayload")
    
    return s_get(session_name)


def define_capsule_drain(session_name="capsule_drain", fuzz_payload=False):
    """
    DRAIN_WEBTRANSPORT_SESSION Capsule (0x78AE).
    Used for graceful session shutdown.
    Format: [0x78AE][0x00] (empty payload)
    """
    s_initialize(session_name)
    
    # Type: DRAIN_WEBTRANSPORT_SESSION (0x78AE = 30894)
    # VarInt: 30894 requires 4 bytes: 0x80 | (30894 >> 24), etc.
    # Actually 0x78AE fits in 2 bytes with proper encoding: 0x40 | high, low
    # But 30894 > 16383, so needs 4-byte encoding: 0x80 prefix
    # 0x80 | (30894 >> 24) = 0x80, then next bytes...
    # Let's use the raw hex for precision
    s_bytes(value=b"\x80\x00\x78\xAE", name="CapsuleType", size=4, fuzzable=True)
    
    # Length: 0 (empty payload for DRAIN)
    s_bytes(value=b"\x00", name="CapsuleLength", size=1, fuzzable=True)
    
    return s_get(session_name)


def define_capsule_close(session_name="capsule_close", fuzz_payload=False):
    """
    CLOSE_WEBTRANSPORT_SESSION Capsule (0x2843).
    Used for immediate session termination.
    Format: [0x2843][Length][Error Code (VarInt)][Reason Phrase]
    """
    s_initialize(session_name)
    
    # Type: CLOSE_WEBTRANSPORT_SESSION (0x2843 = 10307)
    # 10307 > 63, < 16384, so 2-byte VarInt: 0x40 | (10307 >> 8), 10307 & 0xFF
    # 10307 = 0x2843 -> 0x40 | 0x28 = 0x68, 0x43
    s_bytes(value=b"\x68\x43", name="CapsuleType", size=2, fuzzable=True)
    
    # Length of payload (error code + reason)
    s_bytes(value=b"\x08", name="CapsuleLength", size=1, fuzzable=True)
    
    if s_block_start("ClosePayload"):
        # Error Code (VarInt) - 0 = no error
        s_bytes(value=b"\x00", name="ErrorCode", size=1, fuzzable=True)
        
        # Reason Phrase
        s_string(value="closed", name="ReasonPhrase", fuzzable=fuzz_payload, max_len=100)
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
