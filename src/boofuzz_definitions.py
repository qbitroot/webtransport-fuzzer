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
)
from src.callbacks import callback_fill_session_id

# Constants for WebTransport over HTTP/3
# https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-02.html
# Constants for WebTransport over HTTP/3
# https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-02.html
# Stream Type 0x54 (84 decimal) must be VarInt encoded.
# 84 > 63, so it takes 2 bytes. 
# 2-byte marker is 0x40. 0x4000 | 0x54 = 0x4054.
WT_STREAM_TYPE_UNI = b"\x40\x54"  

def define_webtransport_protocol(session_name="webtransport_proto"):
    """
    Defines the WebTransport protocol structure for Boofuzz.
    """
    s_initialize(session_name)
    
    # --- Unidirectional Stream Structure ---
    if s_block_start("UniStreamHeader"):
        # Stream Type: VarInt encoded 0x54. 
        # Size=2, Name="StreamType"
        s_bytes(value=WT_STREAM_TYPE_UNI, name="StreamType", size=2, fuzzable=True)
        
        # Session ID: The stream ID of the CONNECT request.
        # We use a placeholder \xAA that will be replaced.
        s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=True) 
    s_block_end("UniStreamHeader")

    if s_block_start("Payload"):
        s_string("FuzzPayload", fuzzable=True, max_len=1000)
    s_block_end("Payload")
    
    return s_get(session_name)

def define_valid_webtransport_packet(session_name="webtransport_valid"):
    """
    Defines a VALID packet structure for the 'connectivity check' mode.
    """
    s_initialize(session_name)
    s_static(WT_STREAM_TYPE_UNI, name="StreamType")
    s_bytes(value=b"\xAA", name="SessionID", size=1, fuzzable=False) # Placeholder
    s_string("HelloValidWorld", name="Payload", fuzzable=False)
    return s_get(session_name)
