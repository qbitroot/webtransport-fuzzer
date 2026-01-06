"""
QUIC Variable-Length Integer (VarInt) encoding utilities.
Per RFC 9000 Section 16: https://www.rfc-editor.org/rfc/rfc9000#section-16
"""


def encode_varint(value: int) -> bytes:
    """
    Encode an integer as a QUIC variable-length integer.
    
    Args:
        value: Non-negative integer to encode (max 2^62 - 1)
        
    Returns:
        Bytes representing the VarInt encoding
        
    Raises:
        ValueError: If value is negative or too large
    """
    if value < 0:
        raise ValueError("VarInt cannot be negative")
    
    if value < 64:  # 6 bits, 1 byte
        return bytes([value])
    
    elif value < 16384:  # 14 bits, 2 bytes
        return bytes([
            0x40 | (value >> 8),
            value & 0xFF
        ])
    
    elif value < 1073741824:  # 30 bits, 4 bytes
        return bytes([
            0x80 | (value >> 24),
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF
        ])
    
    elif value < 4611686018427387904:  # 62 bits, 8 bytes
        return bytes([
            0xC0 | (value >> 56),
            (value >> 48) & 0xFF,
            (value >> 40) & 0xFF,
            (value >> 32) & 0xFF,
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF
        ])
    
    else:
        raise ValueError(f"VarInt value too large: {value}")


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a QUIC variable-length integer from bytes.
    
    Args:
        data: Bytes containing the VarInt
        offset: Starting offset in the data
        
    Returns:
        Tuple of (decoded_value, bytes_consumed)
        
    Raises:
        ValueError: If data is too short or malformed
    """
    if offset >= len(data):
        raise ValueError("Not enough data to decode VarInt")
    
    first_byte = data[offset]
    prefix = first_byte >> 6
    
    if prefix == 0:  # 1 byte
        return first_byte, 1
    
    elif prefix == 1:  # 2 bytes
        if offset + 2 > len(data):
            raise ValueError("Not enough data for 2-byte VarInt")
        value = ((first_byte & 0x3F) << 8) | data[offset + 1]
        return value, 2
    
    elif prefix == 2:  # 4 bytes
        if offset + 4 > len(data):
            raise ValueError("Not enough data for 4-byte VarInt")
        value = (
            ((first_byte & 0x3F) << 24) |
            (data[offset + 1] << 16) |
            (data[offset + 2] << 8) |
            data[offset + 3]
        )
        return value, 4
    
    else:  # 8 bytes
        if offset + 8 > len(data):
            raise ValueError("Not enough data for 8-byte VarInt")
        value = (
            ((first_byte & 0x3F) << 56) |
            (data[offset + 1] << 48) |
            (data[offset + 2] << 40) |
            (data[offset + 3] << 32) |
            (data[offset + 4] << 24) |
            (data[offset + 5] << 16) |
            (data[offset + 6] << 8) |
            data[offset + 7]
        )
        return value, 8


def varint_size(value: int) -> int:
    """Return the number of bytes needed to encode a value as VarInt."""
    if value < 64:
        return 1
    elif value < 16384:
        return 2
    elif value < 1073741824:
        return 4
    elif value < 4611686018427387904:
        return 8
    else:
        raise ValueError(f"VarInt value too large: {value}")


# Common capsule type values and their encodings
CAPSULE_TYPES = {
    "WT_CLOSE_SESSION": 0x2843,
    "WT_DRAIN_SESSION": 0x78AE,
    "WT_MAX_DATA": 0x190B4D3D,
    "WT_MAX_STREAM_DATA": 0x190B4D3E,
    "WT_MAX_STREAMS_BIDI": 0x190B4D3F,
    "WT_MAX_STREAMS_UNI": 0x190B4D40,
    "WT_DATA_BLOCKED": 0x190B4D41,
    "WT_STREAM_DATA_BLOCKED": 0x190B4D42,
    "WT_STREAMS_BLOCKED_BIDI": 0x190B4D43,
    "WT_STREAMS_BLOCKED_UNI": 0x190B4D44,
    "PADDING": 0x190B4D38,
    "WT_STREAM": 0x190B4D3B,
    "WT_STREAM_FIN": 0x190B4D3C,
    "WT_RESET_STREAM": 0x190B4D39,
    "WT_STOP_SENDING": 0x190B4D3A,
}


def encode_capsule_type(type_name: str) -> bytes:
    """Encode a capsule type name to its VarInt bytes."""
    if type_name not in CAPSULE_TYPES:
        raise ValueError(f"Unknown capsule type: {type_name}")
    return encode_varint(CAPSULE_TYPES[type_name])


def build_capsule(type_value: int, payload: bytes = b"") -> bytes:
    """
    Build a complete capsule with type, length, and payload.
    
    Args:
        type_value: The capsule type as an integer
        payload: The capsule payload bytes
        
    Returns:
        Complete capsule bytes: [Type VarInt][Length VarInt][Payload]
    """
    type_bytes = encode_varint(type_value)
    length_bytes = encode_varint(len(payload))
    return type_bytes + length_bytes + payload
