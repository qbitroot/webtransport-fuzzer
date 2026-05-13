from boofuzz import (
    s_initialize,
    s_group,
    s_static,
    s_get,
    s_random,
    s_byte,
    s_block,
    s_dword,
    s_string,
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
    # ---- Cross-protocol numeric boundaries (added for thesis breadth) ----
    2147483647,  # INT32_MAX — common signed-int overflow trigger in C parsers
    2147483648,  # INT32_MAX + 1 — first value that overflows a signed int32
    8388607,  # HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE max (RFC 9113 §6.5.2: 2^31-1
    # is the cap, but 2^23-1 = 16MB is the per-frame DATA limit; tests parsers
    # that erroneously reuse HTTP/2 window-size constants for capsule sizing)
    9007199254740992,  # JS Number.MAX_SAFE_INTEGER + 1; tests JS-runtime
    # implementations (e.g. Node.js WebTransport stacks) where IEEE-754 mantissa
    # precision is lost beyond 2^53.
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
    # ---- Additional WebTransport-capsule overlong encodings ----
    # RFC 9000 §16: VarInts SHOULD be canonically encoded; receivers MAY treat
    # non-canonical encodings as a connection error. These probe whether the
    # stack normalises before dispatching by capsule type, or rejects them.
    b"\xc0\x00\x00\x00\x19\x0b\x4d\x41",  # WT_DATA_BLOCKED (0x190B4D41) overlong 8-byte
    b"\xc0\x00\x00\x00\x19\x0b\x4d\x43",  # WT_STREAMS_BLOCKED bidi (0x190B4D43) overlong 8-byte
    # ---- Overlong encodings of the 1-byte VarInt boundary (value 63) ----
    # Per RFC 9000 §16, 63 fits in a single byte; encoding it with a wider
    # prefix is non-canonical. Probes parser branches that handle encoded
    # widths separately from value ranges (draft-ietf-quic-transport §16).
    b"\x40\x3f",  # value 63 as overlong 2-byte VarInt
    b"\x80\x00\x00\x3f",  # value 63 as overlong 4-byte VarInt
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


def _build_raw_fuzz_blobs() -> list:
    """
    Build the structure-agnostic ("raw") corpus for the oneshot fuzzer.

    These blobs deliberately violate capsule framing to probe parser
    robustness independent of any specific capsule type. Three sub-corpora,
    all derived from ``ALL_INTERESTING_BYTES`` (which already mixes valid
    capsule types, valid VarInts, malformed VarInts, and cross-layer QUIC/HTTP3
    frame types):

    * **Type-only frames**: a single interesting byte sequence with no
      length and no body. Triggers truncation paths and single-byte
      garbage handling (e.g. ``b"\\x41"`` — WT_STREAM signal byte sent
      as a complete capsule).

    * **Type + length, no body**: an interesting type followed by an
      interesting (often invalid) length byte sequence and no payload.
      Probes length/body length-mismatch handling.

    * **Type + matched length + body**: an interesting type with a
      canonically-encoded length matching the body. Tests well-framed
      capsules carrying foreign payload — including cross-layer type
      confusion (e.g. ``b"\\x40\\x41\\x01\\xff"`` — WT_STREAM signal
      type carrying a single foreign byte).

    Returns a deduplicated, order-preserving list of byte blobs.
    """
    blobs = []

    # Sub-corpus 1: type-only (no length, no body)
    for type_bytes in ALL_INTERESTING_BYTES:
        blobs.append(type_bytes)

    # Sub-corpus 2: type + length cross-product, no body
    for type_bytes in ALL_INTERESTING_BYTES:
        for length_bytes in ALL_INTERESTING_BYTES:
            blobs.append(type_bytes + length_bytes)

    # Sub-corpus 3: type + canonical length + body
    for type_bytes in ALL_INTERESTING_BYTES:
        for payload_bytes in ALL_INTERESTING_BYTES:
            valid_length = encode_quic_varint(len(payload_bytes))
            blobs.append(type_bytes + valid_length + payload_bytes)

    # Order-preserving dedup
    return list(dict.fromkeys(blobs))


def _reset_request(name: str):
    """
    Remove a previously-initialised boofuzz Request from the global registry.

    Boofuzz's ``s_initialize`` raises if a Request with the given name
    already exists. The Tier-A sub-Requests are throw-away scaffolding
    used solely to enumerate spec-aware mutations, so we want to be able
    to rebuild them on every call to ``define_oneshot_capsule()``. This
    helper drops the prior Request from ``boofuzz.blocks.REQUESTS`` and
    clears ``blocks.CURRENT`` if it pointed at the same instance.
    """
    from boofuzz import blocks

    if name in blocks.REQUESTS:
        if blocks.CURRENT is blocks.REQUESTS[name]:
            blocks.CURRENT = None
        del blocks.REQUESTS[name]


def _enumerate_request_renders(req):
    """
    Walk every mutation of a boofuzz Request and yield the rendered bytes.

    Used to materialise sub-Requests' mutation outputs into a flat list,
    so multiple specialised per-branch Requests can be unioned into the
    single top-level oneshot Request without fighting boofuzz's lack of
    native switch/case semantics on a top-level group selector.
    """
    from boofuzz.mutation_context import MutationContext

    seen = set()
    for mutations in req.get_mutations():
        ctx = MutationContext(mutations={m.qualified_name: m for m in mutations})
        rendered = req.render(mutation_context=ctx)
        if rendered not in seen:
            seen.add(rendered)
            yield rendered


def _build_tier_a_close_session():
    """Build the WT_CLOSE_SESSION sub-Request (separate session-name)."""
    from src.quic_varint_fuzzable import s_quic_varint

    name = "__tier_a_close_session"
    _reset_request(name)
    s_initialize(name)
    s_static(CAPSULE_CLOSE_SESSION, name="close_type")
    s_quic_varint(name="close_len", block_name="close_payload")
    with s_block("close_payload"):
        s_dword(0, endian=">", name="close_error_code", fuzzable=True)
        s_string("", max_len=1024, name="close_error_message", fuzzable=True)
    return s_get(name)


def _build_tier_a_simple_varint_capsule(name: str, type_bytes: bytes):
    """
    Build a sub-Request for a capsule whose payload is a single VarInt
    (WT_MAX_DATA, WT_MAX_STREAMS_*, WT_DATA_BLOCKED, WT_STREAMS_BLOCKED_*).
    """
    from src.quic_varint_fuzzable import s_quic_varint

    session_name = f"__tier_a_{name}"
    _reset_request(session_name)
    s_initialize(session_name)
    s_static(type_bytes, name=f"{name}_type")
    s_quic_varint(name=f"{name}_len", block_name=f"{name}_payload")
    with s_block(f"{name}_payload"):
        s_quic_varint(name=f"{name}_value", default_value=0)
    return s_get(session_name)


def _build_tier_a_drain_session():
    """Build the WT_DRAIN_SESSION sub-Request (empty payload per spec)."""
    from src.quic_varint_fuzzable import s_quic_varint

    name = "__tier_a_drain_session"
    _reset_request(name)
    s_initialize(name)
    s_static(CAPSULE_DRAIN_SESSION, name="drain_type")
    s_quic_varint(name="drain_len", block_name="drain_payload")
    with s_block("drain_payload"):
        s_static(b"", name="drain_payload_empty")
    return s_get(name)


def _build_tier_a_blobs() -> list:
    """
    Materialise every Tier-A spec-aware sub-Request into a deduplicated
    list of fully-rendered byte sequences.

    This is necessary because boofuzz lacks native switch/case semantics
    at the top-level Request: ``s_block(group=...)`` iterates but does
    not gate rendering, and ``s_block(dep=...)`` gates rendering but
    only triggers a single render-pass per group-value. Combining both
    leaves branch-internal mutations un-paired with the selector.

    Workaround: define each branch as its own sub-Request, exhaust its
    mutation generator, dedup, and union the resulting bytes into the
    top-level oneshot ``s_group`` together with the Tier-B raw blobs.

    The advantages of native boofuzz primitives — ``s_dword`` boundary
    cases, ``s_string`` SPIKE-derived mutations (format strings, oversize
    buffers, UTF-8 boundaries), and the ``QuicVarInt`` sizer's spec-aware
    integer + malformed-byte mutation pool — are preserved by this
    approach because the sub-Requests run those primitives during
    enumeration. Only the runtime laziness of mutation generation is
    given up; this is acceptable because the corpus is built once at
    fuzz-session start.
    """
    blobs = []
    blobs.extend(_enumerate_request_renders(_build_tier_a_close_session()))
    blobs.extend(_enumerate_request_renders(_build_tier_a_drain_session()))
    blobs.extend(
        _enumerate_request_renders(
            _build_tier_a_simple_varint_capsule("max_data", CAPSULE_MAX_DATA)
        )
    )
    blobs.extend(
        _enumerate_request_renders(
            _build_tier_a_simple_varint_capsule(
                "max_streams_bidi", CAPSULE_MAX_STREAMS_BIDI
            )
        )
    )
    blobs.extend(
        _enumerate_request_renders(
            _build_tier_a_simple_varint_capsule(
                "max_streams_uni", CAPSULE_MAX_STREAMS_UNI
            )
        )
    )
    blobs.extend(
        _enumerate_request_renders(
            _build_tier_a_simple_varint_capsule("data_blocked", CAPSULE_DATA_BLOCKED)
        )
    )
    blobs.extend(
        _enumerate_request_renders(
            _build_tier_a_simple_varint_capsule(
                "streams_blocked_bidi", CAPSULE_STREAMS_BLOCKED_BIDI
            )
        )
    )
    blobs.extend(
        _enumerate_request_renders(
            _build_tier_a_simple_varint_capsule(
                "streams_blocked_uni", CAPSULE_STREAMS_BLOCKED_UNI
            )
        )
    )
    return list(dict.fromkeys(blobs))


def define_oneshot_capsule(session_name="wt_oneshot"):
    """
    One-shot capsule fuzzer (Tier-A spec-aware + Tier-B raw) — flattened.

    The corpus is built in two tiers and unioned into a single top-level
    ``s_group`` so boofuzz's session machinery (resume via ``index_start``/
    ``index_end``, web UI test-case enumeration, monitor invocation) sees
    a flat enumeration of byte blobs:

    **Tier A — spec-typed capsule branches** (draft-ietf-webtrans-http3-14 §4.7):
      * ``close_session`` — WT_CLOSE_SESSION (0x2843): 32-bit BE Application
        Error Code (boofuzz ``s_dword`` mutations) + UTF-8 Error Message
        ≤ 1024 B (boofuzz ``s_string`` SPIKE-derived mutations).
      * ``drain_session`` — WT_DRAIN_SESSION (0x78AE): empty payload.
      * ``max_data`` — WT_MAX_DATA (0x190B4D3D): single VarInt payload.
      * ``max_streams_bidi`` / ``max_streams_uni`` — WT_MAX_STREAMS
        (0x190B4D3F / 0x190B4D40): single VarInt payload.
      * ``data_blocked`` — WT_DATA_BLOCKED (0x190B4D41): single VarInt.
      * ``streams_blocked_bidi`` / ``streams_blocked_uni`` —
        WT_STREAMS_BLOCKED (0x190B4D43 / 0x190B4D44): single VarInt.

      Each branch's Length field is a real ``QuicVarInt`` sizer that
      recomputes from the (possibly-mutated) payload — so payload
      mutations naturally drive length-field mutations consistent with
      RFC 9000 §16 canonical encoding.

    **Tier B — structure-agnostic raw**:
      ``_build_raw_fuzz_blobs()`` covers single-byte frames, type-only
      frames, type+length-only frames, and type+length+body frames
      including cross-layer (QUIC/HTTP3 frame-type) confusion blobs.
    """
    # Build Tier-A first (it consumes throw-away sub-Request names), then
    # initialise the public top-level Request. Resetting the public name
    # also makes the function safe to call multiple times in the same
    # interpreter session (e.g. tests, REPL inspection).
    tier_a = _build_tier_a_blobs()
    tier_b = _build_raw_fuzz_blobs()

    _reset_request(session_name)
    s_initialize(session_name)

    # Order-preserving union: Tier A first (spec-aware), then Tier B (raw).
    all_blobs = list(dict.fromkeys(tier_a + tier_b))

    s_group(values=all_blobs, name="oneshot_capsule_corpus")

    return s_get(session_name)


# =============================================================================
# Capsule Builder Helpers
#
# Build well-formed capsules for multistep sequence fuzzing.
# Format: [Type (VarInt)][Length (VarInt)][Payload]
# =============================================================================


def build_close_session(error_code: int = 0, message: str = "") -> bytes:
    """
    Build a valid CLOSE_WEBTRANSPORT_SESSION capsule (0x2843).

    Payload: [Application Error Code (32-bit BE)][Error Message (UTF-8, max 1024)]
    """
    msg_bytes = message.encode("utf-8")[:1024]
    payload = struct.pack(">I", error_code) + msg_bytes
    return CAPSULE_CLOSE_SESSION + encode_quic_varint(len(payload)) + payload


def build_drain_session() -> bytes:
    """
    Build a valid DRAIN_WEBTRANSPORT_SESSION capsule (0x78AE).

    Payload: empty (Length = 0).
    """
    return CAPSULE_DRAIN_SESSION + b"\x00"


def build_max_data(limit: int) -> bytes:
    """
    Build a WT_MAX_DATA capsule (0x190B4D3D).

    Payload: [Maximum Data (VarInt)]
    """
    payload = encode_quic_varint(limit)
    return CAPSULE_MAX_DATA + encode_quic_varint(len(payload)) + payload


def build_max_streams(limit: int, bidi: bool = True) -> bytes:
    """
    Build a WT_MAX_STREAMS capsule.

    bidi=True  -> 0x190B4D3F (bidirectional)
    bidi=False -> 0x190B4D40 (unidirectional)

    Payload: [Maximum Streams (VarInt)]
    """
    capsule_type = CAPSULE_MAX_STREAMS_BIDI if bidi else CAPSULE_MAX_STREAMS_UNI
    payload = encode_quic_varint(limit)
    return capsule_type + encode_quic_varint(len(payload)) + payload


def build_data_blocked(limit: int) -> bytes:
    """
    Build a WT_DATA_BLOCKED capsule (0x190B4D41).

    Payload: [Maximum Data (VarInt)] — the limit at which blocking occurred.
    """
    payload = encode_quic_varint(limit)
    return CAPSULE_DATA_BLOCKED + encode_quic_varint(len(payload)) + payload


def build_streams_blocked(limit: int, bidi: bool = True) -> bytes:
    """
    Build a WT_STREAMS_BLOCKED capsule.

    bidi=True  -> 0x190B4D43 (bidirectional)
    bidi=False -> 0x190B4D44 (unidirectional)

    Payload: [Maximum Streams (VarInt)] — the limit at which blocking occurred.
    """
    capsule_type = CAPSULE_STREAMS_BLOCKED_BIDI if bidi else CAPSULE_STREAMS_BLOCKED_UNI
    payload = encode_quic_varint(limit)
    return capsule_type + encode_quic_varint(len(payload)) + payload


# =============================================================================
# Multistep Scenarios
#
# Each scenario is a list of Steps (dicts with an "action" key).
# Steps can be data operations (bidi, uni, datagram) or capsule injections.
# The sequence_mutator generates permutations, duplications, omissions,
# and injections — including post-CLOSE data activity.
#
# This is fundamentally different from oneshot: the server has real streams
# and data in flight when capsules arrive, giving the fuzzer a much richer
# attack surface (use-after-free, state confusion, etc.)
# =============================================================================


def _build_multistep_scenarios():
    """
    Build scenario dict. Deferred to a function so step_* helpers are available
    at import time (they come from sequence_mutator).
    """
    from src.sequence_mutator import (
        step_bidi,
        step_uni,
        step_datagram,
        step_capsule,
        step_sleep,
    )

    return {
        # ---- Scenario 1: Bidi echo then graceful shutdown ----
        # Establish real data flow, then tear down cleanly.
        # Mutations: close before echo, drain mid-stream, double close, etc.
        "bidi_then_shutdown": [
            step_bidi(b"HELLO"),
            step_capsule(build_drain_session()),
            step_capsule(build_close_session(error_code=0)),
        ],
        # ---- Scenario 2: Multiple transports then close ----
        # Exercise all three data paths, then close.
        # Server has bidi, uni, and datagram state simultaneously.
        "all_transports_then_close": [
            step_bidi(b"BIDI_PAYLOAD"),
            step_uni(b"UNI_PAYLOAD"),
            step_datagram(b"DGRAM_PAYLOAD"),
            step_capsule(build_close_session(error_code=0)),
        ],
        # ---- Scenario 3: Capsule between bidi streams ----
        # Two bidi echo exchanges with a capsule in between.
        # Tests: does a capsule disrupt ongoing stream processing?
        "capsule_between_bidi": [
            step_bidi(b"FIRST"),
            step_capsule(build_max_data(65536)),
            step_bidi(b"SECOND"),
        ],
        # ---- Scenario 4: Drain mid-conversation ----
        # Send drain while data streams are active.
        # Server should stay alive but prepare to shut down.
        "drain_mid_data": [
            step_bidi(b"BEFORE_DRAIN"),
            step_capsule(build_drain_session()),
            step_bidi(b"AFTER_DRAIN"),
            step_uni(b"UNI_AFTER_DRAIN"),
        ],
        # ---- Scenario 5: Flow control with active streams ----
        # Set flow limits while data is flowing.
        # Tests: does MAX_DATA mid-stream confuse stream accounting?
        "flow_with_streams": [
            step_capsule(build_max_streams(10, bidi=True)),
            step_capsule(build_max_streams(10, bidi=False)),
            step_bidi(b"DATA_UNDER_LIMIT"),
            step_capsule(build_max_data(65536)),
            step_uni(b"MORE_DATA"),
        ],
        # ---- Scenario 6: Close with error after data ----
        # Successful echo then abnormal close with error code + message.
        # Tests: error code and UTF-8 message parsing after real activity.
        "close_error_after_data": [
            step_bidi(b"NORMAL_ECHO"),
            step_datagram(b"NORMAL_DG"),
            step_capsule(build_close_session(error_code=42, message="test error")),
        ],
        # ---- Scenario 7: Rapid bidi then close ----
        # Burst of bidi streams followed by immediate close.
        # Tests: does the server handle rapid stream creation before close?
        "rapid_bidi_close": [
            step_bidi(b"A"),
            step_bidi(b"BB"),
            step_bidi(b"CCC"),
            step_capsule(build_close_session(error_code=0)),
        ],
        # ---- Scenario 8: Datagram flood then drain ----
        # Multiple datagrams then a drain signal.
        # Datagrams are unreliable; tests: drain during datagram processing.
        "datagram_flood_drain": [
            step_datagram(b"D1"),
            step_datagram(b"D2"),
            step_datagram(b"D3"),
            step_capsule(build_drain_session()),
        ],
        # ---- Scenario 9: Interleaved uni + capsules ----
        # Uni streams interleaved with flow control capsules.
        # Tests: capsule processing doesn't block/corrupt uni stream handling.
        "uni_capsule_interleave": [
            step_uni(b"UNI_1"),
            step_capsule(build_data_blocked(0)),
            step_uni(b"UNI_2"),
            step_capsule(build_max_data(4096)),
            step_uni(b"UNI_3"),
        ],
        # ---- Scenario 10: Kitchen sink ----
        # One of everything in a plausible order. Maximum permutation surface.
        "kitchen_sink": [
            step_capsule(build_max_streams(10, bidi=True)),
            step_bidi(b"ECHO_ME"),
            step_uni(b"FIRE_FORGET"),
            step_datagram(b"UNRELIABLE"),
            step_capsule(build_drain_session()),
            step_capsule(build_close_session(error_code=0, message="done")),
        ],
        # ---- Scenario 11: Contradictory limits with data ----
        # Set MAX_DATA to 0 (block everything), try data, then raise limit.
        "contradictory_limits_with_data": [
            step_capsule(build_max_data(0)),
            step_bidi(b"SHOULD_THIS_WORK"),
            step_capsule(build_max_data(65536)),
            step_bidi(b"NOW_IT_SHOULD"),
        ],
        # ---- Scenario 12: Streams blocked signaling with data ----
        # Report blocked, then try to create streams anyway.
        "blocked_then_create": [
            step_capsule(build_streams_blocked(0, bidi=True)),
            step_bidi(b"BIDI_DESPITE_BLOCKED"),
            step_capsule(build_streams_blocked(0, bidi=False)),
            step_uni(b"UNI_DESPITE_BLOCKED"),
        ],
    }


def _build_lastfuzz_capsules() -> list:
    """
    Build a list of malformed capsule blobs for scenario-lastfuzz mode.

    Mirrors the oneshot fuzzer's independent-axis strategy (not a full
    cross-product) to keep the test count manageable:

      Axis 1 — Fuzz capsule type, use a neutral length+payload:
               [FuzzedType][0x00]  (length=0, no body)

      Axis 2 — Fuzz length+payload, use a neutral capsule type:
               [0x00][FuzzedLengthAndPayload]  (type=0, unknown → must be ignored)

    Reuses ALL_INTERESTING_BYTES from the oneshot definition to stay DRY.
    """
    DEFAULT_LENGTH_PAYLOAD = b"\x00"  # VarInt length=0, empty body
    DEFAULT_TYPE = b"\x00"  # Type 0 (unknown, must be ignored per RFC 9297)

    blobs = []

    # Axis 1: fuzz type, neutral length+payload
    for capsule_type in ALL_INTERESTING_BYTES:
        blobs.append(capsule_type + DEFAULT_LENGTH_PAYLOAD)

    # Axis 2: fuzz length+payload, neutral type
    # Without body: length is fuzzed, body is empty
    for length_bytes in ALL_INTERESTING_BYTES:
        blobs.append(DEFAULT_TYPE + length_bytes)
    # With body: length is valid, body is an interesting payload
    for payload_bytes in ALL_INTERESTING_BYTES:
        valid_length = encode_quic_varint(len(payload_bytes))
        blobs.append(DEFAULT_TYPE + valid_length + payload_bytes)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for b in blobs:
        if b not in seen:
            seen.add(b)
            unique.append(b)
    return unique


def define_scenario_lastfuzz(session_name="wt_scenario_lastfuzz"):
    """
    Scenario-lastfuzz mode: play each scenario in original order (no
    permutations), but replace the last step with a malformed capsule.

    This puts the server into a specific state via legitimate traffic
    (bidi, uni, datagram, capsule steps) and then sends a single fuzzed
    capsule — combining the state-richness of multistep scenarios with
    the capsule-level coverage of oneshot mode.

    Test cases = scenarios × fuzz blobs.

    Returns:
        The boofuzz Request object.
    """
    from src.sequence_mutator import step_capsule, encode_scenario

    scenarios = _build_multistep_scenarios()
    fuzz_blobs = _build_lastfuzz_capsules()

    all_encoded = []
    for _name, scenario in scenarios.items():
        prefix = scenario[:-1] if len(scenario) > 1 else []
        for blob in fuzz_blobs:
            mutated = prefix + [step_capsule(blob)]
            all_encoded.append(encode_scenario(mutated))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for m in all_encoded:
        if m not in seen:
            seen.add(m)
            unique.append(m)

    s_initialize(session_name)
    s_group(values=unique, name="ScenarioLastFuzz")

    return s_get(session_name)


def _build_oneshot_as_scenarios() -> list:
    """
    Re-encode every oneshot capsule test case as a single-step scenario.

    This allows oneshot blobs to be mixed into a unified s_group that
    uses send_mode="scenario", keeping the 'all' mode executor uniform.

    Mirrors define_oneshot_capsule() exactly: the two s_group axes are
    iterated in lockstep with each axis held at its default while the
    other varies, and the compound blob [type + length_and_payload] is
    what gets sent.

      Axis 1 — type varies, LengthAndPayload fixed at default (first value):
                [FuzzedType][DefaultLAP]

      Axis 2 — type fixed at default (first value), LengthAndPayload varies:
                [DefaultType][FuzzedLAP]

    The seed case (both defaults) is included as well.
    """
    from src.sequence_mutator import step_capsule, encode_scenario

    # Build the LengthAndPayload list exactly as define_oneshot_capsule does
    length_and_payload = []
    for length_bytes in ALL_INTERESTING_BYTES:
        length_and_payload.append(length_bytes + b"")
    for payload_bytes in ALL_INTERESTING_BYTES:
        valid_length = encode_quic_varint(len(payload_bytes))
        length_and_payload.append(valid_length + payload_bytes)
    unique_lap = list(dict.fromkeys(length_and_payload))

    default_type = ALL_INTERESTING_BYTES[0]
    default_lap = unique_lap[0]

    blobs = []
    # Seed: both axes at default
    blobs.append(default_type + default_lap)
    # Axis 1: type varies, LAP held at default
    for capsule_type in ALL_INTERESTING_BYTES[1:]:
        blobs.append(capsule_type + default_lap)
    # Axis 2: LAP varies, type held at default
    for lap in unique_lap[1:]:
        blobs.append(default_type + lap)

    # Deduplicate while preserving order, then wrap each as a 1-step scenario
    seen = set()
    unique = []
    for b in blobs:
        if b not in seen:
            seen.add(b)
            unique.append(encode_scenario([step_capsule(b)]))
    return unique


def define_all(session_name="wt_all"):
    """
    Combined mode: concatenates test cases from all three modes into a
    single boofuzz s_group.

    Order: oneshot (as scenarios) → multistep → scenario-lastfuzz.

    Everything uses the scenario encoding so the connection executor
    (send_mode="scenario") handles all cases uniformly.

    Returns:
        The boofuzz Request object.
    """
    from src.sequence_mutator import generate_sequence_mutations, encode_scenario

    all_values = []

    # 1. Oneshot capsules wrapped as single-step scenarios
    all_values.extend(_build_oneshot_as_scenarios())

    # 2. Multistep mutations
    scenarios = _build_multistep_scenarios()
    for _name, scenario in scenarios.items():
        for mutation in generate_sequence_mutations(scenario):
            all_values.append(encode_scenario(mutation))

    # 3. Scenario-lastfuzz
    from src.sequence_mutator import step_capsule

    fuzz_blobs = _build_lastfuzz_capsules()
    for _name, scenario in scenarios.items():
        prefix = scenario[:-1] if len(scenario) > 1 else []
        for blob in fuzz_blobs:
            all_values.append(encode_scenario(prefix + [step_capsule(blob)]))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for m in all_values:
        if m not in seen:
            seen.add(m)
            unique.append(m)

    s_initialize(session_name)
    s_group(values=unique, name="AllModes")

    return s_get(session_name)


def define_multistep(session_name="wt_multistep"):
    """
    Multistep scenario fuzzer.

    Pre-generates all step-sequence mutations from MULTISTEP_SCENARIOS,
    encodes each as a binary scenario, and wraps them as a boofuzz s_group.

    The connection decodes each scenario at send-time and executes the
    steps (bidi, uni, datagram, capsule, sleep) in order.

    Returns:
        The boofuzz Request object.
    """
    from src.sequence_mutator import generate_sequence_mutations, encode_scenario

    scenarios = _build_multistep_scenarios()
    all_mutations = []

    for _name, scenario in scenarios.items():
        for mutation in generate_sequence_mutations(scenario):
            all_mutations.append(encode_scenario(mutation))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for m in all_mutations:
        if m not in seen:
            seen.add(m)
            unique.append(m)

    s_initialize(session_name)
    s_group(values=unique, name="ScenarioSequence")

    return s_get(session_name)
