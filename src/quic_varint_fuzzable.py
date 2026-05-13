"""
QuicVarInt: a custom boofuzz Fuzzable primitive for QUIC Variable-Length Integers.

WebTransport-over-HTTP/3 (draft-ietf-webtrans-http3-14) uses QUIC VarInts
(RFC 9000 §16) for capsule Type and Length fields. QUIC VarInts have a 2-bit
length prefix selecting 1-, 2-, 4-, or 8-byte width. Boofuzz's built-in
``Size``/``BitField`` classes only render fixed-width integers (``length * 8``
bits), so they cannot produce protocol-faithful VarInts. This subclass extends
boofuzz's ``Fuzzable`` interface to fill that gap.

Two roles, selected by the ``block_name`` constructor argument:

* **Sizer (length-of) role** — when ``block_name`` is set, the primitive computes
  ``len(target_block.render(...))`` at render time and emits the result as a
  canonically-encoded VarInt. Mirrors the contract of ``boofuzz.blocks.Size``.

* **Standalone fuzzed VarInt role** — when ``block_name`` is None, the primitive
  emits a fuzzable VarInt whose default value is given by ``default_value``.
  Used for capsule payloads that themselves are a single VarInt (e.g. the
  ``Maximum Data`` field of WT_MAX_DATA, draft-ietf-webtrans-http3-14 §4.7.5).

Mutation source (both roles):

* Integer mutations from ``INTERESTING_NUMBERS`` (boundary values around
  VarInt width transitions and protocol-defined limits — see
  ``src/boofuzz_definitions.py``).
* Raw byte mutations from ``MALFORMED_VARINTS`` (overlong, truncated, and
  oversized encodings) — emitted verbatim to bypass canonical VarInt encoding,
  enabling tests against parser robustness rather than just value handling.

Combining the two axes in a single primitive is intentional: the boofuzz
mutation engine treats them as a flat sequence, so cross-product enumeration
with sibling fields (capsule type, payload contents) follows naturally.
"""

from boofuzz import blocks
from boofuzz.fuzzable import Fuzzable
from boofuzz import helpers


def _push_to_current_request(item):
    """
    Push a Fuzzable instance onto the currently-open boofuzz request.

    This mirrors what the ``s_*`` helper functions in ``boofuzz/__init__.py``
    do internally (see e.g. ``s_size`` at boofuzz/__init__.py:527). Calling
    ``blocks.CURRENT.push(item)`` registers the item with the active Request
    so its ``request`` and ``context_path`` attributes get set, enabling
    ``Request.resolve_name(...)`` lookups during render.
    """
    blocks.CURRENT.push(item)


class QuicVarInt(Fuzzable):
    """
    A fuzzable QUIC Variable-Length Integer field.

    :param name: boofuzz field name.
    :param block_name: if set, this primitive acts as a length-of sizer for
        the named sibling block; if None, it is a standalone fuzzable VarInt.
    :param default_value: integer used as the un-mutated value (sizer role
        ignores this and computes the target length instead).
    :param fuzzable: enable mutation; defaults to True.
    """

    def __init__(self, name=None, block_name=None, default_value=0, fuzzable=True):
        super().__init__(name=name, default_value=default_value, fuzzable=fuzzable)
        self.block_name = block_name
        # Lazy import to avoid circular import at module load time.
        from src.boofuzz_definitions import (
            INTERESTING_NUMBERS,
            MALFORMED_VARINTS,
            encode_quic_varint,
        )

        self._interesting_numbers = INTERESTING_NUMBERS
        self._malformed_varints = MALFORMED_VARINTS
        self._encode_varint = encode_quic_varint
        self._recursion_flag = False

    # -- mutation generation ---------------------------------------------------

    def mutations(self, default_value):
        """
        Yield mutations across two axes, in order:

        1. Integers from ``INTERESTING_NUMBERS`` — these will be VarInt-encoded
           by ``encode()``.
        2. Raw byte sequences from ``MALFORMED_VARINTS`` — emitted verbatim by
           ``encode()`` so they can carry malformed/overlong/truncated framing.
        """
        for n in self._interesting_numbers:
            yield n
        for raw in self._malformed_varints:
            yield raw

    def num_mutations(self, default_value):
        return len(self._interesting_numbers) + len(self._malformed_varints)

    # -- rendering -------------------------------------------------------------

    def encode(self, value, mutation_context):
        """
        Encode the current value to bytes.

        Three input cases:

        * ``bytes`` — emit verbatim. Used for ``MALFORMED_VARINTS`` mutations
          and to allow injection of any pre-encoded byte sequence.
        * ``int`` — encode as a canonical QUIC VarInt. Used for default values
          and for ``INTERESTING_NUMBERS`` mutations.
        * ``None`` — sizer role: resolve the target block, render it, and emit
          ``len(...)`` as a canonical VarInt. Mirrors ``boofuzz.blocks.Size``.
        """
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)

        if isinstance(value, int):
            return self._encode_varint(value)

        if value is None:
            if self.block_name is None:
                # No sizer target and no value — emit empty.
                return b""
            if self._recursion_flag:
                # Mirror Size._get_dummy_value() to break render-time recursion;
                # 1 byte is the smallest valid VarInt width.
                return b"\x00"
            return self._encode_varint(self._length_of_target_block(mutation_context))

        # Defensive default: stringify and treat as bytes via boofuzz helper.
        return helpers.str_to_bytes(value)

    # -- sizer-role helpers (mirrors boofuzz.blocks.size.Size) -----------------

    def _length_of_target_block(self, mutation_context):
        """Resolve target block and return its rendered length in bytes."""
        if self.request is None or self.block_name is None:
            return 0
        self._recursion_flag = True
        try:
            target = self.request.resolve_name(self.context_path, self.block_name)
            return len(target.render(mutation_context=mutation_context))
        finally:
            self._recursion_flag = False


def s_quic_varint(name=None, block_name=None, default_value=0, fuzzable=True):
    """
    Convenience helper mirroring boofuzz's ``s_*`` style: instantiates a
    ``QuicVarInt`` and pushes it onto the currently-open request.
    """
    _push_to_current_request(
        QuicVarInt(
            name=name,
            block_name=block_name,
            default_value=default_value,
            fuzzable=fuzzable,
        )
    )
