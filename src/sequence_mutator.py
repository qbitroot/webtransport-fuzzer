"""
Step + Scenario types and the multistep mutation engine.

A scenario is a tuple of Steps. Each Step is an action the fuzzer performs
on a live WebTransport session: send a bidi stream, send a uni stream,
send a datagram, or inject a raw capsule.

The mutator takes a scenario and generates all interesting re-orderings:
permutations, duplications, omissions, rapid-fire bursts, reversal, and
prohibited-capsule injections. All operators preserve action types so the
connection knows how to execute each step.

For boofuzz transport, scenarios are not encoded into bytes directly.
Instead, ``ScenarioRegistry`` assigns each unique scenario a sequential
integer id, and the bytes value handed to ``s_group`` is a fixed-width
8-byte token of the form ``b"WTSC" + id (BE u32)``. The connection
decodes the token and looks up the scenario by id at send time. This
avoids JSON-in-bytes encoding entirely.
"""

from __future__ import annotations

import itertools
import struct
from dataclasses import dataclass
from typing import Iterable, List, Tuple

from src.boofuzz_definitions import encode_quic_varint


# ---- Step type ----

Action = str  # "bidi" | "uni" | "datagram" | "capsule"


@dataclass(frozen=True)
class Step:
    """A single step in a multistep scenario.

    Attributes:
        action: One of ``bidi``, ``uni``, ``datagram``, ``capsule``.
        data:   Payload bytes for the action.

    The class is frozen so it is hashable, which lets us dedupe whole
    scenarios via tuple-of-Step set membership.
    """

    action: Action
    data: bytes

    def __repr__(self) -> str:  # pragma: no cover — for debug only
        return f"Step({self.action}, {len(self.data)}B)"


Scenario = Tuple[Step, ...]


def step_bidi(data: bytes) -> Step:
    """Bidirectional stream step (sends data, server echoes)."""
    return Step("bidi", data)


def step_uni(data: bytes) -> Step:
    """Unidirectional stream step (fire-and-forget; server may echo)."""
    return Step("uni", data)


def step_datagram(data: bytes) -> Step:
    """Datagram step (unreliable, server may echo)."""
    return Step("datagram", data)


def step_capsule(data: bytes) -> Step:
    """Raw capsule on the CONNECT stream (session control channel)."""
    return Step("capsule", data)


# ---- Prohibited capsule types (draft-ietf-webtrans-http3-14 §5.4) ----

CAPSULE_MAX_STREAM_DATA = b"\x99\x0b\x4d\x3e"  # 0x190B4D3E
CAPSULE_STREAM_DATA_BLOCKED = b"\x99\x0b\x4d\x42"  # 0x190B4D42


def _build_prohibited_capsules() -> List[bytes]:
    """Well-formed capsules whose receipt MUST be a session error per spec."""
    capsules = []
    # WT_MAX_STREAM_DATA(stream_id=4, limit=999)
    payload = encode_quic_varint(4) + encode_quic_varint(999)
    capsules.append(
        CAPSULE_MAX_STREAM_DATA + encode_quic_varint(len(payload)) + payload
    )
    # WT_STREAM_DATA_BLOCKED(stream_id=4, limit=999)
    payload = encode_quic_varint(4) + encode_quic_varint(999)
    capsules.append(
        CAPSULE_STREAM_DATA_BLOCKED + encode_quic_varint(len(payload)) + payload
    )
    return capsules


PROHIBITED_CAPSULES = _build_prohibited_capsules()

MAX_PERMUTATIONS = 5040  # 7! — see boofuzz_definitions for rationale


# ---- Mutation engine ----


def generate_sequence_mutations(scenario: Scenario) -> List[Scenario]:
    """
    Generate all interesting mutations of a step scenario.

    The returned list is deduplicated and order-preserved (insertion
    order). Each mutation is a tuple of Steps so callers can use a set
    keyed directly on the tuple for global dedup.
    """
    seen: set[Scenario] = set()
    out: List[Scenario] = []

    def add(seq: Iterable[Step]) -> None:
        s = tuple(seq)
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    scenario = tuple(scenario)
    n = len(scenario)
    add(scenario)

    # 1. Permutations (capped)
    if n > 1:
        for i, perm in enumerate(itertools.permutations(scenario)):
            if i >= MAX_PERMUTATIONS:
                break
            add(perm)

    # 2. Each step duplicated in place, then duplicated at end
    for i in range(n):
        add(scenario[:i] + (scenario[i], scenario[i]) + scenario[i + 1 :])
    for i in range(n):
        add(scenario + (scenario[i],))

    # 3. Each step omitted
    if n > 1:
        for i in range(n):
            add(scenario[:i] + scenario[i + 1 :])

    # 4. Rapid-fire: same step repeated 2/5/10×
    for step in scenario:
        for k in (2, 5, 10):
            add((step,) * k)

    # 5. Reversed order
    if n > 1:
        add(scenario[::-1])

    # 6. Inject prohibited capsule at every position
    for i in range(n + 1):
        for prohibited in PROHIBITED_CAPSULES:
            add(scenario[:i] + (step_capsule(prohibited),) + scenario[i:])

    # 7. Post-CLOSE_SESSION activity: probe whether the server still serves
    #    streams/datagrams after a graceful close
    from src.boofuzz_definitions import CAPSULE_CLOSE_SESSION, CAPSULE_DRAIN_SESSION

    drain_capsule = CAPSULE_DRAIN_SESSION + b"\x00"
    after_close_steps = [
        step_bidi(b"AFTERCLOSE"),
        step_uni(b"AFTERCLOSE"),
        step_datagram(b"AFTERCLOSE"),
        step_capsule(drain_capsule),
    ] + [step_capsule(p) for p in PROHIBITED_CAPSULES]

    for i, step in enumerate(scenario):
        if step.action == "capsule" and step.data.startswith(CAPSULE_CLOSE_SESSION):
            for follow in after_close_steps:
                add(scenario[: i + 1] + (follow,))

    return out


# ---- Scenario registry: bytes-token <-> Scenario lookup for boofuzz s_group ----

_SCENARIO_MAGIC = b"WTSC"
_SCENARIO_TOKEN_LEN = len(_SCENARIO_MAGIC) + 4  # magic + uint32 BE


class ScenarioRegistry:
    """
    Per-process registry that assigns each unique scenario a sequential id
    and produces a fixed-width 8-byte token suitable for ``s_group``.

    A single global registry is sufficient because boofuzz session
    definitions are only built once per run and live in the same process
    as the connection that resolves them at send time.
    """

    def __init__(self) -> None:
        self._scenarios: List[Scenario] = []
        self._index: dict[Scenario, int] = {}

    def __len__(self) -> int:
        return len(self._scenarios)

    def register(self, scenario: Scenario) -> bytes:
        """Return the token for ``scenario``, registering it if new."""
        scenario = tuple(scenario)
        idx = self._index.get(scenario)
        if idx is None:
            idx = len(self._scenarios)
            self._scenarios.append(scenario)
            self._index[scenario] = idx
        return _SCENARIO_MAGIC + struct.pack(">I", idx)

    def lookup(self, token: bytes) -> Scenario:
        """Decode a token back into the registered scenario."""
        if not is_scenario_token(token):
            raise ValueError("Not a scenario token")
        (idx,) = struct.unpack(">I", token[len(_SCENARIO_MAGIC) :])
        try:
            return self._scenarios[idx]
        except IndexError:
            raise ValueError(f"Unknown scenario id {idx}") from None

    def reset(self) -> None:
        """Drop all registered scenarios. Useful for tests / repeated runs."""
        self._scenarios.clear()
        self._index.clear()


# Process-wide registry shared by definitions (writers) and the connection (reader).
SCENARIOS = ScenarioRegistry()


def is_scenario_token(data: bytes) -> bool:
    """True if ``data`` is a fixed-width scenario token."""
    return len(data) == _SCENARIO_TOKEN_LEN and data.startswith(_SCENARIO_MAGIC)
