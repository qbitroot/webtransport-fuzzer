"""
Sequence mutation engine for multistep capsule fuzzing.

A scenario is a list of Steps. Each step is an action the fuzzer performs
on a live WebTransport session: send a bidi stream, send a datagram,
inject a capsule, wait briefly, etc.

The mutator takes a scenario and generates all interesting re-orderings:
permutations, duplications, omissions, rapid-fire, and prohibited-capsule
injections — while preserving the action types so the connection knows
how to execute each step.
"""

import itertools
import json
import struct
from typing import List, Tuple, Dict, Any

from src.boofuzz_definitions import encode_quic_varint


# ---- Step types ----
# Each step is a dict: {"action": str, ...params}
#
#   {"action": "bidi",     "data": b"hello"}        — send on bidi stream, await echo
#   {"action": "uni",      "data": b"fire"}          — send on uni stream (fire-and-forget)
#   {"action": "datagram", "data": b"ping"}           — send datagram
#   {"action": "capsule",  "data": b"\x68\x43..."}   — raw capsule bytes on CONNECT stream
#   {"action": "sleep",    "seconds": 0.05}           — pause between steps


def step_bidi(data: bytes) -> dict:
    """Create a bidirectional stream step (sends data, server echoes)."""
    return {"action": "bidi", "data": data}


def step_uni(data: bytes) -> dict:
    """Create a unidirectional stream step (fire-and-forget)."""
    return {"action": "uni", "data": data}


def step_datagram(data: bytes) -> dict:
    """Create a datagram step."""
    return {"action": "datagram", "data": data}


def step_capsule(data: bytes) -> dict:
    """Create a capsule step (raw bytes on CONNECT stream)."""
    return {"action": "capsule", "data": data}


def step_sleep(seconds: float = 0.05) -> dict:
    """Create a sleep/delay step."""
    return {"action": "sleep", "seconds": seconds}


# ---- Prohibited capsule types (draft-15 §5.4) ----
CAPSULE_MAX_STREAM_DATA = b"\x99\x0b\x4d\x3e"  # 0x190B4D3E
CAPSULE_STREAM_DATA_BLOCKED = b"\x99\x0b\x4d\x42"  # 0x190B4D42


def _build_prohibited_capsules() -> List[Tuple[str, bytes]]:
    """Build well-formed but prohibited capsules for injection testing."""
    capsules = []

    # WT_MAX_STREAM_DATA with stream_id=4, limit=999
    payload = encode_quic_varint(4) + encode_quic_varint(999)
    capsule = CAPSULE_MAX_STREAM_DATA + encode_quic_varint(len(payload)) + payload
    capsules.append(("WT_MAX_STREAM_DATA", capsule))

    # WT_STREAM_DATA_BLOCKED with stream_id=4, limit=999
    payload = encode_quic_varint(4) + encode_quic_varint(999)
    capsule = CAPSULE_STREAM_DATA_BLOCKED + encode_quic_varint(len(payload)) + payload
    capsules.append(("WT_STREAM_DATA_BLOCKED", capsule))

    return capsules


PROHIBITED_CAPSULES = _build_prohibited_capsules()

MAX_PERMUTATIONS = 120  # 5! = 120


def _step_key(step: dict) -> bytes:
    """Deterministic key for deduplication."""
    if step["action"] == "sleep":
        return b"sleep:" + str(step["seconds"]).encode()
    return step["action"].encode() + b":" + step.get("data", b"")


def _seq_key(steps: List[dict]) -> bytes:
    """Deduplicate entire sequences."""
    return b"|".join(_step_key(s) for s in steps)


def generate_sequence_mutations(
    scenario: List[dict],
    include_permutations: bool = True,
    include_duplications: bool = True,
    include_omissions: bool = True,
    include_rapid_fire: bool = True,
    include_injections: bool = True,
) -> List[List[dict]]:
    """
    Generate all interesting mutations of a step scenario.

    Args:
        scenario: Ordered list of step dicts.

    Returns:
        List of mutated scenarios. Each is a list of step dicts.
    """
    seen = set()
    mutations: List[List[dict]] = []

    def _add(seq: List[dict]):
        key = _seq_key(seq)
        if key not in seen:
            seen.add(key)
            mutations.append(seq)

    # 0. Original order (baseline)
    _add(scenario[:])

    # 1. All permutations (capped)
    if include_permutations and len(scenario) > 1:
        count = 0
        for perm in itertools.permutations(scenario):
            _add(list(perm))
            count += 1
            if count >= MAX_PERMUTATIONS:
                break

    # 2. Each step duplicated at its position
    if include_duplications:
        for i in range(len(scenario)):
            dup = scenario[:i] + [scenario[i], scenario[i]] + scenario[i + 1 :]
            _add(dup)

    # 3. Each step duplicated at end
    if include_duplications:
        for i in range(len(scenario)):
            _add(scenario[:] + [scenario[i]])

    # 4. Each step omitted
    if include_omissions and len(scenario) > 1:
        for i in range(len(scenario)):
            omit = scenario[:i] + scenario[i + 1 :]
            if omit:
                _add(omit)

    # 5. Rapid-fire: same step repeated N times
    if include_rapid_fire:
        for step in scenario:
            if step["action"] == "sleep":
                continue
            for n in [2, 5, 10]:
                _add([step] * n)

    # 6. Reversed order
    if len(scenario) > 1:
        _add(scenario[::-1])

    # 7. Inject prohibited capsule at each position
    if include_injections:
        for i in range(len(scenario) + 1):
            for _name, prohibited in PROHIBITED_CAPSULES:
                injected = scenario[:i] + [step_capsule(prohibited)] + scenario[i:]
                _add(injected)

    # 8. Post-close injection: if scenario has a capsule that looks like CLOSE,
    #    inject data activity after it
    if include_injections:
        from src.boofuzz_definitions import CAPSULE_CLOSE_SESSION, CAPSULE_DRAIN_SESSION

        for i, s in enumerate(scenario):
            if (
                s["action"] == "capsule"
                and s["data"][: len(CAPSULE_CLOSE_SESSION)] == CAPSULE_CLOSE_SESSION
            ):
                # Send bidi after close — should the server still echo?
                _add(scenario[: i + 1] + [step_bidi(b"AFTERCLOSE")])
                # Send uni after close
                _add(scenario[: i + 1] + [step_uni(b"AFTERCLOSE")])
                # Send datagram after close
                _add(scenario[: i + 1] + [step_datagram(b"AFTERCLOSE")])
                # Send drain after close
                drain_bytes = CAPSULE_DRAIN_SESSION + b"\x00"
                _add(scenario[: i + 1] + [step_capsule(drain_bytes)])
                # Send prohibited after close
                for _name, prohibited in PROHIBITED_CAPSULES:
                    _add(scenario[: i + 1] + [step_capsule(prohibited)])

    return mutations


# ---- Encoding / decoding for boofuzz transport ----
# We encode a scenario (list of step dicts) as JSON inside a binary envelope
# so boofuzz s_group can hold it as bytes, and the connection can decode it.

SCENARIO_MAGIC = b"WTSC"  # WebTransport SCenario


def encode_scenario(steps: List[dict]) -> bytes:
    """Encode a scenario into bytes for boofuzz s_group storage."""
    # Convert bytes fields to hex strings for JSON serialization
    serializable = []
    for step in steps:
        s = dict(step)
        if "data" in s and isinstance(s["data"], bytes):
            s["data"] = s["data"].hex()
        serializable.append(s)
    payload = json.dumps(serializable, separators=(",", ":")).encode("utf-8")
    return SCENARIO_MAGIC + struct.pack(">I", len(payload)) + payload


def decode_scenario(data: bytes) -> List[dict]:
    """Decode a scenario from its binary envelope."""
    if not data.startswith(SCENARIO_MAGIC):
        raise ValueError("Not a scenario-encoded payload")
    offset = len(SCENARIO_MAGIC)
    (length,) = struct.unpack(">I", data[offset : offset + 4])
    offset += 4
    payload = data[offset : offset + length]
    raw = json.loads(payload.decode("utf-8"))
    # Convert hex strings back to bytes
    steps = []
    for s in raw:
        if "data" in s and isinstance(s["data"], str):
            s["data"] = bytes.fromhex(s["data"])
        steps.append(s)
    return steps


def is_scenario_encoded(data: bytes) -> bool:
    """Check if data starts with the scenario magic."""
    return data.startswith(SCENARIO_MAGIC)
