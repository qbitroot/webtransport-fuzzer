#!/usr/bin/env python3
"""
check_compliance.py — evaluate recorded test-case scenarios against
WebTransport over HTTP/3 protocol compliance rules.

Reads test cases from a fuzzer SQLite database (produced by log_db.py and
optionally correlated by analyze_logs.py), reconstructs the step sequence
for each test case, and checks whether the *sending* behaviour conforms to
the relevant draft.  It also checks whether the *server response* (when a
log group is present) is consistent with the expected server behaviour.

Supported draft versions:
  --draft 03   draft-ietf-webtrans-http3-03  (GEN1 / aioquic server)
  --draft 15   draft-ietf-webtrans-http3-15  (GEN4 / latest)

Usage:
    uv run python check_compliance.py --db boofuzz-results/run_<ts>.db --draft 15
    uv run python check_compliance.py --db run.db --draft 03 --verbose
    uv run python check_compliance.py --db run.db --draft 15 --show-only violations
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Capsule type constants (hex, lowercase, no 0x prefix)
# These match the VarInt-encoded bytes stored in the DB step hex strings.
# ---------------------------------------------------------------------------

# 2-byte VarInt for 0x2843
CLOSE_SESSION_TYPE_HEX = "6843"

# 4-byte VarInt for 0x78AE
DRAIN_SESSION_TYPE_HEX = "800078ae"

# 4-byte VarInt prefixes for flow-control capsules (0x190B4D**)
MAX_DATA_TYPE_HEX = "990b4d3d"
MAX_STREAMS_BIDI_TYPE_HEX = "990b4d3f"
MAX_STREAMS_UNI_TYPE_HEX = "990b4d40"
DATA_BLOCKED_TYPE_HEX = "990b4d41"
STREAMS_BLOCKED_BIDI_TYPE_HEX = "990b4d43"
STREAMS_BLOCKED_UNI_TYPE_HEX = "990b4d44"

# Prohibited in draft-15 §5.4
MAX_STREAM_DATA_TYPE_HEX = "990b4d3e"  # WT_MAX_STREAM_DATA (0x190B4D3E)
STREAM_DATA_BLOCKED_TYPE_HEX = "990b4d42"  # WT_STREAM_DATA_BLOCKED (0x190B4D42)

DRAFT15_FLOW_CONTROL_TYPES = {
    MAX_DATA_TYPE_HEX,
    MAX_STREAMS_BIDI_TYPE_HEX,
    MAX_STREAMS_UNI_TYPE_HEX,
    DATA_BLOCKED_TYPE_HEX,
    STREAMS_BLOCKED_BIDI_TYPE_HEX,
    STREAMS_BLOCKED_UNI_TYPE_HEX,
}

DRAFT15_PROHIBITED_TYPES = {
    MAX_STREAM_DATA_TYPE_HEX,
    STREAM_DATA_BLOCKED_TYPE_HEX,
}

WTFUZZ_PREFIX = "WTFUZZ|"


# ---------------------------------------------------------------------------
# Step parsing
# ---------------------------------------------------------------------------


def parse_steps(sent_data: Optional[str]) -> list[str]:
    """Split stored sent_data into individual step strings."""
    if not sent_data:
        return []
    return [s for s in sent_data.splitlines() if s.strip()]


def step_action(step: str) -> str:
    """Extract action name from 'action(hex)' string."""
    m = re.match(r"^(\w+)\(", step)
    return m.group(1) if m else "unknown"


def step_hex(step: str) -> str:
    """Extract hex payload (lowercase) from 'action(hex)' string."""
    m = re.match(r"^\w+\(([0-9a-fA-F]*)\)", step)
    return m.group(1).lower() if m else ""


def capsule_type_hex(capsule_hex: str) -> str:
    """
    Return the leading VarInt type bytes of a raw capsule hex string.

    We check for the known 4-byte and 2-byte prefixes.  For everything
    else we return the first 2 hex chars (1 byte), which covers 1-byte
    VarInt types (values 0–63).
    """
    if len(capsule_hex) >= 8:
        prefix4 = capsule_hex[:8]
        if prefix4 in DRAFT15_FLOW_CONTROL_TYPES | DRAFT15_PROHIBITED_TYPES:
            return prefix4
    if len(capsule_hex) >= 8 and capsule_hex[:8] == DRAIN_SESSION_TYPE_HEX:
        return DRAIN_SESSION_TYPE_HEX
    if len(capsule_hex) >= 4 and capsule_hex[:4] == CLOSE_SESSION_TYPE_HEX:
        return CLOSE_SESSION_TYPE_HEX
    # fall back: first 2 hex chars
    return capsule_hex[:2] if len(capsule_hex) >= 2 else capsule_hex


def is_close_capsule(capsule_hex: str) -> bool:
    return capsule_hex.startswith(CLOSE_SESSION_TYPE_HEX)


def is_drain_capsule(capsule_hex: str) -> bool:
    return capsule_hex.startswith(DRAIN_SESSION_TYPE_HEX)


def is_flow_control_capsule(capsule_hex: str) -> bool:
    t = capsule_hex[:8] if len(capsule_hex) >= 8 else capsule_hex
    return t in DRAFT15_FLOW_CONTROL_TYPES


def is_prohibited_capsule(capsule_hex: str) -> bool:
    t = capsule_hex[:8] if len(capsule_hex) >= 8 else capsule_hex
    return t in DRAFT15_PROHIBITED_TYPES


# ---------------------------------------------------------------------------
# Server log helpers
# ---------------------------------------------------------------------------


def log_has_event(raw_text: Optional[str], event: str) -> bool:
    """Return True if the log group contains a given WTFUZZ event."""
    if not raw_text:
        return False
    for line in raw_text.splitlines():
        if line.startswith(WTFUZZ_PREFIX) and f"|{event}|" in line:
            return True
        if line == f"{WTFUZZ_PREFIX}{event}":
            return True
    return False


def log_has_raw_output(raw_text: Optional[str]) -> bool:
    """True if the log group contains non-WTFUZZ lines (panics, tracebacks)."""
    if not raw_text:
        return False
    for line in raw_text.splitlines():
        if line.strip() and not line.startswith(WTFUZZ_PREFIX):
            return True
    return False


def server_crashed(raw_text: Optional[str]) -> bool:
    """Heuristic: server crash if non-WTFUZZ lines present or SESSION_CLOSE missing."""
    return log_has_raw_output(raw_text)


def session_closed_cleanly(raw_text: Optional[str]) -> bool:
    return log_has_event(raw_text, "SESSION_CLOSE")


# ---------------------------------------------------------------------------
# Compliance verdict
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    rule: str  # short rule ID / name
    description: str  # human-readable description
    draft: str  # "03", "15", or "both"
    severity: str  # "error" | "warning" | "info"


@dataclass
class ComplianceResult:
    test_case_id: int
    test_index: Optional[int]
    draft: str
    steps: list[str]
    violations: list[Violation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def verdict(self) -> str:
        errors = [v for v in self.violations if v.severity == "error"]
        warns = [v for v in self.violations if v.severity == "warning"]
        if errors:
            return "VIOLATION"
        if warns:
            return "WARNING"
        return "OK"


# ---------------------------------------------------------------------------
# Compliance checkers
# ---------------------------------------------------------------------------


def _find_close_index(steps: list[str]) -> int:
    """Return the index of the first CLOSE capsule step, or -1."""
    for i, step in enumerate(steps):
        if step_action(step) == "capsule" and is_close_capsule(step_hex(step)):
            return i
    return -1


def check_draft03_compliance(
    tc_id: int,
    tc_index: Optional[int],
    steps: list[str],
    raw_text: Optional[str],
) -> ComplianceResult:
    """
    Evaluate a scenario against draft-ietf-webtrans-http3-03 rules.

    Key rules checked:
    - §5 Session Termination:
        * After CLOSE_WEBTRANSPORT_SESSION, no further data on CONNECT stream.
          Data after CLOSE → MUST be reset with H3_MESSAGE_ERROR.
        * CLOSE MUST be followed by FIN.
        * Scenario sends data (bidi/uni/datagram) after a CLOSE: this is
          testing whether the server correctly handles post-close traffic.
    - §4.1/4.2: Capsule types unknown to draft-03 MUST be silently ignored
        per RFC 9297 (graceful degradation for flow-control capsules).
    - §5: DRAIN_SESSION (0x78AE) does not exist in draft-03. Sending it is
        sending an unknown capsule — server MUST ignore it.
    - Server crash is always a compliance issue regardless of draft version.
    """
    result = ComplianceResult(
        test_case_id=tc_id, test_index=tc_index, draft="03", steps=steps
    )

    if not steps:
        result.notes.append("No steps recorded (health-check or empty).")
        return result

    close_idx = _find_close_index(steps)

    # --- Rule 03-POST-CLOSE ---
    # draft-03 §5: after CLOSE_WEBTRANSPORT_SESSION is sent, sender MUST
    # follow with FIN.  Any additional stream data after CLOSE MUST be
    # reset with H3_MESSAGE_ERROR.
    if close_idx >= 0 and close_idx < len(steps) - 1:
        post_close_steps = steps[close_idx + 1 :]
        post_actions = [step_action(s) for s in post_close_steps]
        result.notes.append(
            f"Post-CLOSE steps present ({len(post_close_steps)} step(s) after CLOSE at index {close_idx})."
        )
        # Sending bidi/uni/datagram or capsule after CLOSE is the fuzzer's
        # intentional probe. The server SHOULD handle this by resetting.
        # From the *sending* perspective this is testing the rule;
        # the test intent is valid — we mark it as expected probe behaviour.
        if any(a in ("bidi", "uni", "datagram") for a in post_actions):
            result.notes.append(
                "PROBE: Sent data after CLOSE (draft-03 §5: server must reset with H3_MESSAGE_ERROR)."
            )
        if any(a == "capsule" for a in post_actions):
            result.notes.append(
                "PROBE: Sent capsule after CLOSE (draft-03 §5: stream must be reset with H3_MESSAGE_ERROR)."
            )

    # --- Rule 03-UNKNOWN-CAPS ---
    # Flow control capsules and DRAIN_SESSION do not exist in draft-03.
    # Per RFC 9297: unknown capsule types MUST be silently ignored.
    # Sending them to a draft-03 server is a valid fuzz probe — the
    # server MUST NOT crash or close the session.
    fc_capsules = [
        s
        for s in steps
        if step_action(s) == "capsule" and is_flow_control_capsule(step_hex(s))
    ]
    drain_capsules = [
        s
        for s in steps
        if step_action(s) == "capsule" and is_drain_capsule(step_hex(s))
    ]

    if fc_capsules:
        result.notes.append(
            f"Contains {len(fc_capsules)} flow-control capsule(s) (draft-15 only). "
            f"Draft-03 server MUST silently ignore these per RFC 9297."
        )

    if drain_capsules:
        result.notes.append(
            f"Contains {len(drain_capsules)} DRAIN_SESSION capsule(s) (unknown in draft-03). "
            f"Draft-03 server MUST silently ignore these per RFC 9297."
        )

    # --- Rule 03-PROHIBITED ---
    # WT_MAX_STREAM_DATA / WT_STREAM_DATA_BLOCKED are prohibited in draft-15
    # but in draft-03 they are just unknown capsules, so MUST be ignored.
    prohibited = [
        s
        for s in steps
        if step_action(s) == "capsule" and is_prohibited_capsule(step_hex(s))
    ]
    if prohibited:
        result.notes.append(
            f"Contains {len(prohibited)} capsule(s) that are prohibited in draft-15 "
            f"(WT_MAX_STREAM_DATA / WT_STREAM_DATA_BLOCKED). "
            f"In draft-03 these are simply unknown and MUST be ignored."
        )

    # --- Server response checks (if log data available) ---
    if raw_text is not None:
        if server_crashed(raw_text):
            result.violations.append(
                Violation(
                    rule="03-SERVER-CRASH",
                    description=(
                        "Server emitted non-WTFUZZ output (panic / traceback). "
                        "A conformant server MUST NOT crash on any valid or unknown capsule input."
                    ),
                    draft="both",
                    severity="error",
                )
            )

        # If flow-control capsules were sent, the server must not crash
        if (fc_capsules or drain_capsules or prohibited) and server_crashed(raw_text):
            result.violations.append(
                Violation(
                    rule="03-UNKNOWN-CAPS-CRASH",
                    description=(
                        "Server crashed after receiving capsule types unknown to draft-03. "
                        "RFC 9297 requires unknown capsule types to be silently ignored."
                    ),
                    draft="03",
                    severity="error",
                )
            )

        # If data was sent after CLOSE, server should still terminate cleanly
        if close_idx >= 0 and close_idx < len(steps) - 1:
            if not session_closed_cleanly(raw_text) and not server_crashed(raw_text):
                result.violations.append(
                    Violation(
                        rule="03-POST-CLOSE-NO-TERMINATION",
                        description=(
                            "Data was sent after CLOSE_SESSION but server log shows no SESSION_CLOSE "
                            "and no crash. The session may be stuck or the post-close data was silently "
                            "absorbed without resetting (draft-03 §5 requires H3_MESSAGE_ERROR reset)."
                        ),
                        draft="03",
                        severity="warning",
                    )
                )
    else:
        result.notes.append("No server log correlated (run analyze_logs.py first).")

    return result


def check_draft15_compliance(
    tc_id: int,
    tc_index: Optional[int],
    steps: list[str],
    raw_text: Optional[str],
) -> ComplianceResult:
    """
    Evaluate a scenario against draft-ietf-webtrans-http3-15 rules.

    Key rules checked:
    - §5.4: WT_MAX_STREAM_DATA and WT_STREAM_DATA_BLOCKED are PROHIBITED.
        Receipt MUST be treated as a session error (i.e. the session should close).
    - §6 Session Termination:
        * After sending WT_CLOSE_SESSION, sender MUST stop reading from CONNECT
          stream and not send further data.
        * Any data received after CLOSE on the CONNECT stream MUST cause the
          stream to be reset with H3_MESSAGE_ERROR.
        * The recipient MUST either close the stream with FIN or reset.
    - §4.7: After WT_DRAIN_SESSION, endpoint MAY continue using the session.
        This means bidi/uni/datagram activity after DRAIN is spec-compliant.
    - §5.1: Flow-control capsules (WT_MAX_DATA, WT_MAX_STREAMS, etc.) are valid.
    - Unknown capsule types: MUST be silently ignored (RFC 9297).
    - Server crash is always a compliance issue.
    """
    result = ComplianceResult(
        test_case_id=tc_id, test_index=tc_index, draft="15", steps=steps
    )

    if not steps:
        result.notes.append("No steps recorded (health-check or empty).")
        return result

    close_idx = _find_close_index(steps)

    # --- Rule 15-PROHIBITED ---
    # draft-15 §5.4: WT_MAX_STREAM_DATA and WT_STREAM_DATA_BLOCKED are
    # explicitly prohibited.  Receipt MUST be treated as a session error.
    prohibited = [
        (i, s)
        for i, s in enumerate(steps)
        if step_action(s) == "capsule" and is_prohibited_capsule(step_hex(s))
    ]
    if prohibited:
        pnames = []
        for _, s in prohibited:
            h = step_hex(s)
            if h[:8] == MAX_STREAM_DATA_TYPE_HEX:
                pnames.append("WT_MAX_STREAM_DATA")
            else:
                pnames.append("WT_STREAM_DATA_BLOCKED")
        result.notes.append(
            f"PROBE: Contains {len(prohibited)} prohibited capsule(s): {', '.join(pnames)}. "
            f"Draft-15 §5.4: server MUST treat receipt as a session error."
        )

        # Check server response: session should be terminated (error)
        if raw_text is not None:
            if not server_crashed(raw_text) and not session_closed_cleanly(raw_text):
                result.violations.append(
                    Violation(
                        rule="15-PROHIBITED-NO-SESSION-ERROR",
                        description=(
                            f"Sent prohibited capsule(s) ({', '.join(pnames)}) but server log shows "
                            f"no SESSION_CLOSE and no crash. Draft-15 §5.4 requires the endpoint "
                            f"to treat receipt as a session error (session MUST be terminated)."
                        ),
                        draft="15",
                        severity="error",
                    )
                )

    # --- Rule 15-POST-CLOSE-DATA ---
    # draft-15 §6: After CLOSE_SESSION is sent, sender MUST stop.
    # Any data received on the CONNECT stream after CLOSE MUST be reset with H3_MESSAGE_ERROR.
    if close_idx >= 0 and close_idx < len(steps) - 1:
        post_close = steps[close_idx + 1 :]
        post_actions = [step_action(s) for s in post_close]
        result.notes.append(
            f"PROBE: {len(post_close)} step(s) sent after CLOSE at index {close_idx}."
        )

        has_data_after_close = any(
            a in ("bidi", "uni", "datagram") for a in post_actions
        )
        has_capsule_after_close = any(a == "capsule" for a in post_actions)

        if has_capsule_after_close:
            result.notes.append(
                "PROBE: Capsule sent after CLOSE_SESSION "
                "(draft-15 §6: stream MUST be reset with H3_MESSAGE_ERROR on receipt)."
            )

        if has_data_after_close:
            result.notes.append(
                "PROBE: Data (bidi/uni/datagram) sent after CLOSE_SESSION "
                "(draft-15 §6: endpoint MUST NOT send new datagrams or open new streams after CLOSE)."
            )

        if raw_text is not None and (has_capsule_after_close or has_data_after_close):
            if not session_closed_cleanly(raw_text) and not server_crashed(raw_text):
                result.violations.append(
                    Violation(
                        rule="15-POST-CLOSE-NO-TERMINATION",
                        description=(
                            "Data/capsule sent after CLOSE_SESSION, but server shows no SESSION_CLOSE "
                            "and no crash. Draft-15 §6 requires the stream to be reset or closed."
                        ),
                        draft="15",
                        severity="warning",
                    )
                )

    # --- Rule 15-DRAIN-CONTINUE ---
    # draft-15 §4.7: After WT_DRAIN_SESSION, endpoints MAY continue using the session.
    # Sending bidi/uni/datagram/capsule after DRAIN is spec-compliant.
    drain_indices = [
        i
        for i, s in enumerate(steps)
        if step_action(s) == "capsule" and is_drain_capsule(step_hex(s))
    ]
    if drain_indices:
        last_drain = max(drain_indices)
        post_drain_data = [
            s
            for s in steps[last_drain + 1 :]
            if step_action(s) in ("bidi", "uni", "datagram", "capsule")
        ]
        if post_drain_data:
            result.notes.append(
                f"Contains {len(post_drain_data)} step(s) after DRAIN_SESSION "
                f"(draft-15 §4.7: continuing after DRAIN is explicitly allowed)."
            )

    # --- Rule 15-FC-VALID ---
    # Flow-control capsules are valid in draft-15.
    fc_capsules = [
        s
        for s in steps
        if step_action(s) == "capsule" and is_flow_control_capsule(step_hex(s))
    ]
    if fc_capsules:
        fc_types = set()
        for s in fc_capsules:
            h = step_hex(s)[:8]
            name = {
                MAX_DATA_TYPE_HEX: "WT_MAX_DATA",
                MAX_STREAMS_BIDI_TYPE_HEX: "WT_MAX_STREAMS(bidi)",
                MAX_STREAMS_UNI_TYPE_HEX: "WT_MAX_STREAMS(uni)",
                DATA_BLOCKED_TYPE_HEX: "WT_DATA_BLOCKED",
                STREAMS_BLOCKED_BIDI_TYPE_HEX: "WT_STREAMS_BLOCKED(bidi)",
                STREAMS_BLOCKED_UNI_TYPE_HEX: "WT_STREAMS_BLOCKED(uni)",
            }.get(h, h)
            fc_types.add(name)
        result.notes.append(
            f"Contains {len(fc_capsules)} valid flow-control capsule(s): {', '.join(sorted(fc_types))}."
        )

    # --- Rule 15-FC-CONTRADICTORY ---
    # WT_MAX_DATA(0) followed by bidi data is a probe of contradictory limits.
    # Draft-15 §5.4: sending data that exceeds WT_MAX_DATA limit → session error.
    # From the fuzzer's perspective, sending MAX_DATA(0) then bidi is checking
    # whether the server enforces or ignores the limit.
    max_data_zero = any(
        step_action(s) == "capsule"
        and step_hex(s).startswith(MAX_DATA_TYPE_HEX)
        and len(step_hex(s)) > 8
        and step_hex(s)[8:10] == "00"
        for s in steps
    )
    if max_data_zero:
        bidi_after = False
        found_maxdata = False
        for s in steps:
            if (
                step_action(s) == "capsule"
                and step_hex(s).startswith(MAX_DATA_TYPE_HEX)
                and len(step_hex(s)) > 8
                and step_hex(s)[8:10] == "00"
            ):
                found_maxdata = True
            if found_maxdata and step_action(s) == "bidi":
                bidi_after = True
                break
        if bidi_after:
            result.notes.append(
                "PROBE: WT_MAX_DATA(0) sent before bidi data. "
                "Draft-15 §5.4: if server enforces this limit, sending bidi data should result in a session error."
            )

    # --- Server response checks ---
    if raw_text is not None:
        if server_crashed(raw_text):
            result.violations.append(
                Violation(
                    rule="15-SERVER-CRASH",
                    description=(
                        "Server emitted non-WTFUZZ output (panic / traceback). "
                        "A conformant server MUST NOT crash on any input."
                    ),
                    draft="both",
                    severity="error",
                )
            )
    else:
        result.notes.append("No server log correlated (run analyze_logs.py first).")

    return result


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def open_db(path: str) -> sqlite3.Connection:
    if not Path(path).exists():
        print(f"[ERROR] Database not found: {path}", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def load_test_cases(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT tc.id, tc.test_index, tc.sent_data, tc.is_healthcheck, "
        "       tc.log_group_id, lg.raw_text "
        "FROM test_cases tc "
        "LEFT JOIN log_groups lg ON tc.log_group_id = lg.id "
        "WHERE tc.is_healthcheck = 0 "
        "ORDER BY tc.id"
    ).fetchall()


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

SEVERITY_SYMBOL = {
    "error": "[VIOLATION]",
    "warning": "[WARNING]  ",
    "info": "[INFO]     ",
}

VERDICT_SYMBOL = {
    "OK": "[OK]      ",
    "WARNING": "[WARNING] ",
    "VIOLATION": "[VIOLATION]",
}


def infer_scenario_label(steps: list[str]) -> str:
    """Return a concise label for the step sequence."""
    actions = [step_action(s) for s in steps]
    counts: dict[str, int] = {}
    for a in actions:
        counts[a] = counts.get(a, 0) + 1
    parts = [f"{a}×{n}" if n > 1 else a for a, n in counts.items()]
    return " → ".join(actions[:6]) + ("…" if len(actions) > 6 else "")


def print_result(result: ComplianceResult, verbose: bool, show_only: str):
    verdict = result.verdict
    show = True
    if show_only == "violations" and verdict not in ("VIOLATION", "WARNING"):
        show = False
    if show_only == "errors" and verdict != "VIOLATION":
        show = False
    if not show:
        return

    label = infer_scenario_label(result.steps)
    log_status = "no-log"
    if result.steps:
        for step in result.steps:
            pass  # just to have the loop; log status is from raw_text
    # Determine log status from violations (server crash note)
    has_log = any(
        "No server log correlated" not in n for n in result.notes if "correlated" in n
    )

    print(
        f"{VERDICT_SYMBOL[verdict]}  tc.id={result.test_case_id:>5}  "
        f"idx={str(result.test_index or '?'):>5}  "
        f"draft-{result.draft}  "
        f"steps={len(result.steps):>2}  "
        f"{label}"
    )

    if verbose or verdict in ("VIOLATION", "WARNING"):
        for v in result.violations:
            print(f"    {SEVERITY_SYMBOL[v.severity]}  [{v.rule}]  {v.description}")
        if verbose:
            for note in result.notes:
                print(f"    [NOTE]       {note}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Check recorded fuzzer test cases against WebTransport "
            "draft-03 or draft-15 compliance rules."
        )
    )
    parser.add_argument(
        "--db", required=True, help="Path to the SQLite fuzzer run database."
    )
    parser.add_argument(
        "--draft",
        choices=["03", "15", "both"],
        default="15",
        help="Which draft version to check compliance against (default: 15).",
    )
    parser.add_argument(
        "--show-only",
        choices=["all", "violations", "errors"],
        default="all",
        help=(
            "Filter output: 'all' shows every test case, "
            "'violations' shows warnings and errors, "
            "'errors' shows only hard violations (default: all)."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show notes for every test case, not just violations.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process the first N test cases (0 = all).",
    )
    args = parser.parse_args()

    conn = open_db(args.db)
    rows = load_test_cases(conn)
    conn.close()

    if args.limit > 0:
        rows = rows[: args.limit]

    drafts_to_check = ["03", "15"] if args.draft == "both" else [args.draft]

    checker_map = {
        "03": check_draft03_compliance,
        "15": check_draft15_compliance,
    }

    all_results: list[ComplianceResult] = []
    for row in rows:
        steps = parse_steps(row["sent_data"])
        raw_text = row["raw_text"]
        for draft in drafts_to_check:
            result = checker_map[draft](
                tc_id=row["id"],
                tc_index=row["test_index"],
                steps=steps,
                raw_text=raw_text,
            )
            all_results.append(result)

    # Print
    print(f"\nChecking {len(rows)} test case(s) against draft-{args.draft} compliance.")
    print(f"{'=' * 80}\n")

    for result in all_results:
        print_result(result, verbose=args.verbose, show_only=args.show_only)

    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")

    by_draft: dict[str, list[ComplianceResult]] = defaultdict(list)
    for r in all_results:
        by_draft[r.draft].append(r)

    for draft, results in sorted(by_draft.items()):
        oks = sum(1 for r in results if r.verdict == "OK")
        warns = sum(1 for r in results if r.verdict == "WARNING")
        errors = sum(1 for r in results if r.verdict == "VIOLATION")
        no_log = sum(
            1 for r in results if any("No server log correlated" in n for n in r.notes)
        )
        print(f"\n  Draft-{draft}:")
        print(f"    Total checked  : {len(results)}")
        print(f"    OK             : {oks}")
        print(f"    Warnings       : {warns}")
        print(f"    Violations     : {errors}")
        print(f"    No log data    : {no_log}")

        # Rule breakdown
        rule_counts: dict[str, int] = defaultdict(int)
        for r in results:
            for v in r.violations:
                rule_counts[v.rule] += 1
        if rule_counts:
            print(f"\n    Rule breakdown:")
            for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
                print(f"      {rule:<40} {count} case(s)")

    # Scenario-level summary: which scenarios have the most violations?
    print(f"\n{'=' * 80}")
    print("SCENARIO PATTERN ANALYSIS")
    print(f"{'=' * 80}")
    print(
        "\n  This groups test cases by step-sequence pattern to show which "
        "mutation types produce the most violations.\n"
    )

    pattern_stats: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "violations": 0, "warnings": 0}
    )

    # Use only one result per tc (if both drafted, deduplicate by mutation type)
    seen_tc_ids: set[int] = set()
    for result in all_results:
        if result.test_case_id in seen_tc_ids:
            continue
        seen_tc_ids.add(result.test_case_id)
        label = _classify_mutation_pattern(result.steps)
        pattern_stats[label]["total"] += 1
        if result.verdict == "VIOLATION":
            pattern_stats[label]["violations"] += 1
        elif result.verdict == "WARNING":
            pattern_stats[label]["warnings"] += 1

    for label, stats in sorted(
        pattern_stats.items(), key=lambda x: -(x[1]["violations"] + x[1]["warnings"])
    ):
        v = stats["violations"]
        w = stats["warnings"]
        t = stats["total"]
        indicator = ""
        if v > 0:
            indicator = f"  <- {v} violation(s)"
        elif w > 0:
            indicator = f"  <- {w} warning(s)"
        print(
            f"  {label:<42}  total={t:>5}  violations={v:>4}  warnings={w:>4}{indicator}"
        )

    print()


def _classify_mutation_pattern(steps: list[str]) -> str:
    """
    Classify the mutation pattern of a step sequence for reporting.
    Mirrors analyze_db.py's classify_mutation but with richer labels.
    """
    if not steps:
        return "empty"

    actions = [step_action(s) for s in steps]
    capsule_hexes = [step_hex(s) for s in steps if step_action(s) == "capsule"]

    # Prohibited capsule injection
    if any(is_prohibited_capsule(h) for h in capsule_hexes):
        return "prohibited_injection (WT_MAX_STREAM_DATA / WT_STREAM_DATA_BLOCKED)"

    # Post-close activity
    close_idx = _find_close_index(steps)
    if close_idx >= 0 and close_idx < len(steps) - 1:
        post = steps[close_idx + 1 :]
        post_a = [step_action(s) for s in post]
        if any(a in ("bidi", "uni", "datagram") for a in post_a):
            return "post_CLOSE_data"
        if any(a == "capsule" for a in post_a):
            return "post_CLOSE_capsule"

    # Drain present
    if any(is_drain_capsule(h) for h in capsule_hexes):
        if any(
            step_action(steps[i + 1]) in ("bidi", "uni", "datagram")
            for i, h in enumerate(capsule_hexes)
            if is_drain_capsule(h) and i + 1 < len(steps)
        ):
            return "drain_then_data"
        return "drain_session"

    # Rapid-fire
    unique_actions = set(actions)
    if len(unique_actions) == 1:
        if len(actions) >= 10:
            return f"rapid_fire_10x_{actions[0]}"
        if len(actions) >= 5:
            return f"rapid_fire_5x_{actions[0]}"
        if len(actions) >= 2:
            return f"duplication_{actions[0]}"

    # Baseline: single or small sequence
    if len(steps) <= 2:
        return "baseline_short_sequence"

    # General permutation/omission
    action_signature = "+".join(sorted(set(actions)))
    return f"permutation_or_omission ({action_signature})"


if __name__ == "__main__":
    main()
