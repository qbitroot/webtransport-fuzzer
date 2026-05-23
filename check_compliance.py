#!/usr/bin/env python3
"""
check_compliance.py — evaluate recorded test-case scenarios against
WebTransport over HTTP/3 protocol compliance rules.

Reads test cases from a fuzzer SQLite database (produced by log_db.py and
optionally correlated by correlate_logs.py), checks server responses for
compliance violations, and reports problems grouped by log_group.

Usage:
    uv run python check_compliance.py --db logs/<stem>.db
    uv run python check_compliance.py --db run.db --draft 03
    uv run python check_compliance.py --db run.db --draft both
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
# ---------------------------------------------------------------------------

CLOSE_SESSION_TYPE_HEX = "6843"
DRAIN_SESSION_TYPE_HEX = "800078ae"

MAX_DATA_TYPE_HEX = "990b4d3d"
MAX_STREAMS_BIDI_TYPE_HEX = "990b4d3f"
MAX_STREAMS_UNI_TYPE_HEX = "990b4d40"
DATA_BLOCKED_TYPE_HEX = "990b4d41"
STREAMS_BLOCKED_BIDI_TYPE_HEX = "990b4d43"
STREAMS_BLOCKED_UNI_TYPE_HEX = "990b4d44"

MAX_STREAM_DATA_TYPE_HEX = "990b4d3e"
STREAM_DATA_BLOCKED_TYPE_HEX = "990b4d42"

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
    if not sent_data:
        return []
    return [s for s in sent_data.splitlines() if s.strip()]


def step_action(step: str) -> str:
    m = re.match(r"^(\w+)\(", step)
    return m.group(1) if m else "unknown"


def step_hex(step: str) -> str:
    m = re.match(r"^\w+\(([0-9a-fA-F]*)\)", step)
    return m.group(1).lower() if m else ""


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
    if not raw_text:
        return False
    for line in raw_text.splitlines():
        if line.startswith(WTFUZZ_PREFIX) and f"|{event}|" in line:
            return True
        if line == f"{WTFUZZ_PREFIX}{event}":
            return True
    return False


def log_has_raw_output(raw_text: Optional[str]) -> bool:
    if not raw_text:
        return False
    for line in raw_text.splitlines():
        if line.strip() and not line.startswith(WTFUZZ_PREFIX):
            return True
    return False


def log_has_server_ready(raw_text: Optional[str]) -> bool:
    """True if this log group contains SERVER_READY (i.e. it is log_group 1,
    the first captured session which has server startup output prepended)."""
    return log_has_event(raw_text, "SERVER_READY")


def server_crashed(raw_text: Optional[str]) -> bool:
    return log_has_raw_output(raw_text)


def session_closed_cleanly(raw_text: Optional[str]) -> bool:
    return log_has_event(raw_text, "SESSION_CLOSE")


def log_extract_field(line: str, field: str) -> Optional[str]:
    for part in line.split("|"):
        if part.startswith(f"{field}="):
            return part[len(field) + 1 :]
    return None


def log_collect_stream_ids(raw_text: Optional[str], event: str) -> list[int]:
    ids: list[int] = []
    if not raw_text:
        return ids
    for line in raw_text.splitlines():
        if not line.startswith(WTFUZZ_PREFIX):
            continue
        parts = line.split("|")
        if len(parts) >= 2 and parts[1] == event:
            val = log_extract_field(line, "stream_id")
            if val is not None:
                try:
                    ids.append(int(val))
                except ValueError:
                    pass
    return ids


# ---------------------------------------------------------------------------
# Compliance result types
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    rule: str
    description: str
    draft: str
    severity: str  # "error" | "warning"


@dataclass
class ComplianceResult:
    test_case_id: int
    log_group_id: Optional[int]
    draft: str
    steps: list[str]
    violations: list[Violation] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(v.severity == "error" for v in self.violations):
            return "VIOLATION"
        if any(v.severity == "warning" for v in self.violations):
            return "WARNING"
        return "OK"


# ---------------------------------------------------------------------------
# Stream ID checker (shared)
# ---------------------------------------------------------------------------


def _check_stream_ids(
    raw_text: Optional[str],
    result: ComplianceResult,
    draft: str,
) -> None:
    """
    Check RECV_BIDI / RECV_UNI events for invalid stream IDs.

    RFC 9000 §2.1 — stream ID type bits:
        % 4 == 0  client-initiated bidirectional   ← expected for RECV_BIDI
        % 4 == 1  server-initiated bidirectional
        % 4 == 2  client-initiated unidirectional  ← expected for RECV_UNI
        % 4 == 3  server-initiated unidirectional

    Special case — stream_id == 0 (the CONNECT stream / Session ID):
        Satisfies % 4 == 0 but is the HTTP/3 CONNECT stream used as the
        WebTransport session control channel (capsule channel).  The server
        MUST NOT treat it as a WebTransport data stream.  Logging
        RECV_BIDI|stream_id=0 means the server misclassified capsule data
        arriving on the CONNECT stream as application bidi stream data.
    """
    bidi_ids = log_collect_stream_ids(raw_text, "RECV_BIDI")
    uni_ids = log_collect_stream_ids(raw_text, "RECV_UNI")

    for sid in bidi_ids:
        if sid == 0:
            result.violations.append(
                Violation(
                    rule=f"{draft}-CONNECT-STREAM-AS-BIDI",
                    description=(
                        "RECV_BIDI stream_id=0: server treated the HTTP/3 CONNECT stream "
                        "(Session ID / capsule channel) as a WebTransport bidi data stream "
                        "(draft-ietf-webtrans-http3 §2.2)."
                    ),
                    draft="both",
                    severity="error",
                )
            )
        elif sid % 4 != 0:
            result.violations.append(
                Violation(
                    rule=f"{draft}-STREAM-ID-BIDI",
                    description=(
                        f"RECV_BIDI stream_id={sid} (% 4 = {sid % 4}): "
                        "client-initiated bidi streams must have IDs ≡ 0 (mod 4) "
                        "(RFC 9000 §2.1)."
                    ),
                    draft="both",
                    severity="warning",
                )
            )

    for sid in uni_ids:
        if sid % 4 != 2:
            result.violations.append(
                Violation(
                    rule=f"{draft}-STREAM-ID-UNI",
                    description=(
                        f"RECV_UNI stream_id={sid} (% 4 = {sid % 4}): "
                        "client-initiated uni streams must have IDs ≡ 2 (mod 4) "
                        "(RFC 9000 §2.1)."
                    ),
                    draft="both",
                    severity="warning",
                )
            )


# ---------------------------------------------------------------------------
# Compliance checkers
# ---------------------------------------------------------------------------


def _find_close_index(steps: list[str]) -> int:
    for i, step in enumerate(steps):
        if step_action(step) == "capsule" and is_close_capsule(step_hex(step)):
            return i
    return -1


def check_draft03_compliance(
    tc_id: int,
    log_group_id: Optional[int],
    steps: list[str],
    raw_text: Optional[str],
) -> ComplianceResult:
    result = ComplianceResult(
        test_case_id=tc_id, log_group_id=log_group_id, draft="03", steps=steps
    )

    if not steps or raw_text is None:
        return result

    is_startup_log = log_has_server_ready(raw_text)
    close_idx = _find_close_index(steps)

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
    prohibited = [
        s
        for s in steps
        if step_action(s) == "capsule" and is_prohibited_capsule(step_hex(s))
    ]

    if server_crashed(raw_text):
        severity = "warning" if is_startup_log else "error"
        desc = "Server emitted non-WTFUZZ output (panic / traceback)."
        if is_startup_log:
            desc += (
                " [only log_group 1: may be startup noise, not crash from this input]"
            )
        result.violations.append(
            Violation(
                rule="03-SERVER-CRASH",
                description=desc,
                draft="both",
                severity=severity,
            )
        )

    if (fc_capsules or drain_capsules or prohibited) and server_crashed(raw_text):
        severity = "warning" if is_startup_log else "error"
        result.violations.append(
            Violation(
                rule="03-UNKNOWN-CAPS-CRASH",
                description="Server crashed after receiving capsule types unknown to draft-03 (RFC 9297: must silently ignore).",
                draft="03",
                severity=severity,
            )
        )

    if close_idx >= 0 and close_idx < len(steps) - 1:
        post_actions = [step_action(s) for s in steps[close_idx + 1 :]]
        if any(a in ("bidi", "uni", "datagram", "capsule") for a in post_actions):
            if not session_closed_cleanly(raw_text) and not server_crashed(raw_text):
                result.violations.append(
                    Violation(
                        rule="03-POST-CLOSE-NO-TERMINATION",
                        description="Data sent after CLOSE_SESSION but no SESSION_CLOSE and no crash (draft-03 §5: must reset with H3_MESSAGE_ERROR).",
                        draft="03",
                        severity="warning",
                    )
                )

    _check_stream_ids(raw_text, result, draft="03")
    return result


def check_draft15_compliance(
    tc_id: int,
    log_group_id: Optional[int],
    steps: list[str],
    raw_text: Optional[str],
) -> ComplianceResult:
    result = ComplianceResult(
        test_case_id=tc_id, log_group_id=log_group_id, draft="15", steps=steps
    )

    if not steps or raw_text is None:
        return result

    is_startup_log = log_has_server_ready(raw_text)
    close_idx = _find_close_index(steps)

    # Prohibited capsules
    prohibited_steps = [
        (i, s)
        for i, s in enumerate(steps)
        if step_action(s) == "capsule" and is_prohibited_capsule(step_hex(s))
    ]
    if prohibited_steps:
        pnames = [
            "WT_MAX_STREAM_DATA"
            if step_hex(s)[:8] == MAX_STREAM_DATA_TYPE_HEX
            else "WT_STREAM_DATA_BLOCKED"
            for _, s in prohibited_steps
        ]
        if not server_crashed(raw_text) and not session_closed_cleanly(raw_text):
            result.violations.append(
                Violation(
                    rule="15-PROHIBITED-NO-SESSION-ERROR",
                    description=(
                        f"Sent {', '.join(pnames)} but server shows no SESSION_CLOSE and no crash. "
                        "Draft-15 §5.4: receipt must be treated as a session error."
                        + (" [only log_group 1]" if is_startup_log else "")
                    ),
                    draft="15",
                    severity="warning" if is_startup_log else "error",
                )
            )

    # Post-close
    if close_idx >= 0 and close_idx < len(steps) - 1:
        post_actions = [step_action(s) for s in steps[close_idx + 1 :]]
        if any(a in ("bidi", "uni", "datagram", "capsule") for a in post_actions):
            if not session_closed_cleanly(raw_text) and not server_crashed(raw_text):
                result.violations.append(
                    Violation(
                        rule="15-POST-CLOSE-NO-TERMINATION",
                        description="Data/capsule sent after CLOSE_SESSION but no SESSION_CLOSE and no crash (draft-15 §6: stream must be reset or closed).",
                        draft="15",
                        severity="warning",
                    )
                )

    # Server crash
    if server_crashed(raw_text):
        severity = "warning" if is_startup_log else "error"
        desc = "Server emitted non-WTFUZZ output (panic / traceback)."
        if is_startup_log:
            desc += (
                " [only log_group 1: may be startup noise, not crash from this input]"
            )
        result.violations.append(
            Violation(
                rule="15-SERVER-CRASH",
                description=desc,
                draft="both",
                severity=severity,
            )
        )

    _check_stream_ids(raw_text, result, draft="15")
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
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Check fuzzer test cases against WebTransport compliance rules."
    )
    parser.add_argument(
        "--db", required=True, help="Path to the SQLite fuzzer run database."
    )
    parser.add_argument(
        "--draft",
        choices=["03", "15", "both"],
        default="15",
        help="Draft version to check against (default: 15).",
    )
    args = parser.parse_args()

    conn = open_db(args.db)
    rows = load_test_cases(conn)
    conn.close()

    drafts_to_check = ["03", "15"] if args.draft == "both" else [args.draft]
    checker_map = {"03": check_draft03_compliance, "15": check_draft15_compliance}

    # Run all checks, collecting results keyed by (log_group_id, draft)
    # log_group_id=None means no log correlated — skip from grouped output.
    all_results: list[ComplianceResult] = []
    total_cases = 0
    no_log_cases = 0

    for row in rows:
        total_cases += 1
        steps = parse_steps(row["sent_data"])
        raw_text = row["raw_text"]
        lg_id = row["log_group_id"]

        if raw_text is None:
            no_log_cases += 1

        for draft in drafts_to_check:
            result = checker_map[draft](
                tc_id=row["id"],
                log_group_id=lg_id,
                steps=steps,
                raw_text=raw_text,
            )
            all_results.append(result)

    # Group problematic results by log_group_id
    # Key: (log_group_id, draft) → list of ComplianceResult with violations
    # We want to report per log_group: which rules fired, how many test cases
    @dataclass
    class LGSummary:
        log_group_id: Optional[int]
        draft: str
        is_startup: bool
        rule_to_cases: dict = field(default_factory=lambda: defaultdict(list))
        # rule -> list of (tc_id, severity, description)

    lg_summaries: dict[tuple, LGSummary] = {}

    for result in all_results:
        if not result.violations:
            continue
        key = (result.log_group_id, result.draft)
        if key not in lg_summaries:
            # Determine if startup log from any violation hint or re-check
            is_startup = any(
                "[only log_group 1" in v.description for v in result.violations
            )
            lg_summaries[key] = LGSummary(
                log_group_id=result.log_group_id,
                draft=result.draft,
                is_startup=is_startup,
            )
        summary = lg_summaries[key]
        for v in result.violations:
            summary.rule_to_cases[v.rule].append(
                (result.test_case_id, v.severity, v.description)
            )

    # Print report
    print(
        f"Checked {total_cases} test case(s)  |  draft-{args.draft}  |  no-log: {no_log_cases}"
    )

    if not lg_summaries:
        print("No violations found.")
        return

    print()

    # Sort: log_group_id=None last, then by log_group_id, then draft
    def sort_key(item):
        (lg_id, draft), _ = item
        return (0 if lg_id is None else 1, lg_id or 0, draft)

    for (lg_id, draft), summary in sorted(lg_summaries.items(), key=sort_key):
        lg_label = f"log_group {lg_id}" if lg_id is not None else "no log_group"
        startup_note = (
            "  [only log_group 1 — startup log]" if summary.is_startup else ""
        )
        # Total unique affected test cases across all rules in this group
        all_tc_ids = set(
            tc_id for cases in summary.rule_to_cases.values() for tc_id, _, _ in cases
        )
        print(f"  {lg_label}  draft-{draft}  {len(all_tc_ids)} case(s){startup_note}")
        for rule, cases in sorted(summary.rule_to_cases.items()):
            severity = cases[0][1]
            description = cases[0][2]
            sev_tag = "[ERR] " if severity == "error" else "[WARN]"
            print(f"    {sev_tag} {rule}  ({len(cases)} case(s))")
            print(f"           {description}")
        print()

    # Totals
    total_violations = sum(
        1 for r in all_results if any(v.severity == "error" for v in r.violations)
    )
    total_warnings = sum(1 for r in all_results if r.verdict == "WARNING")
    affected_groups = len(lg_summaries)
    print(f"log_groups with issues : {affected_groups}")
    print(f"cases with violations  : {total_violations}")
    print(f"cases with warnings    : {total_warnings}")


if __name__ == "__main__":
    main()
