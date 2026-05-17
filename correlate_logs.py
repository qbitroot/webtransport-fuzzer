#!/usr/bin/env python3
"""
correlate_logs.py — correlate a WTFUZZ server log with a fuzzer run database.

The fuzzer opens exactly one WebTransport session per test case. Inside
that session it executes the test-case payload (capsule send or scenario
steps) and an in-session bidi echo probe; both share the same conn_idx.

This script groups the log into sessions by conn_idx, pairs them 1:1 with
``test_cases`` rows by insertion order, and fills in ``log_group_id``.

Usage:
    python correlate_logs.py --log server.log --db boofuzz-results/run_XYZ.db

Pairing rule:
    conn_idx 0 ↔ test_cases.id 1
    conn_idx 1 ↔ test_cases.id 2
    ...
"""

import argparse
import logging
import sys
import time

from src.log_db import LogDB, WTFUZZ_PREFIX

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)5s] %(name)s: %(message)s",
)
logger = logging.getLogger("correlate_logs")


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------


def parse_sessions(log_path: str) -> list[dict]:
    """
    Parse a WTFUZZ log file into an ordered list of sessions.

    Each session is a dict:
        conn_idx  : int     — the connection index from the log
        lines     : list[str] — all log lines belonging to this session
                               (WTFUZZ lines with conn_idx stripped to
                               WTFUZZ|EVENT|... format, plus raw lines)
        has_open  : bool    — SESSION_OPEN was seen
        has_close : bool    — SESSION_CLOSE was seen

    Sessions are ordered by the conn_idx of their first line.
    Raw non-WTFUZZ lines (panics, tracebacks) are attached to the most
    recently opened session, or to a special session with conn_idx=-1 if
    they appear before any WTFUZZ line.
    """
    sessions: dict[int, dict] = {}  # conn_idx -> session dict
    order: list[int] = []  # conn_idx insertion order
    current_conn_idx: int = -1  # tracks where to attach raw lines

    # Session for lines that appear before any WTFUZZ session
    pre_session: list[str] = []

    with open(log_path, "r", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")

            if not line.startswith(WTFUZZ_PREFIX):
                # Raw line (panic, traceback, etc.) — attach to current session
                if current_conn_idx >= 0 and current_conn_idx in sessions:
                    sessions[current_conn_idx]["lines"].append(line)
                else:
                    pre_session.append(line)
                continue

            # WTFUZZ|<conn_idx>|EVENT|...
            parts = line.split("|")
            if len(parts) < 3:
                # Malformed — attach as raw
                if current_conn_idx >= 0 and current_conn_idx in sessions:
                    sessions[current_conn_idx]["lines"].append(line)
                else:
                    pre_session.append(line)
                continue

            try:
                conn_idx = int(parts[1])
            except ValueError:
                # conn_idx field isn't an integer — old-format line without conn_idx?
                if current_conn_idx >= 0 and current_conn_idx in sessions:
                    sessions[current_conn_idx]["lines"].append(line)
                else:
                    pre_session.append(line)
                continue

            # Strip conn_idx: WTFUZZ|<conn_idx>|EVENT|... -> WTFUZZ|EVENT|...
            stripped = WTFUZZ_PREFIX + "|".join(parts[2:])
            event = parts[2] if len(parts) > 2 else ""

            if conn_idx not in sessions:
                sessions[conn_idx] = {
                    "conn_idx": conn_idx,
                    "lines": [],
                    "has_open": False,
                    "has_close": False,
                }
                order.append(conn_idx)

            sessions[conn_idx]["lines"].append(stripped)

            if event == "SESSION_OPEN":
                sessions[conn_idx]["has_open"] = True
                current_conn_idx = conn_idx
            elif event == "SESSION_CLOSE":
                sessions[conn_idx]["has_close"] = True

    # Build the ordered list; prepend any pre-session raw lines to the first session
    ordered = [sessions[idx] for idx in sorted(order)]

    if pre_session and ordered:
        ordered[0]["lines"] = pre_session + ordered[0]["lines"]
    elif pre_session:
        logger.warning(
            "%d raw lines appeared before any WTFUZZ session and will be discarded.",
            len(pre_session),
        )

    return ordered


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Correlate a WTFUZZ server log with a fuzzer run database."
    )
    parser.add_argument("--log", required=True, help="Path to the server log file")
    parser.add_argument("--db", required=True, help="Path to the SQLite run database")
    args = parser.parse_args()

    # ---- Parse server log ----
    logger.info("Parsing server log: %s", args.log)
    try:
        sessions = parse_sessions(args.log)
    except FileNotFoundError:
        logger.error("Log file not found: %s", args.log)
        sys.exit(1)

    logger.info("Found %d sessions in log.", len(sessions))

    missing_open = sum(1 for s in sessions if not s["has_open"])
    missing_close = sum(1 for s in sessions if not s["has_close"])
    if missing_open:
        logger.warning("%d session(s) missing SESSION_OPEN.", missing_open)
    if missing_close:
        logger.warning("%d session(s) missing SESSION_CLOSE.", missing_close)

    # ---- Open DB ----
    logger.info("Opening database: %s", args.db)
    db = LogDB(args.db)

    fuzz_cases = db.get_test_cases()
    logger.info("Found %d fuzz test case(s) in database.", len(fuzz_cases))

    # ---- Pair 1:1 by insertion order ----
    # The fuzzer opens exactly one WebTransport session per test case
    # (the in-session bidi health probe shares that session, see
    # ``EchoCompareMonitor``), so sessions[i] ↔ fuzz_cases[i].

    matched = 0
    unmatched = 0
    for case_num, tc in enumerate(fuzz_cases):
        if case_num >= len(sessions):
            logger.warning(
                "test_cases.id=%d: no corresponding session in log (log may be truncated).",
                tc["id"],
            )
            unmatched += 1
            continue
        log_group_id = db._get_or_create_log_group(sessions[case_num]["lines"])
        db.set_log_group(tc["id"], log_group_id)
        matched += 1

    if len(sessions) > len(fuzz_cases):
        extra = len(sessions) - len(fuzz_cases)
        logger.warning(
            "%d extra session(s) in log beyond the %d test case(s) — "
            "was the server reused across runs?",
            extra,
            len(fuzz_cases),
        )

    db.close()

    print()
    print("=== correlate_logs summary ===")
    print(f"  Fuzz test cases in DB : {len(fuzz_cases)}")
    print(f"  Sessions in log       : {len(sessions)}")
    print(f"  Matched               : {matched}")
    print(f"  Unmatched (truncated) : {unmatched}")
    print(f"  Sessions missing OPEN : {missing_open}")
    print(f"  Sessions missing CLOSE: {missing_close}")
    print()


if __name__ == "__main__":
    main()
