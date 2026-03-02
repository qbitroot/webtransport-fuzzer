#!/usr/bin/env python3
"""
analyze_logs.py — correlate a server WTFUZZ log file with a fuzzer run database.

The server emits one WTFUZZ session per connection. The fuzzer sends one
connection per test case, optionally followed by a health-check connection.
This script groups the log into sessions by conn_idx, pairs them with
test_cases rows by insertion order (test_cases.id), fills in log_group_id
for fuzz rows, and inserts health-check rows.

Usage:
    python analyze_logs.py --log server.log --db boofuzz-results/run_XYZ.db
    python analyze_logs.py --log server.log --db run.db --no-healthcheck

Pairing rule (default, health-check enabled):
    server conn_idx 0 → fuzz   for test_cases.id 1
    server conn_idx 1 → health-check row inserted after id 1
    server conn_idx 2 → fuzz   for test_cases.id 2
    server conn_idx 3 → health-check row inserted after id 2
    ...

With --no-healthcheck:
    server conn_idx 0 → fuzz for test_cases.id 1
    server conn_idx 1 → fuzz for test_cases.id 2
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
logger = logging.getLogger("analyze_logs")


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
    parser.add_argument(
        "--no-healthcheck",
        action="store_true",
        help="Log was captured without health-check probes (1 session per fuzz request)",
    )
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

    # ---- Load existing fuzz test case rows ----
    test_cases = db.get_test_cases()
    fuzz_cases = [tc for tc in test_cases if not tc["is_healthcheck"]]
    logger.info("Found %d fuzz test case(s) in database.", len(fuzz_cases))

    # ---- Pair sessions to test cases ----
    # sessions list is ordered by conn_idx.
    # With healthcheck: even positions (0, 2, 4, ...) = fuzz; odd = healthcheck.
    # Without healthcheck: every position = fuzz.

    sessions_per_case = 1 if args.no_healthcheck else 2

    matched = 0
    inserted_hc = 0
    unmatched_sessions = 0

    for case_num, tc in enumerate(fuzz_cases):
        base = case_num * sessions_per_case

        # Fuzz session
        if base >= len(sessions):
            logger.warning(
                "test_cases.id=%d: no corresponding fuzz session in log (log may be truncated).",
                tc["id"],
            )
            unmatched_sessions += 1
            continue

        fuzz_session = sessions[base]
        log_group_id = db._get_or_create_log_group(fuzz_session["lines"])
        db.set_log_group(tc["id"], log_group_id)
        matched += 1

        # Health-check session
        if not args.no_healthcheck:
            hc_base = base + 1
            if hc_base < len(sessions):
                hc_session = sessions[hc_base]
                hc_log_group_id = db._get_or_create_log_group(hc_session["lines"])
                db.record_test_case(
                    index=tc["test_index"],
                    sent_writes=[],
                    is_healthcheck=True,
                    lines=hc_session["lines"],
                )
                inserted_hc += 1
            else:
                logger.warning(
                    "test_cases.id=%d: no health-check session in log.",
                    tc["id"],
                )

    # Warn about leftover sessions beyond what test cases account for
    expected_sessions = len(fuzz_cases) * sessions_per_case
    if len(sessions) > expected_sessions:
        extra = len(sessions) - expected_sessions
        logger.warning(
            "%d extra session(s) in log beyond the %d test case(s) — "
            "was the server reused across runs?",
            extra,
            len(fuzz_cases),
        )

    db.close()

    print()
    print("=== analyze_logs summary ===")
    print(f"  Fuzz test cases in DB : {len(fuzz_cases)}")
    print(f"  Sessions in log       : {len(sessions)}")
    print(f"  Matched               : {matched}")
    print(f"  Health-check rows ins.: {inserted_hc}")
    print(f"  Unmatched (truncated) : {unmatched_sessions}")
    print(f"  Sessions missing OPEN : {missing_open}")
    print(f"  Sessions missing CLOSE: {missing_close}")
    print()


if __name__ == "__main__":
    main()
