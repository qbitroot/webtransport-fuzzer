#!/usr/bin/env python3
"""
compare_db.py — compare server responses between two fuzzer SQLite databases.

Matches test cases by sent_data (step sequence) and reports mismatches in the
server log response.  Useful for detecting regressions between server versions
or draft implementations: same fuzz input, different server output.

Usage:
    uv run python compare_db.py run_A.db run_B.db

    # Ignore transient key=value fields (stream_id, session_id) — compare
    # only the sequence of WTFUZZ event names:
    uv run python compare_db.py run_A.db run_B.db --strip-extra
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

WTFUZZ_PREFIX = "WTFUZZ|"


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


def load_fuzz_cases(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT tc.id, tc.sent_data, lg.raw_text "
        "FROM test_cases tc "
        "LEFT JOIN log_groups lg ON tc.log_group_id = lg.id "
        "WHERE tc.is_healthcheck = 0 "
        "ORDER BY tc.id"
    ).fetchall()


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def normalise_sent_data(sent_data: Optional[str]) -> str:
    if not sent_data:
        return ""
    return "\n".join(
        line.strip().lower() for line in sent_data.splitlines() if line.strip()
    )


def normalise_raw_text(raw_text: Optional[str], strip_extra: bool) -> str:
    """Return raw_text with optional stripping of key=value fields.

    With strip_extra=True each WTFUZZ line is reduced to just:
        WTFUZZ|<EVENT_NAME>
    so that transient per-run values (stream_id, session_id, bind address)
    don't produce spurious mismatches.  Non-WTFUZZ lines (panics, tracebacks)
    are kept verbatim — they are evidence of crashes and must not be dropped.
    """
    if not raw_text:
        return ""
    lines_out: list[str] = []
    for line in raw_text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if strip_extra and line.startswith(WTFUZZ_PREFIX):
            parts = line.split("|")
            # parts[1] is the event name (conn_idx already stripped by analyze_logs.py)
            event = parts[1] if len(parts) >= 2 else ""
            lines_out.append(f"{WTFUZZ_PREFIX}{event}")
        else:
            lines_out.append(line)
    return "\n".join(lines_out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare server responses between two fuzzer run databases."
    )
    parser.add_argument("db_a", metavar="DB_A", help="First SQLite database.")
    parser.add_argument("db_b", metavar="DB_B", help="Second SQLite database.")
    parser.add_argument(
        "--strip-extra",
        action="store_true",
        help=(
            "Strip key=value fields from WTFUZZ log lines before comparing. "
            "Only event names are retained, ignoring transient values like "
            "stream_id and session_id."
        ),
    )
    args = parser.parse_args()

    conn_a = open_db(args.db_a)
    conn_b = open_db(args.db_b)
    rows_a = load_fuzz_cases(conn_a)
    rows_b = load_fuzz_cases(conn_b)
    conn_a.close()
    conn_b.close()

    # Index by normalised sent_data; keep first representative per unique input
    index_a: dict[str, sqlite3.Row] = {}
    index_b: dict[str, sqlite3.Row] = {}
    for row in rows_a:
        key = normalise_sent_data(row["sent_data"])
        if key not in index_a:
            index_a[key] = row
    for row in rows_b:
        key = normalise_sent_data(row["sent_data"])
        if key not in index_b:
            index_b[key] = row

    shared = sorted(k for k in index_a if k in index_b)

    print(f"DB_A : {args.db_a}  ({len(rows_a)} cases, {len(index_a)} unique inputs)")
    print(f"DB_B : {args.db_b}  ({len(rows_b)} cases, {len(index_b)} unique inputs)")
    print(f"Shared inputs : {len(shared)}")
    print(f"Only in DB_A  : {len(index_a) - len(shared)}")
    print(f"Only in DB_B  : {len(index_b) - len(shared)}")
    print(f"Strip extra   : {'yes' if args.strip_extra else 'no'}")
    print(f"\n{'=' * 72}\n")

    mismatches = 0
    for key in shared:
        row_a = index_a[key]
        row_b = index_b[key]

        norm_a = normalise_raw_text(row_a["raw_text"], args.strip_extra)
        norm_b = normalise_raw_text(row_b["raw_text"], args.strip_extra)

        if norm_a == norm_b:
            continue

        mismatches += 1
        steps = [l for l in key.splitlines() if l]
        step_summary = " → ".join(steps[:5]) + ("…" if len(steps) > 5 else "")
        print(f"[MISMATCH]  A:tc={row_a['id']}  B:tc={row_b['id']}")
        print(f"  sent : {step_summary}")

        # Show event-sequence diff
        def events(text: str) -> list[str]:
            out = []
            for line in text.splitlines():
                if line.startswith(WTFUZZ_PREFIX):
                    parts = line.split("|")
                    if len(parts) >= 2:
                        out.append(parts[1])
            return out

        ea = events(norm_a)
        eb = events(norm_b)
        if ea != eb:
            print(f"  A events : {' → '.join(ea) or '(none)'}")
            print(f"  B events : {' → '.join(eb) or '(none)'}")
        else:
            # Same events, different field values (only reachable without --strip-extra)
            print(f"  events match but field values differ")
            for la, lb in zip(norm_a.splitlines(), norm_b.splitlines()):
                if la != lb:
                    print(f"  A: {la}")
                    print(f"  B: {lb}")
        print()

    print(f"{'=' * 72}")
    print(f"Mismatches : {mismatches} / {len(shared)} matched pairs")
    print()


if __name__ == "__main__":
    main()
