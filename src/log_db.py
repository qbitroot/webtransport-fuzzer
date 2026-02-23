"""
SQLite database for storing server logs correlated with fuzzer test cases.

Normalized model: (request_bytes ↔ response_category).

Log output is deduplicated into `log_groups` — each unique combination of
server output lines is stored once. Multiple test cases that produce the
same output all point to the same log_group_id, making it trivial to
group by failure mode.
"""

import hashlib
import json
import logging
import sqlite3
import time

logger = logging.getLogger(__name__)

# Magic prefix for structured log lines from instrumented servers
WTFUZZ_PREFIX = "WTFUZZ|"


class LogDB:
    """
    SQLite store for fuzzer test cases and their corresponding server logs.

    Schema:
        log_groups   — unique server output patterns (deduplicated)
        test_cases   — each fuzzer request, pointing to a log_group

    Usage:
        db = LogDB("fuzzer_logs.db")
        db.record_test_case(index=42, sent_data=b"\\x00\\x01", lines=[...])
        db.close()
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        logger.info("Log database opened: %s", db_path)

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS log_groups (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                raw_text    TEXT NOT NULL,
                events_json TEXT
            );

            CREATE TABLE IF NOT EXISTS test_cases (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                test_index   INTEGER NOT NULL,
                sent_data    BLOB,
                log_group_id INTEGER REFERENCES log_groups(id),
                timestamp    REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tc_log_group
                ON test_cases(log_group_id);
        """)
        self._conn.commit()

    def record_test_case(
        self,
        index: int,
        sent_data: bytes | None,
        lines: list[str],
    ) -> int:
        """
        Record a test case and its server output.

        If the exact same output was seen before, reuses the existing
        log_group. Returns the test_case id.
        """
        log_group_id = self._get_or_create_log_group(lines) if lines else None

        cur = self._conn.execute(
            "INSERT INTO test_cases (test_index, sent_data, log_group_id, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (index, sent_data, log_group_id, time.time()),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def _get_or_create_log_group(self, lines: list[str]) -> int:
        """Find or create a log_group for the given output lines."""
        raw_text = "\n".join(lines)
        fingerprint = hashlib.sha256(raw_text.encode("utf-8", errors="replace")).hexdigest()

        # Check if this fingerprint already exists
        row = self._conn.execute(
            "SELECT id FROM log_groups WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row:
            return row[0]

        # Parse structured events
        events = []
        for line in lines:
            event, kv_json = self._parse_line(line)
            if event:
                events.append({"event": event, **(json.loads(kv_json) if kv_json else {})})

        events_json = json.dumps(events) if events else None

        cur = self._conn.execute(
            "INSERT INTO log_groups (fingerprint, raw_text, events_json) VALUES (?, ?, ?)",
            (fingerprint, raw_text, events_json),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    @staticmethod
    def _parse_line(raw_line: str) -> tuple[str | None, str | None]:
        """
        Parse a WTFUZZ| structured line.

        Format: WTFUZZ|EVENT|key1=val1|key2=val2|...
        Returns (event, kv_json) or (None, None) for non-WTFUZZ lines.
        """
        if not raw_line.startswith(WTFUZZ_PREFIX):
            return None, None

        parts = raw_line[len(WTFUZZ_PREFIX):].split("|")
        if not parts:
            return None, None

        event = parts[0]
        kv = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                kv[k] = v

        kv_json = json.dumps(kv) if kv else None
        return event, kv_json

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            logger.info("Log database closed: %s", self._db_path)
