"""
SQLite database for storing server logs correlated with fuzzer test cases.

Normalized model: (request_bytes ↔ response_category).

Log output is deduplicated into `log_groups` — each unique combination of
server output lines is stored once. Multiple test cases that produce the
same output all point to the same log_group_id, making it trivial to
group by failure mode.

No parsing or validation is performed on the server output. The WTFUZZ
structured log format (``WTFUZZ|EVENT|k=v|...``) is already self-describing,
so lines are stored verbatim. If the server emits unexpected output (panics,
exceptions, etc.), it is captured alongside the structured lines, making
anomalies immediately visible by their deviation from the expected pattern.
"""

import hashlib
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
                raw_text    TEXT NOT NULL
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
        fingerprint = hashlib.sha256(
            raw_text.encode("utf-8", errors="replace")
        ).hexdigest()

        row = self._conn.execute(
            "SELECT id FROM log_groups WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row:
            return row[0]

        cur = self._conn.execute(
            "INSERT INTO log_groups (fingerprint, raw_text) VALUES (?, ?)",
            (fingerprint, raw_text),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            logger.info("Log database closed: %s", self._db_path)
