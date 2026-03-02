"""
SQLite database for storing server logs correlated with fuzzer test cases.

Normalized model: (request_bytes ↔ response_category).

Log output is deduplicated into `log_groups` — each unique combination of
server output lines is stored once. Multiple test cases that produce the
same output all point to the same log_group_id, making it trivial to
group by failure mode.

No parsing or validation is performed on the server output. The WTFUZZ
structured log format (``WTFUZZ|<conn_idx>|EVENT|k=v|...``) is already
self-describing, so lines are stored verbatim. If the server emits
unexpected output (panics, exceptions, etc.), it is captured alongside the
structured lines, making anomalies immediately visible by their deviation
from the expected pattern.

sent_data is stored as newline-separated hex strings, one per write:
    "4041ff\n6843"
means two writes were sent in sequence within the same session.
"""

import hashlib
import logging
import sqlite3
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Magic prefix for structured log lines from instrumented servers
WTFUZZ_PREFIX = "WTFUZZ|"


class LogDB:
    """
    SQLite store for fuzzer test cases and their corresponding server logs.

    Schema:
        log_groups   — unique server output patterns (deduplicated)
        test_cases   — each fuzzer request, pointing to a log_group

    sent_data is stored as newline-separated hex strings (one per write).
    Use encode_sent() / decode_sent() to convert to/from raw bytes.

    Usage:
        db = LogDB("fuzzer_logs.db")
        db.record_test_case(index=42, sent_writes=[b"\\x00\\x01"], is_healthcheck=False)
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
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                test_index      INTEGER,
                sent_data       TEXT,
                is_healthcheck  INTEGER NOT NULL DEFAULT 0,
                log_group_id    INTEGER REFERENCES log_groups(id),
                timestamp       REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tc_log_group
                ON test_cases(log_group_id);
        """)
        self._conn.commit()

    @staticmethod
    def encode_sent(writes: list[bytes]) -> Optional[str]:
        """
        Encode a list of raw byte writes as a newline-separated hex string.
        Returns None if the list is empty.

        Example: [b'\\x40\\x41', b'\\x68\\x43'] -> '4041\\n6843'
        """
        if not writes:
            return None
        return "\n".join(w.hex() for w in writes)

    @staticmethod
    def decode_sent(sent_data: Optional[str]) -> list[bytes]:
        """
        Decode a newline-separated hex string back to a list of byte writes.
        Returns an empty list if sent_data is None or empty.
        """
        if not sent_data:
            return []
        return [bytes.fromhex(h) for h in sent_data.splitlines()]

    def record_test_case(
        self,
        index: Optional[int],
        sent_writes: list[bytes],
        is_healthcheck: bool = False,
        lines: Optional[list[str]] = None,
    ) -> int:
        """
        Record a test case and optionally its server output.

        sent_writes: list of raw byte payloads sent in order within this session.
        lines: server log lines for this test case (stored in log_groups).
               Pass None or [] if log correlation will be done later by analyze_logs.py.

        Returns the new test_case id.
        """
        sent_data = self.encode_sent(sent_writes)
        log_group_id = self._get_or_create_log_group(lines) if lines else None

        cur = self._conn.execute(
            "INSERT INTO test_cases "
            "(test_index, sent_data, is_healthcheck, log_group_id, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (index, sent_data, int(is_healthcheck), log_group_id, time.time()),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def set_log_group(self, test_case_id: int, log_group_id: int) -> None:
        """Update the log_group_id for an existing test case (used by analyze_logs.py)."""
        self._conn.execute(
            "UPDATE test_cases SET log_group_id = ? WHERE id = ?",
            (log_group_id, test_case_id),
        )
        self._conn.commit()

    def get_test_cases(self) -> list[dict]:
        """Return all test cases ordered by id."""
        cur = self._conn.execute(
            "SELECT id, test_index, sent_data, is_healthcheck, log_group_id, timestamp "
            "FROM test_cases ORDER BY id"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

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
        assert cur.lastrowid is not None
        return cur.lastrowid

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            logger.info("Log database closed: %s", self._db_path)
