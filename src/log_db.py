"""
SQLite store for fuzzer test cases and the server output they produced.

Two tables:

* ``test_cases`` — one row per fuzz test case, with ``sent_data`` as
  newline-separated ``action(hex)`` lines (one per executed step).
* ``log_groups`` — unique server-output blocks, deduplicated by SHA-256
  of the joined log lines. ``test_cases.log_group_id`` is filled in
  offline by ``correlate_logs.py`` once the server log is available.

Server output is stored verbatim. The WTFUZZ structured log format
(``WTFUZZ|<conn_idx>|EVENT|k=v|...``) is self-describing; raw lines
(panics, tracebacks) are captured alongside structured ones so anomalies
stand out by their deviation from the expected pattern.

``sent_data`` examples::

    oneshot   : "capsule(6843040000000000)"
    multistep : "bidi(48454c4c4f)\\ncapsule(800078ae00)\\ncapsule(68430400000000)"

Each line is ``action(hex-payload)`` where ``action`` is one of
``capsule`` / ``bidi`` / ``uni`` / ``datagram``.
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
    Use encode_sent() / decode_sent() to convert to/from step strings.

    Usage:
        db = LogDB("fuzzer_logs.db")
        db.record_test_case(index=42, sent_steps=["capsule(0001)"], is_healthcheck=False)
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
    def encode_sent(steps: list[str]) -> Optional[str]:
        """
        Join pre-formatted step strings into a newline-separated column value.
        Returns None if the list is empty.

        Each step is already in "action(hex)" form, e.g.:
            "capsule(6843040000000000)"
            "bidi(48454c4c4f)"
        """
        if not steps:
            return None
        return "\n".join(steps)

    @staticmethod
    def decode_sent(sent_data: Optional[str]) -> list[str]:
        """
        Split a stored sent_data column back into individual step strings.
        Returns an empty list if sent_data is None or empty.
        """
        if not sent_data:
            return []
        return sent_data.splitlines()

    def record_test_case(
        self,
        index: Optional[int],
        sent_steps: list[str],
        is_healthcheck: bool = False,
        lines: Optional[list[str]] = None,
    ) -> int:
        """
        Record a test case and optionally its server output.

        sent_steps: list of pre-formatted step strings in "action(hex)" form,
                    one per step sent within the session.
        lines: server log lines for this test case (stored in log_groups).
               Pass None or [] if log correlation will be done later by correlate_logs.py.

        Returns the new test_case id.
        """
        sent_data = self.encode_sent(sent_steps)
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
        """Update the log_group_id for an existing test case (used by correlate_logs.py)."""
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
