"""
Minimal boofuzz monitor that records each fuzz request into the log database.

Does NO server interaction — no draining, no timing, no subprocess handling.
Server log correlation is done offline by analyze_logs.py after the run.

Writes one test_cases row per boofuzz test case:
  - test_index: boofuzz mutant_index
  - sent_data:  newline-separated hex of each write in the session
  - is_healthcheck: always 0 (health check rows are inserted by analyze_logs.py)
  - log_group_id: NULL until analyze_logs.py fills it in
"""

import logging

from boofuzz.monitors.base_monitor import BaseMonitor

from src.log_db import LogDB

logger = logging.getLogger(__name__)


class RequestLogger(BaseMonitor):
    """
    Boofuzz monitor that records sent payloads into the log database.

    One row is written per test case in post_send. log_group_id is left
    NULL and filled in later by analyze_logs.py once the server log is
    available.
    """

    def __init__(self, log_db: LogDB):
        super().__init__()
        self._db = log_db
        self._current_test_index: int = 0

    def pre_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Capture the current test index before sending."""
        self._current_test_index = (
            session.mutant_index if hasattr(session, "mutant_index") else 0
        )

    def post_send(
        self, target, fuzz_data_logger, session, mutated_data=None, *args, **kwargs
    ):
        """Record the sent payload into the DB."""
        sent: bytes | None = None

        if mutated_data is not None:
            sent = mutated_data
        else:
            try:
                conn = target._target_connection
                if conn:
                    sent = conn._last_sent_data
            except Exception:
                pass

        writes = [sent] if sent is not None else []

        self._db.record_test_case(
            index=self._current_test_index,
            sent_writes=writes,
            is_healthcheck=False,
        )

        return True

    def alive(self):
        return True
