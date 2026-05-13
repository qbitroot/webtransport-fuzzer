"""
Boofuzz monitor that records each test case to the SQLite log database.

Reads the structured per-step record from the connection
(``last_sent_steps``) rather than reverse-engineering it from raw bytes.
For oneshot mode there is exactly one ``capsule`` step; for scenario
modes there is one entry per executed step.

No server-side correlation happens here — that is the job of the
offline ``analyze_logs.py`` tool, which fills in ``log_group_id`` after
the fact from the WTFUZZ structured server log.
"""

from __future__ import annotations

import logging
from typing import List

from boofuzz.monitors.base_monitor import BaseMonitor

from src.log_db import LogDB
from src.sequence_mutator import Step

logger = logging.getLogger(__name__)


def _format_steps(steps: List[Step]) -> List[str]:
    """Render Steps as ``action(hex)`` lines for the SQLite ``sent_data`` column."""
    return [f"{s.action}({s.data.hex()})" for s in steps]


class RequestLogger(BaseMonitor):
    """Persist one row per test case to the SQLite log DB."""

    def __init__(self, log_db: LogDB):
        super().__init__()
        self._db = log_db
        self._test_index: int = 0

    def pre_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        self._test_index = getattr(session, "mutant_index", 0)

    def post_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        conn = getattr(target, "_target_connection", None)
        steps = getattr(conn, "last_sent_steps", []) if conn is not None else []
        self._db.record_test_case(
            index=self._test_index,
            sent_steps=_format_steps(steps),
            is_healthcheck=False,
        )
        return True

    def alive(self) -> bool:
        return True
