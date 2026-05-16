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
import sys
import time
from typing import List

from boofuzz.monitors.base_monitor import BaseMonitor

from src.log_db import LogDB
from src.sequence_mutator import Step

logger = logging.getLogger(__name__)

# Progress is printed every N test cases (quiet mode only).
_PROGRESS_INTERVAL = 100


def _format_steps(steps: List[Step]) -> List[str]:
    """Render Steps as ``action(hex)`` lines for the SQLite ``sent_data`` column."""
    return [f"{s.action}({s.data.hex()})" for s in steps]


class RequestLogger(BaseMonitor):
    """Persist one row per test case to the SQLite log DB."""

    def __init__(self, log_db: LogDB, total: int = 0):
        super().__init__()
        self._db = log_db
        self._total = total
        self._test_index: int = 0
        self._start_time: float = time.monotonic()
        self._completed: int = 0

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
        self._completed += 1
        if self._completed % _PROGRESS_INTERVAL == 0:
            self._print_progress()
        return True

    def _print_progress(self) -> None:
        elapsed = time.monotonic() - self._start_time
        rate = self._completed / elapsed if elapsed > 0 else 0
        if self._total > 0:
            pct = self._completed / self._total * 100
            eta = (self._total - self._completed) / rate if rate > 0 else 0
            eta_m, eta_s = divmod(int(eta), 60)
            sys.stderr.write(
                f"\r[progress] {self._completed}/{self._total}"
                f" ({pct:.1f}%)  {rate:.1f} tc/s  ETA {eta_m}m{eta_s:02d}s   "
            )
        else:
            sys.stderr.write(f"\r[progress] {self._completed} done  {rate:.1f} tc/s   ")
        sys.stderr.flush()

    def print_summary(self) -> None:
        """Print final progress line (call after fuzzing completes)."""
        elapsed = time.monotonic() - self._start_time
        rate = self._completed / elapsed if elapsed > 0 else 0
        minutes, secs = divmod(int(elapsed), 60)
        sys.stderr.write(
            f"\r[done] {self._completed} test cases in"
            f" {minutes}m{secs:02d}s ({rate:.1f} tc/s)          \n"
        )
        sys.stderr.flush()

    def alive(self) -> bool:
        return True
