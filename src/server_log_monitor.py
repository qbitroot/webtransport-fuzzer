"""
Boofuzz monitor that drains server subprocess output and writes it to the log database.

Wires together ServerManager (line capture) and LogDB (storage) on every test case.
"""

import logging
import time

from boofuzz.monitors.base_monitor import BaseMonitor

from src.log_db import LogDB, WTFUZZ_PREFIX
from src.server_manager import ServerManager

logger = logging.getLogger(__name__)


class ServerLogMonitor(BaseMonitor):
    """
    Boofuzz monitor that:
    1. After each send, drains buffered server output from ServerManager
    2. Stores the lines in LogDB correlated with the current test case
    3. Logs a summary to boofuzz's fuzz_data_logger
    """

    def __init__(
        self, server_manager: ServerManager, log_db: LogDB, delay_ms: int = 250
    ):
        super().__init__()
        self._server = server_manager
        self._db = log_db
        self._current_test_index = 0
        self._delay_secs = delay_ms / 1000.0

    def post_start_target(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Called after target connection is opened. Drain any startup noise."""
        self._server.drain_lines()

    def pre_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Track the current test case index before sending."""
        self._current_test_index = (
            session.mutant_index if hasattr(session, "mutant_index") else 0
        )
        # Drain any lines from between test cases (e.g. from health checks)
        self._server.drain_lines()

    def post_send(
        self, target, fuzz_data_logger, session, mutated_data=None, *args, **kwargs
    ):
        """
        After each fuzzed send, drain server output and store in DB.
        """
        # Get the data that was sent
        sent_data = None
        if mutated_data is not None:
            sent_data = mutated_data
        else:
            try:
                conn = target._target_connection
                if conn:
                    sent_data = conn._last_sent_data
            except Exception:
                pass

        # Give the server a moment to process the payload and log panics
        time.sleep(self._delay_secs)

        # Drain all server output since the last drain
        lines = self._server.drain_lines()

        # Filter out stray WTFUZZ lines from previous testcases (like health checks or slow closes).
        # We find the LAST SESSION_OPEN, and drop any WTFUZZ line before it, but we KEEP panics.
        last_open_idx = -1
        for i, line in enumerate(lines):
            if line.startswith(f"{WTFUZZ_PREFIX}SESSION_OPEN"):
                last_open_idx = i

        if last_open_idx != -1:
            filtered_lines = []
            for i, line in enumerate(lines):
                if i < last_open_idx:
                    # Keep raw panics/errors from previous late-terminating testcases,
                    # but drop the stray WTFUZZ structured lines (e.g. SESSION_CLOSE).
                    if not line.startswith(WTFUZZ_PREFIX):
                        filtered_lines.append(line)
                else:
                    filtered_lines.append(line)
            lines = filtered_lines

        # Store in DB (log_group deduplication handled internally)
        self._db.record_test_case(
            index=self._current_test_index,
            sent_data=sent_data,
            lines=lines,
        )

        # Log summary to boofuzz
        wtfuzz_count = sum(1 for l in lines if l.startswith(WTFUZZ_PREFIX))
        raw_count = len(lines) - wtfuzz_count

        if lines:
            fuzz_data_logger.log_info(
                f"Server output: {wtfuzz_count} structured + {raw_count} raw lines"
            )
            # Show raw (non-WTFUZZ) lines prominently — these are panics, exceptions, etc.
            for line in lines:
                if not line.startswith(WTFUZZ_PREFIX):
                    fuzz_data_logger.log_info(f"[SERVER RAW] {line}")
        else:
            fuzz_data_logger.log_info("Server output: (silent)")

        # Check if server is still alive
        if not self._server.is_alive():
            fuzz_data_logger.log_fail("SERVER PROCESS DIED!")
            return False

        return True

    def alive(self):
        """Report whether the server subprocess is still running."""
        return self._server.is_alive()
