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
        self._max_processed_conn_idx = -1
        self._accumulated_lines = []

    def post_start_target(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Called after target connection is opened. Accumulate any startup logs."""
        self._accumulated_lines.extend(self._server.drain_lines())

    def pre_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Track the current test case index before sending."""
        self._current_test_index = (
            session.mutant_index if hasattr(session, "mutant_index") else 0
        )
        # Accumulate any logs from just before sending
        self._accumulated_lines.extend(self._server.drain_lines())

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

        # FORCE CLOSE the fuzzer connection before we sleep and drain logs.
        # This guarantees the server will emit the SESSION_CLOSE log for the
        # fuzzed request (which otherwise wouldn't happen until boofuzz closes
        # it *after* post_send finishes). Boofuzz's subsequent target.close()
        # safely ignores already-closed connections.
        try:
            if target._target_connection:
                target._target_connection.close()
        except Exception:
            pass

        # Give the server a moment to process the payload and log panics
        time.sleep(self._delay_secs)

        # Drain all server output since the last drain, combining with accumulated
        lines = self._accumulated_lines + self._server.drain_lines()
        self._accumulated_lines = []

        # Filter out stray WTFUZZ lines from previous testcases
        # Group lines by their conn_idx, dropping those from old connection cycles,
        # and strip the conn_idx field before recording.
        conn_lines = {}
        raw_lines = []
        current_max_idx = self._max_processed_conn_idx

        for line in lines:
            if line.startswith(WTFUZZ_PREFIX):
                parts = line.split("|")
                if len(parts) >= 3:
                    try:
                        idx = int(parts[1])
                        # Accept if it's a new connection index
                        if idx > self._max_processed_conn_idx:
                            if idx not in conn_lines:
                                conn_lines[idx] = []
                            # Strip the connection index: WTFUZZ|<conn_idx>|EVENT|... -> WTFUZZ|EVENT|...
                            stripped_line = f"{WTFUZZ_PREFIX}{'|'.join(parts[2:])}"
                            conn_lines[idx].append(stripped_line)

                            if idx > current_max_idx:
                                current_max_idx = idx
                        else:
                            # It's an old connection's delayed log, ignore it completely.
                            pass
                    except ValueError:
                        # Couldn't parse idx, treat as raw
                        raw_lines.append(line)
                else:
                    # Malformed WTFUZZ line
                    raw_lines.append(line)
            else:
                # Raw panic/error line - always keep
                raw_lines.append(line)

        self._max_processed_conn_idx = current_max_idx

        filtered_lines = []
        # Group perfectly by connection ID
        for idx in sorted(conn_lines.keys()):
            filtered_lines.extend(conn_lines[idx])

        # Append any raw lines
        filtered_lines.extend(raw_lines)

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
