"""
Echo comparison monitor for boofuzz fuzzing.
Compares sent data with echoed responses.
"""

import logging
import os
import time
from typing import Optional

from boofuzz.monitors.base_monitor import BaseMonitor

logger = logging.getLogger(__name__)

class ServerDownError(Exception):
    """Raised when the target server is unreachable/down."""
    pass

FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


def save_failure(sent: Optional[bytes], recv: Optional[bytes]) -> str:
    """Save sent/recv pair to a timestamped file; return path."""
    ts = int(time.time() * 1000)
    fname = os.path.join(FAILURES_DIR, f"failure_{ts}.bin")
    with open(fname, "wb") as f:
        f.write(b"---SENT---\n")
        f.write(sent or b"")
        f.write(b"\n---RECV---\n")
        f.write(recv or b"")
    return fname


class EchoCompareMonitor(BaseMonitor):
    """
    Monitor that compares what was sent with what the target echoed back.

    After EVERY fuzzed request, performs a universal health check using a fresh
    connection to catch memory corruption that only manifests on a subsequent
    valid session (the core one-shot fuzzing pattern).
    """

    def __init__(self, crash_on_mismatch: bool = True):
        super().__init__()
        self.crash_on_mismatch = crash_on_mismatch
        self.target_ref = None

    def _fresh_health_check(self, conn, fuzz_data_logger, sent):
        """
        Universal health check using a FRESH connection.
        Opens a new connection, sends a bidirectional echo, and verifies the response.
        This catches memory corruption / server crashes that only appear on the next
        valid session after a malformed request.

        Returns True if server is healthy, raises ServerDownError otherwise.
        """
        fuzz_data_logger.log_info("Performing post-fuzz health check (fresh connection)...")

        try:
            from src.fuzzer_connection import WebTransportConnection

            probe_conn = WebTransportConnection(conn.url, timeout=3.0)
            probe_conn.open()

            probe_success = probe_conn.send_health_check()
            probe_conn.close()

            if probe_success:
                fuzz_data_logger.log_check("Health Check PASSED: Server is alive (fresh connection).")
                return True
            else:
                fuzz_data_logger.log_fail("Health Check FAILED: Server unresponsive to fresh connection!")
                save_failure(sent, b"")
                raise ServerDownError("Server is down (fresh probe failed)")

        except ServerDownError:
            raise
        except Exception as probe_err:
            fuzz_data_logger.log_fail(f"Health Check Exception: {probe_err}. SERVER DOWN.")
            save_failure(sent, b"")
            raise ServerDownError(f"Server is down (probe exception: {probe_err})")

    def post_send(self, target, fuzz_data_logger, session, mutated_data=None, *args, **kwargs):
        """
        Called after each send.
        1. Log what happened with this request (echo match / silence / etc).
        2. ALWAYS perform a fresh-connection health check to catch delayed corruption.
        """
        self.target_ref = target

        try:
            conn = target._target_connection
            if conn is None:
                fuzz_data_logger.log_error("EchoCompareMonitor: could not access connection")
                return True

            sent = mutated_data if mutated_data is not None else conn._last_sent_data
            recv = conn._last_received_data

            if sent is None:
                return True

            # --- Step 1: Log the echo result for this request ---

            if recv is None or len(recv) == 0:
                # Silence — expected for many fuzzed/malformed packets
                fuzz_data_logger.log_info("No echo response received (expected for fuzzed input).")
            else:
                # Response received — compare against expected payload if possible
                expected_payload = None
                if hasattr(session, 'fuzz_node') and session.fuzz_node:
                    for name, primitive in session.fuzz_node.names.items():
                        if name.endswith(".Payload") or name == "Payload":
                            try:
                                val = primitive._value
                                if isinstance(val, bytes):
                                    expected_payload = val
                                elif isinstance(val, str):
                                    expected_payload = val.encode('utf-8')
                            except:
                                pass
                            break

                if expected_payload:
                    if recv == expected_payload:
                        fuzz_data_logger.log_check(f"Echo OK: received bytes match Payload (len={len(recv)})")
                    else:
                        fuzz_data_logger.log_info(f"Echo mismatch (ignored): received {recv!r} != expected {expected_payload!r}")
                else:
                    fuzz_data_logger.log_info(f"Echo received: {len(recv)} bytes")

            # --- Step 2: Universal health check (fresh connection) ---
            # This is the core of one-shot fuzzing: after sending a potentially
            # malformed request, we perform a valid session to catch memory
            # corruption that only manifests on the next request.
            self._fresh_health_check(conn, fuzz_data_logger, sent)

            return True

        except ServerDownError:
            raise
        except Exception as e:
            fuzz_data_logger.log_error(f"Exception in EchoCompareMonitor.post_send: {e}")
            logger.exception("EchoCompareMonitor exception")
            return True

    def alive(self):
        return True
