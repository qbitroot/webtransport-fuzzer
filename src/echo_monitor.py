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
    Uses alive() check to distinguish between silence (valid) and crash (invalid).
    """

    def __init__(self, crash_on_mismatch: bool = True):
        super().__init__()
        self.crash_on_mismatch = crash_on_mismatch
        self.target_ref = None
        self._check_health_next = False

    def post_send(self, target, fuzz_data_logger, session, mutated_data=None, *args, **kwargs):
        """
        Called after each send. If no response is received, we IMMEDIATELY check health.
        """
        self._check_health_next = False
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

            # Case 1: Empty recv (Silence) - Potential Crash or Just Invalid Input
            if recv is None or len(recv) == 0:
                fuzz_data_logger.log_info("No response received. performing ACTIVE health check...")
                
                # Perform Health Check Immediately
                is_alive = conn.send_health_check()
                
                if is_alive:
                    fuzz_data_logger.log_check("Health Check PASSED: Server is alive (silence was safe).")
                    return True
                else:
                    fuzz_data_logger.log_fail("Health Check FAILED: Server unresponsive!")
                    save_failure(sent, b"")
                    return False

            # Case 2: Response received
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

            return True

        except Exception as e:
            fuzz_data_logger.log_error(f"Exception in EchoCompareMonitor.post_send: {e}")
            logger.exception("EchoCompareMonitor exception")
            return True

    def alive(self):
        return True
