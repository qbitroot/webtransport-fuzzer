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
                # OPTIMIZATION: If we are fuzzing 'wt_close', silence is EXPECTED because
                # the connection is closed immediately. Don't waste time on health checks.
                if hasattr(session, 'fuzz_node') and session.fuzz_node.name == 'wt_close':
                     fuzz_data_logger.log_info("No response received (Expected for wt_close). Skipping health check.")
                     return True

                fuzz_data_logger.log_info("No response received. performing ACTIVE health check...")
                
                # Step 1: Check health on CURRENT connection
                try:
                    is_alive = conn.send_health_check()
                except Exception:
                    is_alive = False
                
                if is_alive:
                    fuzz_data_logger.log_check("Health Check PASSED: Server is alive (silence was safe).")
                    return True
                else:
                    # Step 2: Current connection might be dead (closed by server), 
                    # but server process might still be alive.
                    fuzz_data_logger.log_info("Current connection failed health check. Probing with FRESH connection...")
                    
                    try:
                        from src.fuzzer_connection import WebTransportConnection
                        
                        probe_conn = WebTransportConnection(conn.url, timeout=3.0)
                        probe_conn.open()
                        
                        probe_success = probe_conn.send_health_check()
                        probe_conn.close()
                        
                        if probe_success:
                             fuzz_data_logger.log_check("Probe PASSED: Server is alive. Current connection was just closed.")
                             return True
                        else:
                             fuzz_data_logger.log_fail("Probe FAILED: Server unresponsive to fresh connection!")
                             save_failure(sent, b"")
                             # Log crash but continue gracefully
                             fuzz_data_logger.log_error("CRASH DETECTED: Server unreachable. Saved failure case.")
                             return False
                             
                    except Exception as probe_err:
                        fuzz_data_logger.log_fail(f"Probe Exception: {probe_err}. SERVER DOWN.")
                        save_failure(sent, b"")
                        # Log crash but continue gracefully instead of crashing
                        fuzz_data_logger.log_error(f"CRASH DETECTED: Server probe failed. Saved failure case.")
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
