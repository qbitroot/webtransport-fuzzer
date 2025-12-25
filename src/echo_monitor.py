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

    It runs during the post-send phase. If a mismatch or missing response is
    detected it logs the failure, saves the test case (sent/recv) and returns False
    so boofuzz can treat the testcase as a crash (and optionally restart target).
    """

    def __init__(self, crash_on_mismatch: bool = True):
        """
        :param crash_on_mismatch: if True, the monitor returns False on mismatch/no-recv
                                  which boofuzz treats as a failure/crash condition.
        """
        super().__init__()
        self.crash_on_mismatch = crash_on_mismatch

    def post_send(self, target, fuzz_data_logger, session, mutated_data=None, *args, **kwargs):
        """
        Called after each send. We try to compare echoed response to what was sent.
        """
        try:
            conn = target._target_connection
            if conn is None:
                fuzz_data_logger.log_error("EchoCompareMonitor: could not access connection")
                return not self.crash_on_mismatch

            sent = mutated_data if mutated_data is not None else conn._last_sent_data
            recv = conn._last_received_data

            fuzz_data_logger.log_info("EchoCompareMonitor: performing post-send echo check")

            if sent is None:
                fuzz_data_logger.log_error("No sent buffer recorded for this testcase")
                return not self.crash_on_mismatch

            # Handle empty payload edge case
            if len(sent) == 0:
                if recv is None or len(recv) == 0:
                    fuzz_data_logger.log_check("Echo OK: empty payload echoed correctly")
                    return True
                else:
                    fuzz_data_logger.log_fail(f"Echo mismatch: sent empty but received {len(recv)} bytes")
                    path = save_failure(sent, recv)
                    fuzz_data_logger.log_info(f"Saved mismatch testcase to {path}")
                    return not self.crash_on_mismatch

            # For non-empty sends, missing/empty recv is a failure
            if recv is None or len(recv) == 0:
                fuzz_data_logger.log_fail("No response received from server (possible crash or parsing rejection)")
                path = save_failure(sent, recv)
                fuzz_data_logger.log_info(f"Saved failing testcase to {path}")
                return not self.crash_on_mismatch

            # Retrieve the expected Application Layer Payload from the Boofuzz session context
            # We look for the primitive named "Payload" in the last fuzzed node.
            expected_payload = None
             
            # Attempt 1: Check if we can find the node in the session's last test case
            if hasattr(session, 'last_recv') and session.last_recv:
                # This is usually the receive buffer, not valuable for us.
                pass
            
            # The 'mutated_data' is the full packet. To find the payload:
            # We can iterate the current node's primitives if available.
            current_node = None
            if hasattr(session, 'fuzz_node') and session.fuzz_node:
                 current_node = session.fuzz_node
            
            if current_node:
                payload_primitive = None
                for name, primitive in current_node.names.items():
                    if name.endswith(".Payload") or name == "Payload":
                        payload_primitive = primitive
                        break
                
                if payload_primitive:
                    # We want the value that was actually sent. 
                    # ._value is typically the mutated value if it was mutated, or the default.
                    # Since we don't easily know if it was just mutated, accessing ._value is a good best-guess.
                    try:
                        val = payload_primitive._value
                        if isinstance(val, bytes):
                            expected_payload = val
                        elif isinstance(val, str):
                            expected_payload = val.encode('utf-8')
                    except Exception:
                         pass
                    
                    if expected_payload is None:
                         # Fallback to default if _value is not set or valid
                         expected_payload = payload_primitive._default_value

                    # Ensure we have bytes
                    if isinstance(expected_payload, str):
                        expected_payload = expected_payload.encode('utf-8')
            
            # Comparison Logic
            if expected_payload is not None:
                # Log abstraction layers for clarity
                if len(sent) < 256:
                     fuzz_data_logger.log_info(f"Sent Packet (Wire Layer) : {sent!r}")
                     fuzz_data_logger.log_info(f"Sent Payload (App Layer) : {expected_payload!r}")
                
                if recv == expected_payload:
                    fuzz_data_logger.log_check(f"Echo OK: received bytes match Payload (len={len(recv)})")
                    return True
                else:
                    fuzz_data_logger.log_fail(f"Echo mismatch: received {recv!r} != expected payload {expected_payload!r}")
            else:
                 # Fallback to old strict match if we couldn't extract payload
                 if recv == sent:
                    fuzz_data_logger.log_check("Echo OK: response matches full sent packt")
                    return True
                 elif len(recv) > 0 and recv in sent:
                    fuzz_data_logger.log_check(f"Echo OK: response ({len(recv)} bytes) is substring of sent (legacy fallback)")
                    return True
                 else:
                    fuzz_data_logger.log_fail("Echo mismatch: received content differs from sent payload")

            path = save_failure(sent, recv)
            fuzz_data_logger.log_info(f"Saved mismatch testcase to {path}")
            
            if len(sent) < 256 and len(recv) < 256:
                if expected_payload:
                     fuzz_data_logger.log_info(f"Sent Payload (App Layer) : {expected_payload!r}")
                fuzz_data_logger.log_info(f"Sent Packet (Wire Layer) : {sent!r}")
                fuzz_data_logger.log_info(f"Recv Payload (App Layer) : {recv!r}")

            return not self.crash_on_mismatch

        except Exception as e:
            fuzz_data_logger.log_error(f"Exception in EchoCompareMonitor.post_send: {e}")
            logger.exception("EchoCompareMonitor exception")
            return not self.crash_on_mismatch
