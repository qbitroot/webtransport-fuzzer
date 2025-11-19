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

            # Exact match -> pass
            if recv == sent:
                fuzz_data_logger.log_check("Echo OK: response matches sent data")
                return True

            # Mismatch: save and log details
            fuzz_data_logger.log_fail("Echo mismatch: received content differs from sent payload")
            path = save_failure(sent, recv)
            fuzz_data_logger.log_info(f"Saved mismatch testcase to {path}")

            if len(sent) < 256 and len(recv) < 256:
                fuzz_data_logger.log_info(f"Sent (len={len(sent)}): {sent!r}")
                fuzz_data_logger.log_info(f"Recv (len={len(recv)}): {recv!r}")

            return not self.crash_on_mismatch

        except Exception as e:
            fuzz_data_logger.log_error(f"Exception in EchoCompareMonitor.post_send: {e}")
            logger.exception("EchoCompareMonitor exception")
            return not self.crash_on_mismatch
