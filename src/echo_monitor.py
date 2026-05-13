"""
Echo-comparison monitor.

For each test case, inspects the per-step outcomes recorded by the
WebTransport connection and reports any echo mismatch as a boofuzz
failure. No fresh-handshake probe is performed — the next test case's
``connection.open()`` is the implicit liveness check; if the server is
down it raises ``ConnectionError`` which boofuzz surfaces as a failure.

What counts as an echo mismatch:

* ``bidi`` step — server didn't echo, or echoed bytes differing from the
  sent payload.
* ``uni`` / ``datagram`` step — same: server's echo (if the server is an
  echo server, which is the case for the bundled reference servers).

What does *not* count:

* ``capsule`` steps. Capsules are control messages; servers are free to
  silently ignore unknown / malformed ones (RFC 9297 §3.2).
* Steps that raised an exception locally (e.g. send-side timeout). These
  are recorded in ``StepOutcome.error`` and logged at info level but
  don't fail the test case on their own — many fuzzed scenarios will
  legitimately stress the local stack.

Failure artefacts (sent steps + per-step outcomes) are written to
``failures/failure_<timestamp>.txt`` for offline triage.
"""

from __future__ import annotations

import logging
import os
import time
from typing import List

from boofuzz.monitors.base_monitor import BaseMonitor

from src.fuzzer_connection import StepOutcome
from src.sequence_mutator import Step

logger = logging.getLogger(__name__)


class ServerDownError(Exception):
    """Raised when the target server is unreachable."""


FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


def _save_failure(steps: List[Step], outcomes: List[StepOutcome], reason: str) -> str:
    """Append a human-readable failure record to ``failures/`` and return path."""
    ts = int(time.time() * 1000)
    path = os.path.join(FAILURES_DIR, f"failure_{ts}.txt")
    with open(path, "w") as f:
        f.write(f"reason: {reason}\n")
        f.write("steps:\n")
        for i, (step, outcome) in enumerate(zip(steps, outcomes)):
            f.write(f"  [{i}] {step.action}({step.data.hex()})\n")
            if outcome.error is not None:
                f.write(f"      error: {outcome.error}\n")
            if outcome.echo_received is not None:
                f.write(f"      echo : {outcome.echo_received.hex()}\n")
            if outcome.echo_match is False:
                f.write("      echo_match: NO\n")
    return path


class EchoCompareMonitor(BaseMonitor):
    """
    Inspect per-step outcomes and report echo behaviour.

    Default is informational only: fuzzed scenarios will often legitimately
    drop or distort echoes (out-of-order steps, prohibited capsules, etc.),
    so missing echoes alone are not a failure signal. Set
    ``fail_on_mismatch=True`` to escalate every echo discrepancy into a
    boofuzz failure (saved to ``failures/``) — useful when running a
    pristine scenario against a server you trust to behave.
    """

    def __init__(self, fail_on_mismatch: bool = False):
        super().__init__()
        self.fail_on_mismatch = fail_on_mismatch

    def post_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        conn = getattr(target, "_target_connection", None)
        if conn is None:
            fuzz_data_logger.log_error("EchoCompareMonitor: no connection on target")
            return True

        steps: List[Step] = getattr(conn, "last_sent_steps", []) or []
        outcomes: List[StepOutcome] = getattr(conn, "last_step_outcomes", []) or []

        mismatches = []
        for i, (step, outcome) in enumerate(zip(steps, outcomes)):
            if step.action == "capsule":
                continue
            if outcome.echo_match is True:
                fuzz_data_logger.log_check(
                    f"step[{i}] {step.action}: echo OK ({len(step.data)}B)"
                )
            elif outcome.echo_match is False:
                # No echo, or wrong echo. For fuzzed (mutated) traffic this is
                # informational rather than a definite bug, but for reordered/
                # injected scenarios on a healthy session it indicates the
                # server's echo path is broken.
                got = outcome.echo_received
                if got is None:
                    fuzz_data_logger.log_info(
                        f"step[{i}] {step.action}: no echo received"
                    )
                else:
                    fuzz_data_logger.log_info(
                        f"step[{i}] {step.action}: echo mismatch "
                        f"(sent {len(step.data)}B, got {len(got)}B)"
                    )
                mismatches.append(i)

        if mismatches and self.fail_on_mismatch:
            path = _save_failure(steps, outcomes, "echo mismatch")
            fuzz_data_logger.log_fail(
                f"echo mismatches at steps {mismatches}; saved to {path}"
            )

        return True

    def alive(self) -> bool:
        return True
