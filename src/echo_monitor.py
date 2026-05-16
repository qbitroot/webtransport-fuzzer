"""
Echo-comparison monitor.

Two things happen around each test case:

1. **Pre-send health probe.** Before the fuzz payload is sent, a single
   bidi echo of the magic bytes ``HEALTHCHECK`` is sent on the
   still-fresh WebTransport session. This confirms the echo path is
   functional *before* the malformed data is injected. A failure here
   means the session was broken before we even fuzzed — the test case is
   marked as a boofuzz failure and written to ``failures/``.

2. **Post-send per-step echo logging.** For every executed step the
   connection recorded a ``StepOutcome`` (echo bytes, match/no-match,
   error). The monitor logs each one. For fuzzed scenarios this is
   informational — missing echoes are common and not necessarily bugs.

Server-crash detection is implicit: the *next* test case's ``open()``
fails if the server went down, and boofuzz's retry policy handles
that. This keeps exactly one QUIC handshake per test case.
"""

from __future__ import annotations

import logging
import os
import time
from typing import List, Optional

from boofuzz.monitors.base_monitor import BaseMonitor

from src.fuzzer_connection import StepOutcome
from src.sequence_mutator import Step

logger = logging.getLogger(__name__)


class ServerDownError(Exception):
    """Raised when the target server is unreachable."""


FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


def _save_failure(
    steps: List[Step],
    outcomes: List[StepOutcome],
    health: Optional[StepOutcome],
    reason: str,
) -> str:
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
        if health is not None:
            f.write("health_check:\n")
            if health.error is not None:
                f.write(f"  error: {health.error}\n")
            if health.echo_received is not None:
                f.write(f"  echo : {health.echo_received.hex()}\n")
            f.write(f"  echo_match: {health.echo_match}\n")
    return path


class EchoCompareMonitor(BaseMonitor):
    """
    Run a pre-send health probe and inspect post-send per-step outcomes.

    The health probe runs *before* the fuzz payload to confirm the echo
    path is functional on the fresh session. A failure means the session
    was broken before fuzzing — always escalated to a boofuzz failure.

    Per-step echo mismatches only escalate if ``fail_on_mismatch=True``
    — useful for pristine scenarios against a server you trust to behave;
    off by default because fuzzed scenarios will legitimately drop or
    distort echoes.
    """

    def __init__(self, fail_on_mismatch: bool = False, probe_timeout: float = 1.0):
        super().__init__()
        self.fail_on_mismatch = fail_on_mismatch
        self.probe_timeout = probe_timeout

    def pre_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Health probe: confirm echo path works before the fuzz payload."""
        conn = getattr(target, "_target_connection", None)
        if conn is None:
            fuzz_data_logger.log_error("EchoCompareMonitor: no connection on target")
            return

        health = conn.health_check(timeout=self.probe_timeout)
        if health.echo_match is True:
            fuzz_data_logger.log_check("pre_send health_check: echo OK")
        else:
            if health.error is not None:
                fuzz_data_logger.log_fail(
                    f"pre_send health_check: probe raised {health.error}"
                )
            elif health.echo_received is None:
                fuzz_data_logger.log_fail("pre_send health_check: no echo received")
            else:
                fuzz_data_logger.log_fail(
                    f"pre_send health_check: echo mismatch "
                    f"(got {health.echo_received!r})"
                )
            path = _save_failure([], [], health, "pre_send health_check failed")
            fuzz_data_logger.log_fail(f"saved failure to {path}")

    def post_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Log per-step echo results after the fuzz payload."""
        conn = getattr(target, "_target_connection", None)
        if conn is None:
            fuzz_data_logger.log_error("EchoCompareMonitor: no connection on target")
            return True

        steps: List[Step] = getattr(conn, "last_sent_steps", []) or []
        outcomes: List[StepOutcome] = getattr(conn, "last_step_outcomes", []) or []

        # Log every step's echo result.
        mismatches = []
        for i, (step, outcome) in enumerate(zip(steps, outcomes)):
            if step.action == "capsule":
                continue
            if outcome.echo_match is True:
                fuzz_data_logger.log_check(
                    f"step[{i}] {step.action}: echo OK ({len(step.data)}B)"
                )
            elif outcome.echo_match is False:
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

        # Escalate per-step mismatches if requested.
        if mismatches and self.fail_on_mismatch:
            health = getattr(conn, "last_health_check", None)
            path = _save_failure(steps, outcomes, health, "echo mismatch")
            fuzz_data_logger.log_fail(
                f"echo mismatches at steps {mismatches}; saved to {path}"
            )

        return True

    def alive(self) -> bool:
        return True
