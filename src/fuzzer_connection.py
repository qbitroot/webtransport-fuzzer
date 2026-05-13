"""
Boofuzz ``ITargetConnection`` wrapper around the aioquic WebTransport client.

Two send modes are supported:

* ``capsule``  — the bytes value passed to ``send`` is a raw capsule blob
  written directly to the CONNECT stream. Used by ``--mode oneshot``.

* ``scenario`` — the bytes value is a fixed-width scenario token (see
  ``src.sequence_mutator.SCENARIOS``). The connection looks the scenario
  up in the registry and executes its steps in order on a single live
  session. Used by ``--mode multistep`` / ``scenario-lastfuzz`` / ``all``.

After each ``send``, structured results are stashed on the connection
object so monitors can inspect what happened:

* ``last_sent_steps``     — list of ``Step`` instances actually executed
                            (capsule-mode synthesises a single-step list).
* ``last_step_outcomes``  — list of ``StepOutcome`` parallel to
                            ``last_sent_steps``.
* ``last_send_error``     — ``None`` on success, else the exception
                            raised by the asyncio runner.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from boofuzz.connections import ITargetConnection

from src.sequence_mutator import (
    SCENARIOS,
    Step,
    is_scenario_token,
    step_capsule,
)
from src.webtransport_client import WebTransportClient

logger = logging.getLogger(__name__)


SEND_MODE_CAPSULE = "capsule"
SEND_MODE_SCENARIO = "scenario"
_VALID_SEND_MODES = {SEND_MODE_CAPSULE, SEND_MODE_SCENARIO}


@dataclass
class StepOutcome:
    """Per-step result, parallel to the step list in ``last_sent_steps``.

    ``echo_received`` is the bytes the server sent back on the same logical
    transport (bidi response, uni-stream echo, datagram echo). ``None`` when
    no echo is expected (capsule) or when none was received.

    ``echo_match`` is ``True``/``False`` for steps that expect an echo
    (bidi/uni/datagram), and ``None`` for capsule steps. The "expected echo"
    is the step's own ``data``.

    ``error`` captures any exception raised while executing the step.
    """

    echo_received: Optional[bytes] = None
    echo_match: Optional[bool] = None
    error: Optional[str] = None


@dataclass
class _SendResult:
    steps: List[Step] = field(default_factory=list)
    outcomes: List[StepOutcome] = field(default_factory=list)


class WebTransportConnection(ITargetConnection):
    """
    Boofuzz target connection: opens a WebTransport-over-HTTP/3 session per
    test case and drives it from synchronous ``send`` calls.

    The class owns its own asyncio loop and aioquic protocol instance. A
    fresh QUIC handshake runs on every ``open()`` because boofuzz's
    ``reuse_target_connection=False`` is required for one-shot crash
    isolation.
    """

    def __init__(
        self, url: str, timeout: float = 1.0, send_mode: str = SEND_MODE_CAPSULE
    ):
        if send_mode not in _VALID_SEND_MODES:
            raise ValueError(
                f"Unknown send_mode {send_mode!r}; expected one of {_VALID_SEND_MODES}"
            )
        self.url = url
        self.timeout = timeout
        self._send_mode = send_mode

        parsed = urlparse(url)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or "/"
        self.authority = f"{self.host}:{self.port}"

        self._protocol: Optional[WebTransportClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._client_context = None

        # Public state inspected by monitors (RequestLogger, EchoCompareMonitor)
        self.last_sent_steps: List[Step] = []
        self.last_step_outcomes: List[StepOutcome] = []
        self.last_send_error: Optional[BaseException] = None
        # Result of the in-session post-fuzz health probe (None until run).
        self.last_health_check: Optional[StepOutcome] = None

    @property
    def info(self) -> str:
        return f"WebTransport({self.url})"

    # -- ITargetConnection lifecycle ------------------------------------------------

    def open(self):
        """Establish QUIC + HTTP/3 + WebTransport session synchronously."""
        logger.info("Opening WebTransport connection to %s", self.url)
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._async_open())
            logger.info("Connection open")
        except Exception:
            self._discard_loop()
            raise

    async def _async_open(self):
        config = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=True,
            verify_mode=False,
            max_datagram_frame_size=65536,
        )
        self._client_context = connect(
            self.host,
            self.port,
            configuration=config,
            create_protocol=WebTransportClient,
        )
        try:
            self._protocol = await asyncio.wait_for(
                self._client_context.__aenter__(), timeout=self.timeout
            )
            await asyncio.wait_for(
                self._protocol.establish_session(self.authority, self.path),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            raise ConnectionError("Server unreachable (timeout)") from None
        except Exception as e:
            raise ConnectionError(f"Server unreachable ({e})") from e

    def close(self):
        """Close the WebTransport session and tear down the asyncio loop."""
        logger.info("Closing WebTransport connection")
        if self._loop and self._client_context:
            try:
                self._loop.run_until_complete(
                    self._client_context.__aexit__(None, None, None)
                )
            except Exception:
                logger.exception("Error during client context exit")
        self._discard_loop()

    def _discard_loop(self):
        if self._loop is not None:
            try:
                self._loop.close()
            except Exception:
                pass
        self._loop = None
        self._protocol = None
        self._client_context = None

    # -- ITargetConnection I/O ------------------------------------------------------

    def send(self, data: bytes) -> int:
        """
        Execute one test case. Dispatches by ``send_mode``:

        * ``capsule``  — write ``data`` to the CONNECT stream as a raw capsule
        * ``scenario`` — look up the scenario token and execute every step

        Returns the number of bytes nominally consumed (boofuzz only checks
        for a non-zero return). Records execution details on
        ``self.last_sent_steps`` / ``last_step_outcomes`` /
        ``last_send_error`` for monitors to inspect.
        """
        if not self._loop or not self._protocol:
            raise RuntimeError("Connection not open")

        self.last_sent_steps = []
        self.last_step_outcomes = []
        self.last_send_error = None
        self.last_health_check = None

        try:
            if self._send_mode == SEND_MODE_CAPSULE:
                result = self._loop.run_until_complete(self._run_capsule(data))
            else:  # SEND_MODE_SCENARIO
                result = self._loop.run_until_complete(self._run_scenario(data))
        except Exception as e:
            self.last_send_error = e
            logger.exception("Exception during send")
            raise

        self.last_sent_steps = result.steps
        self.last_step_outcomes = result.outcomes
        return len(data)

    def recv(self, max_bytes: int) -> bytes:
        """
        Required by ``ITargetConnection``; not used by our fuzzing flow.

        Echoes are captured per-step inside ``_run_scenario`` and exposed
        via ``last_step_outcomes`` rather than the boofuzz recv channel.
        """
        return b""

    # -- in-session health probe ----------------------------------------------------

    _HEALTH_PROBE_BYTES = b"HEALTHCHECK"

    def health_check(self, timeout: float = 1.0) -> StepOutcome:
        """
        Send a bidi echo probe on the still-open session and report the result.

        Called by ``EchoCompareMonitor.post_send`` between the fuzz step(s)
        and ``close()``. Detects servers that accepted the malformed input
        without crashing but whose echo path is now broken (silent
        corruption). The result is stored on ``last_health_check`` so the
        monitor can decide whether to fail the test case.
        """
        outcome = StepOutcome()
        if not self._loop or not self._protocol:
            outcome.error = "connection not open"
            self.last_health_check = outcome
            return outcome
        try:
            _sid, response = self._loop.run_until_complete(
                self._protocol.send_bidirectional_stream(
                    self._HEALTH_PROBE_BYTES, timeout=timeout
                )
            )
            outcome.echo_received = response
            outcome.echo_match = response == self._HEALTH_PROBE_BYTES
        except Exception as e:
            outcome.error = repr(e)
        self.last_health_check = outcome
        return outcome

    # -- send-mode implementations --------------------------------------------------

    async def _run_capsule(self, data: bytes) -> _SendResult:
        """One-shot mode: send a raw capsule blob; no echo expected."""
        step = step_capsule(data)
        outcome = StepOutcome()
        try:
            self._protocol.send_capsule(data)
        except Exception as e:
            outcome.error = repr(e)
            raise
        return _SendResult(steps=[step], outcomes=[outcome])

    async def _run_scenario(self, token: bytes) -> _SendResult:
        """Scenario mode: decode token, execute steps, collect outcomes."""
        if not is_scenario_token(token):
            raise RuntimeError("scenario send_mode received non-scenario bytes")

        scenario = SCENARIOS.lookup(token)
        result = _SendResult()

        for step in scenario:
            outcome = StepOutcome()
            result.steps.append(step)
            result.outcomes.append(outcome)
            try:
                await self._execute_step(step, outcome)
            except Exception as e:
                # We log and keep going: a fuzzed scenario may legitimately
                # cause a step to fail. Subsequent steps may still expose
                # state-confusion bugs.
                outcome.error = repr(e)
                logger.debug("Step %s failed: %s (continuing)", step.action, e)
        return result

    async def _execute_step(self, step: Step, outcome: StepOutcome) -> None:
        action = step.action
        data = step.data
        if action == "bidi":
            _sid, response = await self._protocol.send_bidirectional_stream(
                data, timeout=1.0
            )
            outcome.echo_received = response
            outcome.echo_match = response == data if response is not None else False
        elif action == "uni":
            await self._protocol.send_unidirectional_stream(data)
            response = await self._protocol.receive_stream_echo(timeout=0.5)
            outcome.echo_received = response
            outcome.echo_match = response == data if response is not None else False
        elif action == "datagram":
            self._protocol.send_datagram(data)
            response = await self._protocol.receive_datagram_echo(timeout=0.5)
            outcome.echo_received = response
            outcome.echo_match = response == data if response is not None else False
        elif action == "capsule":
            self._protocol.send_capsule(data)
        else:
            raise ValueError(f"Unknown step action: {action!r}")
