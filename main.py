#!/usr/bin/env python3

import asyncio
import logging
import os
import time
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    H3Event,
    HeadersReceived,
    DatagramReceived,
    WebTransportStreamDataReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from boofuzz import Session, Target, FuzzLoggerText
from boofuzz import s_initialize, s_get, s_string
from boofuzz.connections import ITargetConnection
from boofuzz.monitors.base_monitor import BaseMonitor

# ---- Logging setup ----
LOG_FMT = "%(asctime)s [%(levelname)5s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
logger = logging.getLogger("wt_fuzzer")
# reduce tornado noise from boofuzz web ui
logging.getLogger("tornado.access").setLevel(logging.WARNING)

# ---- Helper: ensure failure dir exists ----
FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


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

        The "mutated_data" argument may or may not be provided by the boofuzz runtime;
        if it's not present we fall back to the connection's stored _last_sent_data.
        """
        try:
            # Access the connection directly from target
            conn = target._target_connection
            if conn is None or not isinstance(conn, WebTransportConnection):
                fuzz_data_logger.log_error("EchoCompareMonitor: could not access WebTransportConnection")
                return not self.crash_on_mismatch

            # Prefer mutated_data if boofuzz provided it; otherwise use conn buffer
            sent = mutated_data if mutated_data is not None else conn._last_sent_data
            recv = conn._last_received_data

            fuzz_data_logger.log_info("EchoCompareMonitor: performing post-send echo check")

            if sent is None:
                fuzz_data_logger.log_error("No sent buffer recorded for this testcase")
                return not self.crash_on_mismatch

            # Handle empty payload edge case: empty send should get empty echo
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


class WebTransportClientProtocol(QuicConnectionProtocol):
    """
    Black-box WebTransport client protocol handler.
    Handles HTTP/3 connection and WebTransport session establishment.
    Minimal event handling to capture stream/datagram data for the fuzzer.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._session_id: Optional[int] = None
        self._session_established = asyncio.Event()
        self._authority: Optional[str] = None
        self._bidirectional_streams: Dict[int, asyncio.Queue] = {}
        self._received_messages = asyncio.Queue()

    def quic_event_received(self, event: QuicEvent):
        # Lazily create H3 connection wrapper
        if self._http is None:
            self._http = H3Connection(self._quic, enable_webtransport=True)

        # Handle QUIC-level stream data (client-initiated streams we track)
        if isinstance(event, StreamDataReceived):
            qsid = event.stream_id
            if qsid in self._bidirectional_streams:
                self._bidirectional_streams[qsid].put_nowait(('data', event.data))
                if event.end_stream:
                    self._bidirectional_streams[qsid].put_nowait(('end', None))

        # Translate to H3 events and handle them
        for h3_event in self._http.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event):
        if isinstance(event, HeadersReceived):
            # Check for CONNECT (WebTransport) response success (200)
            headers_dict = dict(event.headers)
            status = headers_dict.get(b":status", b"")
            if status == b"200":
                # the HTTP3 stream_id for the CONNECT indicates the session
                self._session_id = event.stream_id
                self._session_established.set()
                logger.info("WebTransport session established (stream %d)", event.stream_id)
            else:
                logger.error(
                    "WebTransport CONNECT failed: status=%s headers=%s",
                    status.decode(errors="ignore"),
                    headers_dict,
                )

        elif isinstance(event, DatagramReceived):
            self._received_messages.put_nowait(('datagram', event.data))

        elif isinstance(event, WebTransportStreamDataReceived):
            # Server-initiated WebTransport stream data
            self._received_messages.put_nowait(('stream', event.stream_id, event.data))
            if event.stream_ended:
                logger.debug("Server closed stream %d", event.stream_id)

    async def establish_session(self, authority: str, path: str = "/echo"):
        """Send the CONNECT: webtransport request and wait for 200."""
        self._authority = authority
        # pick a new client-initiated stream id
        stream_id = self._quic.get_next_available_stream_id()
        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b":protocol", b"webtransport"),
            (b"sec-webtransport-http3-draft", b"draft02"),
        ]
        logger.info("Sending CONNECT for WebTransport to %s%s", authority, path)
        # send headers and flush
        self._http.send_headers(stream_id, headers)
        self.transmit()
        # wait for session establishment
        await asyncio.wait_for(self._session_established.wait(), timeout=5.0)

    async def send_bidirectional_stream(self, data: bytes, timeout: float = 3.0) -> Tuple[int, Optional[bytes]]:
        """
        Create a WebTransport bidirectional stream, send data, wait for response.
        Returns (stream_id, response_bytes_or_None).
        """
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")

        # create a new webtransport stream via h3 wrapper
        stream_id = self._http.create_webtransport_stream(
            session_id=self._session_id,
            is_unidirectional=False,
        )

        # create a queue to receive data events for this stream
        response_q: asyncio.Queue = asyncio.Queue()
        self._bidirectional_streams[stream_id] = response_q

        # write and close the write side
        self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=True)
        self.transmit()

        try:
            # first event may be data or end
            event_type, payload = await asyncio.wait_for(response_q.get(), timeout=timeout)
            if event_type == 'data':
                # optionally wait a short time for end marker
                try:
                    end_event = await asyncio.wait_for(response_q.get(), timeout=1.0)
                    if end_event[0] == 'end':
                        pass
                except asyncio.TimeoutError:
                    pass
                return stream_id, payload
            elif event_type == 'end':
                return stream_id, None
            else:
                return stream_id, None
        except asyncio.TimeoutError:
            logger.debug("Timeout waiting for response on stream %d", stream_id)
            return stream_id, None
        finally:
            # cleanup
            self._bidirectional_streams.pop(stream_id, None)


class WebTransportConnection(ITargetConnection):
    """
    boofuzz ITargetConnection implementation using aioquic WebTransport streams.

    It stores last sent/received data on the object, so the monitor
    can inspect and compare them.
    """

    def __init__(self, url: str, timeout: float = 3.0):
        self.url = url
        self.timeout = timeout
        self._protocol: Optional[WebTransportClientProtocol] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._client_context = None
        self._last_sent_data: Optional[bytes] = None
        self._last_received_data: Optional[bytes] = None

        parsed = urlparse(url)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or "/"
        self.authority = f"{self.host}:{self.port}"

        logger.info("WebTransportConnection initialized for %s", url)

    @property
    def info(self) -> str:
        return f"WebTransport({self.url})"

    def open(self):
        """Establish QUIC/H3/WebTransport session (blocking for boofuzz)."""
        logger.info("Opening WebTransport connection to %s", self.url)
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._async_open())
            logger.info("Connection open")
        except Exception:
            logger.exception("Failed to open connection")
            # ensure loop closed on failure
            if self._loop:
                try:
                    self._loop.close()
                except Exception:
                    pass
                self._loop = None
            raise

    async def _async_open(self):
        config = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=True,
            verify_mode=False,  # testing: skip cert verification
            max_datagram_frame_size=65536,
        )
        self._client_context = connect(
            self.host,
            self.port,
            configuration=config,
            create_protocol=WebTransportClientProtocol,
        )
        # enter context to get the protocol instance
        self._protocol = await self._client_context.__aenter__()

        # establish webtransport session (CONNECT)
        await self._protocol.establish_session(self.authority, self.path)

    def close(self):
        """Close session and loop cleanly."""
        logger.info("Closing WebTransport connection")
        if self._loop and self._client_context:
            try:
                self._loop.run_until_complete(self._client_context.__aexit__(None, None, None))
            except Exception:
                logger.exception("Error during client context exit")
            finally:
                if self._loop:
                    try:
                        self._loop.close()
                    except Exception:
                        pass
                    self._loop = None
                self._protocol = None

    def send(self, data: bytes) -> int:
        """Send fuzzed data via a new bidirectional stream and store last_* buffers."""
        if not self._loop or not self._protocol:
            raise RuntimeError("Connection not open")

        logger.debug("Sending %d bytes (preview: %s)", len(data), data[:100])
        self._last_sent_data = data
        self._last_received_data = None

        try:
            stream_id, response = self._loop.run_until_complete(
                self._protocol.send_bidirectional_stream(data, timeout=self.timeout)
            )
            self._last_received_data = response
            if response is not None:
                logger.debug("Received %d bytes on stream %d", len(response), stream_id)
            else:
                logger.debug("No response received for stream %d", stream_id)
            # boofuzz expects send() to return number of bytes sent
            return len(data)
        except Exception:
            logger.exception("Exception during send")
            raise

    def recv(self, max_bytes: int) -> bytes:
        """Return previously stored response (up to max_bytes)."""
        if self._last_received_data:
            return self._last_received_data[:max_bytes]
        return b""


# ---- Utilities used by the monitor ----
def save_failure(sent: Optional[bytes], recv: Optional[bytes]) -> str:
    """Save sent/recv pair to a timestamped file; return path."""
    ts = int(time.time() * 1000)
    fname = os.path.join(FAILURES_DIR, f"failure_{ts}.bin")
    with open(fname, "wb") as f:
        # write a small header to aid analysis
        f.write(b"---SENT---\n")
        f.write(sent or b"")
        f.write(b"\n---RECV---\n")
        f.write(recv or b"")
    return fname


# ---- Protocol definition for boofuzz ----
def define_protocol():
    # Using boofuzz's API to define a simple fuzzable string field
    s_initialize("webtransport_echo")
    s_string("Hello, WebTransport!", fuzzable=True)
    return s_get("webtransport_echo")


# ---- Main entrypoint ----
def main():
    target_url = "https://wt-ord.akaleapi.net:6161/echo"  # customize as needed

    print(
        """
╔═══════════════════════════════════════════════════════╗
║   WebTransport Black-Box Fuzzer - PoC                 ║
║   Using: boofuzz + aioquic                            ║
║   Transport: Bidirectional WebTransport Streams       ║
╚═══════════════════════════════════════════════════════╝
    """
    )
    logger.info("Target: %s", target_url)

    # create connection and target
    connection = WebTransportConnection(target_url, timeout=3.0)

    # Attach our EchoCompareMonitor to the Target's monitors list.
    # crash_on_mismatch=True makes the monitor return False on mismatch/no-response,
    # which boofuzz will treat as a failure (and may restart the target).
    echo_monitor = EchoCompareMonitor(crash_on_mismatch=True)
    target = Target(connection=connection, monitors=[echo_monitor])

    # create session
    session = Session(
        target=target,
        fuzz_loggers=[FuzzLoggerText()],
        sleep_time=1.0,
        restart_sleep_time=2.0,
        reuse_target_connection=False,
    )

    # build protocol model
    msg = define_protocol()
    session.connect(msg)

    logger.info("Starting fuzzing session")
    logger.info("Web UI available at: http://localhost:26000 (if enabled)")
    logger.info("Press Ctrl+C to stop")

    try:
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing stopped by user")
    except Exception:
        logger.exception("Fuzzing encountered an error")
    finally:
        logger.info("Fuzzing session finished")


if __name__ == "__main__":
    main()
