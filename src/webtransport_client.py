"""
aioquic-based WebTransport client used by the fuzzer.

A single ``WebTransportClient`` instance owns one QUIC connection, one
HTTP/3 connection, and one WebTransport session (CONNECT stream). It
exposes the four data-plane primitives the fuzzer needs:

* ``send_bidirectional_stream`` — open a bidi stream, send, await echo.
* ``send_unidirectional_stream`` — open a uni stream, send.
* ``send_datagram``               — send a QUIC datagram.
* ``send_capsule``                — write a raw capsule on the CONNECT stream.

For server-echoed data plane primitives (uni, datagram), the matching
``receive_*_echo`` helpers wait for the next message of that type on the
shared queue.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional, Tuple

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    HeadersReceived,
    H3Event,
    WebTransportStreamDataReceived,
)
from aioquic.quic.events import QuicEvent, StreamDataReceived

logger = logging.getLogger(__name__)


class WebTransportClient(QuicConnectionProtocol):
    """WebTransport-over-HTTP/3 client protocol handler."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._session_id: Optional[int] = None
        self._session_established = asyncio.Event()

        # Per-stream response queues for tracked bidirectional streams.
        self._bidi_response_queues: Dict[int, asyncio.Queue] = {}

        # Server-pushed data not tied to a tracked bidi stream:
        #   - WebTransportStreamDataReceived from server-opened uni streams
        #   - DatagramReceived
        # Tuples on the queue: ("stream", stream_id, data) | ("datagram", data).
        self._inbound: asyncio.Queue = asyncio.Queue()

    # -- aioquic event handlers ----------------------------------------------------

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            queue = self._bidi_response_queues.get(event.stream_id)
            if queue is not None:
                queue.put_nowait(("data", event.data))
                if event.end_stream:
                    queue.put_nowait(("end", None))

        if self._http is None:
            self._http = H3Connection(self._quic, enable_webtransport=True)

        for h3_event in self._http.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event):
        if isinstance(event, HeadersReceived):
            status = dict(event.headers).get(b":status", b"")
            if status == b"200":
                logger.info(
                    "WebTransport session established (stream %d)", event.stream_id
                )
                self._session_id = event.stream_id
                self._session_established.set()
            else:
                logger.error("WebTransport session failed; status=%s", status.decode())

        elif isinstance(event, DatagramReceived):
            self._inbound.put_nowait(("datagram", event.data))

        elif isinstance(event, WebTransportStreamDataReceived):
            self._inbound.put_nowait(("stream", event.stream_id, event.data))

    # -- session establishment -----------------------------------------------------

    async def establish_session(self, authority: str, path: str = "/echo"):
        """Send the WebTransport CONNECT request and wait for the 200 response."""
        stream_id = self._quic.get_next_available_stream_id()

        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b":protocol", b"webtransport"),
        ]
        logger.info("Establishing WebTransport session to %s%s", authority, path)
        self._http.send_headers(stream_id, headers)
        self.transmit()

        await asyncio.wait_for(self._session_established.wait(), timeout=5.0)
        logger.info("WebTransport session ready")

    # -- send primitives -----------------------------------------------------------

    def send_capsule(self, data: bytes):
        """Write raw capsule bytes on the CONNECT (session control) stream."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        self._quic.send_stream_data(
            stream_id=self._session_id, data=data, end_stream=False
        )
        self.transmit()
        logger.debug(
            "Sent capsule on CONNECT stream %d: %d bytes", self._session_id, len(data)
        )

    def send_datagram(self, data: bytes):
        """Send a QUIC datagram on the WebTransport session."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        self._http.send_datagram(stream_id=self._session_id, data=data)
        self.transmit()
        logger.debug("Sent datagram: %d bytes", len(data))

    async def send_unidirectional_stream(self, data: bytes) -> int:
        """Open a uni WebTransport stream, send ``data``, return the stream id."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        stream_id = self._http.create_webtransport_stream(
            session_id=self._session_id, is_unidirectional=True
        )
        self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=True)
        self.transmit()
        logger.debug("Sent uni stream %d: %d bytes", stream_id, len(data))
        return stream_id

    async def send_bidirectional_stream(
        self, data: bytes, timeout: float = 5.0
    ) -> Tuple[int, Optional[bytes]]:
        """
        Open a bidi WebTransport stream, send ``data``, wait for the echo.

        Returns ``(stream_id, response_or_None)``. ``None`` on timeout or
        if the server closes the stream without sending data.
        """
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        stream_id = self._http.create_webtransport_stream(
            session_id=self._session_id, is_unidirectional=False
        )
        queue: asyncio.Queue = asyncio.Queue()
        self._bidi_response_queues[stream_id] = queue
        try:
            self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=True)
            self.transmit()
            try:
                event_type, payload = await asyncio.wait_for(
                    queue.get(), timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.debug("Bidi stream %d: timeout waiting for echo", stream_id)
                return stream_id, None
            if event_type == "data":
                # Drain the trailing "end" event if it arrives soon.
                try:
                    await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    pass
                return stream_id, payload
            return stream_id, None
        finally:
            self._bidi_response_queues.pop(stream_id, None)

    # -- echo receive helpers (for uni / datagram steps) ---------------------------

    async def receive_stream_echo(self, timeout: float = 1.0) -> Optional[bytes]:
        """Return the next server-pushed stream payload, or ``None`` on timeout."""
        return await self._next_inbound("stream", timeout)

    async def receive_datagram_echo(self, timeout: float = 1.0) -> Optional[bytes]:
        """Return the next server-pushed datagram, or ``None`` on timeout."""
        return await self._next_inbound("datagram", timeout)

    async def _next_inbound(self, kind: str, timeout: float) -> Optional[bytes]:
        try:
            msg = await asyncio.wait_for(self._inbound.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        if msg[0] != kind:
            # Wrong kind — push it back so the right consumer can pick it up.
            self._inbound.put_nowait(msg)
            return None
        # ("stream", stream_id, data) or ("datagram", data)
        return msg[-1]
