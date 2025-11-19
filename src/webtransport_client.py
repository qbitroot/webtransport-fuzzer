"""
WebTransport client wrapper for aioquic.
Provides a reusable WebTransport client implementation.
"""

import asyncio
import logging
from typing import Optional, Dict, Tuple

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    HeadersReceived,
    WebTransportStreamDataReceived,
    H3Event,
)
from aioquic.quic.events import QuicEvent, StreamDataReceived

logger = logging.getLogger(__name__)


class WebTransportClient(QuicConnectionProtocol):
    """
    WebTransport client protocol handler.
    Manages WebTransport session over HTTP/3.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._session_id: Optional[int] = None
        self._session_established = asyncio.Event()
        self._received_messages = asyncio.Queue()
        self._authority: Optional[str] = None
        self._bidirectional_streams: Dict[int, asyncio.Queue] = {}

    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events and pass them to H3Connection."""
        if isinstance(event, StreamDataReceived):
            if event.stream_id in self._bidirectional_streams:
                logger.debug("Received data on tracked bidirectional stream %d", event.stream_id)
                self._bidirectional_streams[event.stream_id].put_nowait(('data', event.data))
                
                if event.end_stream:
                    logger.debug("Stream %d closed by server", event.stream_id)
                    self._bidirectional_streams[event.stream_id].put_nowait(('end', None))
        
        if self._http is None:
            self._http = H3Connection(self._quic, enable_webtransport=True)

        for h3_event in self._http.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event):
        """Handle HTTP/3 events."""
        if isinstance(event, HeadersReceived):
            headers_dict = dict(event.headers)
            status = headers_dict.get(b":status", b"")
            
            if status == b"200":
                logger.info("WebTransport session established (stream %d)", event.stream_id)
                self._session_id = event.stream_id
                self._session_established.set()
            else:
                logger.error("WebTransport session failed with status: %s", status.decode())
                logger.error("Headers: %s", headers_dict)

        elif isinstance(event, DatagramReceived):
            message = event.data
            logger.debug("Datagram received: %d bytes", len(message))
            self._received_messages.put_nowait(('datagram', message))

        elif isinstance(event, WebTransportStreamDataReceived):
            logger.debug("Stream data received (stream %d): %d bytes", event.stream_id, len(event.data))
            self._received_messages.put_nowait(('stream', event.stream_id, event.data))

            if event.stream_ended:
                logger.debug("Stream %d closed by server", event.stream_id)

    async def establish_session(self, authority: str, path: str = "/echo"):
        """Establish a WebTransport session."""
        self._authority = authority
        
        stream_id = self._quic.get_next_available_stream_id()
        
        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b":protocol", b"webtransport"),
            (b"sec-webtransport-http3-draft", b"draft02"),
        ]
        
        logger.info("Establishing WebTransport session to %s%s", authority, path)
        self._http.send_headers(stream_id, headers)
        self.transmit()
        
        await asyncio.wait_for(self._session_established.wait(), timeout=5.0)
        logger.info("WebTransport session ready")

    def send_datagram(self, data: bytes):
        """Send a datagram over WebTransport."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        
        self._http.send_datagram(stream_id=self._session_id, data=data)
        self.transmit()
        logger.debug("Sent datagram: %d bytes", len(data))

    async def send_unidirectional_stream(self, data: bytes):
        """Send data on a unidirectional WebTransport stream."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        
        stream_id = self._http.create_webtransport_stream(
            session_id=self._session_id,
            is_unidirectional=True
        )
        
        self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=True)
        self.transmit()
        logger.debug("Sent unidirectional stream (stream %d): %d bytes", stream_id, len(data))

    async def send_bidirectional_stream(self, data: bytes, timeout: float = 5.0) -> Tuple[int, Optional[bytes]]:
        """Send data on a bidirectional WebTransport stream and wait for response."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        
        stream_id = self._http.create_webtransport_stream(
            session_id=self._session_id,
            is_unidirectional=False
        )
        
        response_queue = asyncio.Queue()
        self._bidirectional_streams[stream_id] = response_queue
        
        logger.debug("Opened bidirectional stream #%d with %d bytes", stream_id, len(data))
        
        try:
            self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=True)
            self.transmit()
            
            event_type, response = await asyncio.wait_for(response_queue.get(), timeout=timeout)
            
            if event_type == 'data' and response:
                logger.debug("Bidirectional stream %d response received: %d bytes", stream_id, len(response))
                
                try:
                    end_event = await asyncio.wait_for(response_queue.get(), timeout=1.0)
                    if end_event[0] == 'end':
                        logger.debug("Bidirectional stream %d ended", stream_id)
                except asyncio.TimeoutError:
                    logger.debug("No explicit end event for stream %d", stream_id)
                
                return stream_id, response
            elif event_type == 'end':
                logger.debug("Bidirectional stream %d completed (stream ended without data)", stream_id)
                return stream_id, None
            else:
                logger.warning("Unexpected event on bidirectional stream %d", stream_id)
                return stream_id, None
            
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for response on bidirectional stream %d", stream_id)
            return stream_id, None
        finally:
            if stream_id in self._bidirectional_streams:
                del self._bidirectional_streams[stream_id]
