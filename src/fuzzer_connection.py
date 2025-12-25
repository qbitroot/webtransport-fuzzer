"""
WebTransport connection wrapper for boofuzz fuzzing.
"""

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from boofuzz.connections import ITargetConnection

from src.webtransport_client import WebTransportClient

logger = logging.getLogger(__name__)


class WebTransportConnection(ITargetConnection):
    """
    boofuzz ITargetConnection implementation using aioquic WebTransport streams.

    It stores last sent/received data on the object, so the monitor
    can inspect and compare them.
    """

    def __init__(self, url: str, timeout: float = 3.0):
        self.url = url
        self.timeout = timeout
        self._protocol: Optional[WebTransportClient] = None
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
            verify_mode=False,
            max_datagram_frame_size=65536,
        )
        self._client_context = connect(
            self.host,
            self.port,
            configuration=config,
            create_protocol=WebTransportClient,
        )
        self._protocol = await self._client_context.__aenter__()
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

    @property
    def session_id(self) -> Optional[int]:
        if self._protocol:
            return self._protocol._session_id
        return None

    def send(self, data: bytes) -> int:
        """
        Send fuzzed data via a new raw unidirectional stream.
        This assumes 'data' contains the HTTP/3 Stream Type + Session ID + Payload.
        """
        if not self._loop or not self._protocol:
            raise RuntimeError("Connection not open")

        # Dynamic Session ID is now handled by src.callbacks.callback_fill_session_id
        # verifying and updating the Boofuzz graph before serialization.
        pass

        target_len = len(data)
        preview = data[:100] if target_len > 100 else data
        logger.debug("Sending %d raw bytes: %s", target_len, preview)
        
        self._last_sent_data = data
        self._last_received_data = None

        try:
            # Create a raw unidirectional stream (bypassing H3 tracking)
            # We assume the fuzzed data includes the Stream Type (e.g. 0x54).
            stream_id = self._loop.run_until_complete(
                self._async_send_raw(data)
            )
            return target_len
        except Exception:
            logger.exception("Exception during send")
            raise

    async def _async_send_raw(self, data: bytes) -> int:
        # Create raw stream
        stream_id = self._protocol.create_raw_stream(is_unidirectional=True)
        # Send data and close stream immediately (message-style)
        self._protocol.send_raw_stream(stream_id, data, end_stream=True)
        return stream_id

    def recv(self, max_bytes: int) -> bytes:
        """
        Receive data from the WebTransport session.
        This blocks until data is available or timeout.
        """
        if not self._loop or not self._protocol:
            return b""
        
        try:
            data = self._loop.run_until_complete(self._async_recv(timeout=1.0))
            if data:
                # Ensure the monitor can see what we received, even if Boofuzz target doesn't set it in feature_check
                self._last_received_data = data[:max_bytes]
                return self._last_received_data
            
            self._last_received_data = b""
            return b""
        except Exception as e:
            logger.warning("Error receiving data: %s", e)
            return b""

    async def _async_recv(self, timeout: float = 1.0) -> bytes:
        """Async helper to fetch next message from protocol queue."""
        if not self._protocol:
            return b""
        
        # Accumulate data until timeout expiration (or small silence)
        # For fuzzing, we often want "everything sent in response to my input"
        buffer = bytearray()
        end_time = asyncio.get_event_loop().time() + timeout
        
        while True:
            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            
            try:
                # Use a shorter wait for subsequent chunks
                current_wait = remaining
                if len(buffer) > 0:
                     # If we already have data, wait less for more (aggregating)
                     current_wait = min(0.1, remaining)

                queue = self._protocol._received_messages
                type_, *args = await asyncio.wait_for(queue.get(), timeout=current_wait)
                
                if type_ == 'stream':
                    stream_id, data = args
                    logger.debug("Async Recv: Stream %d data: %s", stream_id, data)
                    buffer.extend(data)
                elif type_ == 'datagram':
                    data = args[0]
                    logger.debug("Async Recv: Datagram: %s", data)
                    buffer.extend(data)
            except asyncio.TimeoutError:
                break
            except Exception as e:
                logger.warning("Async recv exception: %s", e)
                break
        
        return bytes(buffer)
