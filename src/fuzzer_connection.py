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
            return len(data)
        except Exception:
            logger.exception("Exception during send")
            raise

    def recv(self, max_bytes: int) -> bytes:
        """Return previously stored response (up to max_bytes)."""
        if self._last_received_data:
            return self._last_received_data[:max_bytes]
        return b""
