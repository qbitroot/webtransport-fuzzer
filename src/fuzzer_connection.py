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
    
    Supports multiple send modes:
    - 'unidirectional': Raw unidirectional stream (default)
    - 'bidirectional': Bidirectional stream with response
    - 'datagram': Unreliable datagram
    """

    def __init__(self, url: str, timeout: float = 1.0, send_mode: str = "unidirectional"):
        self.url = url
        self.timeout = timeout
        self._send_mode = send_mode
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

        logger.info("WebTransportConnection initialized for %s (mode: %s)", url, send_mode)

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
            # Clean logging here is redundant if we re-raise wrapped errors
            # logger.exception("Failed to open connection") 
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
        try:
            self._protocol = await asyncio.wait_for(
                self._client_context.__aenter__(), 
                timeout=self.timeout
            )
            await asyncio.wait_for(
                self._protocol.establish_session(self.authority, self.path),
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            raise ConnectionError("Server Unreachable (Timeout)") from None
        except Exception as e:
            # Ensure we clean up the context if something else broke
            try:
                 pass
            except:
                pass
            raise ConnectionError(f"Server Unreachable (Error: {e})") from e

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
        Send fuzzed data via the configured send mode.
        Dispatches to unidirectional, bidirectional, or datagram based on _send_mode.
        """
        if not self._loop or not self._protocol:
            raise RuntimeError("Connection not open")

        target_len = len(data)
        preview = data[:100] if target_len > 100 else data
        logger.debug("Sending %d bytes via %s: %s", target_len, self._send_mode, preview)
        
        self._last_sent_data = data
        self._last_received_data = None

        try:
            if self._send_mode == "bidirectional":
                self._loop.run_until_complete(self._async_send_bidirectional(data))
            elif self._send_mode == "datagram":
                self._loop.run_until_complete(self._async_send_datagram(data))
            elif self._send_mode == "capsule":
                self._loop.run_until_complete(self._async_send_capsule(data))
            else:  # Default: unidirectional
                self._loop.run_until_complete(self._async_send_unidirectional(data))
            return target_len
        except Exception:
            logger.exception("Exception during send")
            raise

    async def _async_send_unidirectional(self, data: bytes) -> int:
        """Send via raw unidirectional stream (default fuzzing mode)."""
        stream_id = self._protocol.create_raw_stream(is_unidirectional=True)
        self._protocol.send_raw_stream(stream_id, data, end_stream=True)
        return stream_id

    async def _async_send_bidirectional(self, data: bytes) -> int:
        """Send via bidirectional stream and capture response."""
        stream_id = self._protocol.create_raw_stream(is_unidirectional=False)
        self._protocol.send_raw_stream(stream_id, data, end_stream=True)
        # Note: Response is captured via recv() if needed
        return stream_id

    async def _async_send_datagram(self, data: bytes):
        """Send via unreliable datagram."""
        if self._protocol._session_id is None:
            raise RuntimeError("Session not established for datagram")
        self._protocol.send_datagram(data)

    async def _async_send_capsule(self, data: bytes):
        """Send capsule on CONNECT stream (control channel)."""
        if self._protocol._session_id is None:
            raise RuntimeError("Session not established for capsule")
        self._protocol.send_capsule(data)

    def recv(self, max_bytes: int) -> bytes:
        """
        Receive data from the WebTransport session.
        This blocks until data is available or timeout.
        """
        if not self._loop or not self._protocol:
            return b""
        
        try:
            data = self._loop.run_until_complete(self._async_recv(timeout=0.1))
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

    def send_health_check(self) -> bool:
        """
        Send a synchronous health check (bidirectional stream ping)
        to verify if the server is still alive and responsive.
        
        Returns:
            True if health check succeeds (server responded), False otherwise.
        """
        if not self._loop or not self._protocol:
            logger.error("Health check skipped: connection not open")
            return False

        async def _health_check():
            try:
                # Send explicit health check payload
                sid, response = await self._protocol.send_bidirectional_stream(b"HEALTHCHECK", timeout=1.0)
                if response:
                    logger.debug("Health check response: %s", response)
                    return True
                return False
            except Exception as e:
                logger.warning("Health check failed: %s", e)
                return False

        try:
            return self._loop.run_until_complete(_health_check())
        except Exception:
            logger.exception("Health check wrapper exception")
            return False
