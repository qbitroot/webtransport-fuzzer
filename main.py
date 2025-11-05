#!/usr/bin/env python3
"""
WebTransport Protocol Fuzzer using boofuzz and aioquic (Black-box approach)
Simple POC targeting WebTransport echo server
"""

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, ProtocolNegotiated
from aioquic.quic.connection import stream_is_unidirectional

import boofuzz
from boofuzz import Session, Target
from boofuzz.connections import ITargetConnection


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress noisy tornado logs from boofuzz web interface
logging.getLogger('tornado.access').setLevel(logging.WARNING)


class WebTransportClientProtocol(QuicConnectionProtocol):
    """
    Black-box WebTransport client protocol handler.
    Handles HTTP/3 connection and WebTransport session establishment.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._session_id = None
        self._session_established = asyncio.Event()
        self._received_data = {}
        self._authority = None
        self._path = None
        
    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events."""
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic, enable_webtransport=True)
        
        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                self._h3_event_received(h3_event)
    
    def _h3_event_received(self, event: H3Event):
        """Handle HTTP/3 events."""
        if isinstance(event, HeadersReceived):
            headers = dict(event.headers)
            status = headers.get(b":status", b"")
            
            if status == b"200":
                logger.info(f"WebTransport session established (stream {event.stream_id})")
                self._session_id = event.stream_id
                self._session_established.set()
            else:
                logger.error(f"WebTransport handshake failed: {status}")
                
        elif isinstance(event, WebTransportStreamDataReceived):
            logger.debug(f"Received {len(event.data)} bytes on stream {event.stream_id}")
            if event.stream_id not in self._received_data:
                self._received_data[event.stream_id] = b""
            self._received_data[event.stream_id] += event.data
    
    async def establish_session(self, authority: str, path: str):
        """Establish WebTransport session via HTTP/3 CONNECT."""
        self._authority = authority
        self._path = path
        
        # Get a stream ID for the CONNECT request
        stream_id = self._quic.get_next_available_stream_id()
        
        # Send CONNECT request
        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b":protocol", b"webtransport"),
            (b"sec-webtransport-http3-draft", b"draft02"),
        ]
        
        self._http.send_headers(stream_id=stream_id, headers=headers)
        self.transmit()
        
        # Wait for session establishment
        try:
            await asyncio.wait_for(self._session_established.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            raise RuntimeError("WebTransport session establishment timeout")
    
    def send_stream_data(self, data: bytes):
        """Send data on a bidirectional WebTransport stream."""
        if not self._session_id or not self._http:
            raise RuntimeError("Session not established")
        
        # Create new bidirectional stream
        stream_id = self._http.create_webtransport_stream(
            self._session_id,
            is_unidirectional=False
        )
        
        # Send data
        self._http._quic.send_stream_data(stream_id, data, end_stream=True)
        self.transmit()
        
        return stream_id
    
    def get_received_data(self):
        """Get all received data and clear buffer."""
        data = self._received_data.copy()
        self._received_data.clear()
        return data


class WebTransportConnection(ITargetConnection):
    """
    Black-box boofuzz connection for WebTransport.
    """
    
    def __init__(self, url: str, timeout: float = 3.0):
        self.url = url
        self.timeout = timeout
        self._protocol = None
        self._loop = None
        self._client_context = None
        
        # Parse URL
        parsed = urlparse(url)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or "/"
        self.authority = f"{self.host}:{self.port}"
        
        logger.info(f"Initialized fuzzer for {url}")
    
    @property
    def info(self) -> str:
        return f"WebTransport({self.url})"
    
    def open(self):
        """Open WebTransport connection."""
        logger.info(f"Connecting to {self.host}:{self.port}{self.path}")
        
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        
        try:
            self._loop.run_until_complete(self._async_open())
            logger.info("Connection established")
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            raise
    
    async def _async_open(self):
        """Async connection establishment."""
        configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=True,
            verify_mode=False  # Disable cert verification for testing
        )
        
        # Connect
        self._client_context = connect(
            self.host,
            self.port,
            configuration=configuration,
            create_protocol=WebTransportClientProtocol,
        )
        
        self._protocol = await self._client_context.__aenter__()
        
        # Establish WebTransport session
        await self._protocol.establish_session(self.authority, self.path)
    
    def close(self):
        """Close connection."""
        logger.info("Closing connection")
        
        if self._loop and self._client_context:
            try:
                self._loop.run_until_complete(
                    self._client_context.__aexit__(None, None, None)
                )
            except Exception as e:
                logger.debug(f"Close error: {e}")
            finally:
                self._loop.close()
                self._loop = None
                self._protocol = None
    
    def send(self, data: bytes) -> int:
        """Send fuzzed data."""
        if not self._loop or not self._protocol:
            raise RuntimeError("Connection not open")
        
        logger.debug(f"Sending {len(data)} bytes")
        
        try:
            self._protocol.send_stream_data(data)
            return len(data)
        except Exception as e:
            logger.error(f"Send failed: {e}")
            raise
    
    def recv(self, max_bytes: int) -> bytes:
        """Receive response data."""
        if not self._loop or not self._protocol:
            return b""
        
        try:
            # Give server time to respond
            self._loop.run_until_complete(asyncio.sleep(self.timeout))
            
            # Get received data
            received = self._protocol.get_received_data()
            if received:
                all_data = b"".join(received.values())
                return all_data[:max_bytes]
        except Exception as e:
            logger.debug(f"Recv error: {e}")
        
        return b""


def define_protocol():
    """Define the protocol message for fuzzing."""
    boofuzz.s_initialize("webtransport_echo")
    
    # Simple fuzzable text message
    boofuzz.s_string("Hello, WebTransport!", name="message", fuzzable=True)
    
    return boofuzz.s_get("webtransport_echo")


def main():
    """Main fuzzer entry point."""
    # CORRECTED URL with port 6161
    target_url = "https://wt-ord.akaleapi.net:6161/echo"
    
    print("""
╔═══════════════════════════════════════════════════════╗
║   WebTransport Black-Box Fuzzer - PoC                 ║
║   Using: boofuzz + aioquic                            ║
╚═══════════════════════════════════════════════════════╝
    """)
    
    logger.info(f"Target: {target_url}")
    
    # Create connection
    connection = WebTransportConnection(target_url, timeout=2.0)
    
    # Create target
    target = Target(connection=connection)
    
    # Create session
    session = Session(
        target=target,
        fuzz_loggers=[boofuzz.FuzzLoggerText()],
        sleep_time=1.0,
        restart_sleep_time=2.0,
        reuse_target_connection=False,  # New connection each test
    )
    
    # Define protocol
    message = define_protocol()
    session.connect(message)
    
    # Start fuzzing
    logger.info("Starting fuzzing...")
    logger.info("Web UI: http://localhost:26000")
    logger.info("Press Ctrl+C to stop")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("\nStopped by user")
    except Exception as e:
        logger.error(f"Fuzzing error: {e}", exc_info=True)
    finally:
        logger.info("Session complete")


if __name__ == "__main__":
    main()
