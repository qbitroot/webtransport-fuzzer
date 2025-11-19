#!/usr/bin/env python3
"""
WebTransport over HTTP/3 Echo Client

This client connects to a WebTransport server and demonstrates:
- Sending datagrams
- Opening unidirectional streams
- Opening bidirectional streams
"""

import argparse
import asyncio
import logging
from typing import Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    DataReceived,
    HeadersReceived,
    WebTransportStreamDataReceived,
    H3Event,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
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

    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events and pass them to H3Connection."""
        if self._http is None:
            self._http = H3Connection(self._quic, enable_webtransport=True)

        for h3_event in self._http.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event):
        """Handle HTTP/3 events."""
        if isinstance(event, HeadersReceived):
            # Check if this is the WebTransport session response
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
            # Received a datagram from the server
            message = event.data.decode('utf-8', errors='ignore')
            logger.info("📨 Datagram received: %s", message)
            self._received_messages.put_nowait(('datagram', message))

        elif isinstance(event, WebTransportStreamDataReceived):
            # Received data on a WebTransport stream
            message = event.data.decode('utf-8', errors='ignore')
            logger.info("📨 Stream data received (stream %d): %s", event.stream_id, message)
            self._received_messages.put_nowait(('stream', event.stream_id, message))

            if event.stream_ended:
                logger.info("Stream %d closed by server", event.stream_id)

        elif isinstance(event, DataReceived):
            # Regular HTTP/3 data (not WebTransport stream)
            pass

    async def establish_session(self, authority: str, path: str = "/echo"):
        """Establish a WebTransport session."""
        self._authority = authority
        
        # Create a new bidirectional stream for the CONNECT request
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
        
        # Wait for session to be established
        await asyncio.wait_for(self._session_established.wait(), timeout=5.0)
        logger.info("✅ WebTransport session ready")

    def send_datagram(self, data: bytes):
        """Send a datagram over WebTransport."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        
        # According to aioquic docs, send_datagram takes stream_id and data
        self._http.send_datagram(stream_id=self._session_id, data=data)
        self.transmit()
        logger.info("📤 Sent datagram: %s", data.decode('utf-8', errors='ignore'))

    async def send_unidirectional_stream(self, data: bytes):
        """Send data on a unidirectional WebTransport stream."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        
        # Create a WebTransport stream
        stream_id = self._http.create_webtransport_stream(
            session_id=self._session_id,
            is_unidirectional=True
        )
        
        # Write directly to the QUIC stream
        self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=True)
        self.transmit()
        logger.info("📤 Sent unidirectional stream (stream %d): %s", 
                   stream_id, data.decode('utf-8', errors='ignore'))

    async def send_bidirectional_stream(self, data: bytes):
        """Send data on a bidirectional WebTransport stream."""
        if self._session_id is None:
            raise RuntimeError("WebTransport session not established")
        
        # Create a WebTransport stream
        stream_id = self._http.create_webtransport_stream(
            session_id=self._session_id,
            is_unidirectional=False
        )
        
        # Write directly to the QUIC stream
        self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=True)
        self.transmit()
        logger.info("📤 Sent bidirectional stream (stream %d): %s", 
                   stream_id, data.decode('utf-8', errors='ignore'))
        return stream_id


async def interactive_mode(client: WebTransportClient):
    """Interactive mode for sending messages."""
    print("\n" + "="*60)
    print("WebTransport Echo Client - Interactive Mode")
    print("="*60)
    print("Commands:")
    print("  d <message>  - Send datagram")
    print("  u <message>  - Send unidirectional stream")
    print("  b <message>  - Send bidirectional stream")
    print("  q            - Quit")
    print("="*60 + "\n")

    while True:
        try:
            command = await asyncio.get_event_loop().run_in_executor(
                None, input, ">>> "
            )
            command = command.strip()
            
            if not command:
                continue
            
            if command.startswith('q'):
                print("Exiting...")
                break
            
            parts = command.split(' ', 1)
            if len(parts) < 2:
                print("Invalid command. Use: <d|u|b> <message>")
                continue
            
            cmd_type, message = parts
            data = message.encode('utf-8')
            
            if cmd_type == 'd':
                client.send_datagram(data)
            elif cmd_type == 'u':
                await client.send_unidirectional_stream(data)
            elif cmd_type == 'b':
                await client.send_bidirectional_stream(data)
            else:
                print(f"Unknown command: {cmd_type}")
            
            # Small delay to see responses
            await asyncio.sleep(0.1)
            
        except EOFError:
            break
        except Exception as e:
            logger.error("Error in interactive mode: %s", e)


async def demo_mode(client: WebTransportClient):
    """Automated demo mode."""
    logger.info("\n" + "="*60)
    logger.info("Running automated demo...")
    logger.info("="*60 + "\n")
    
    # Test 1: Send a datagram
    logger.info("Test 1: Sending datagram...")
    client.send_datagram(b"Hello via datagram!")
    await asyncio.sleep(0.5)
    
    # Test 2: Send unidirectional stream
    logger.info("\nTest 2: Sending unidirectional stream...")
    await client.send_unidirectional_stream(b"Hello via unidirectional stream!")
    await asyncio.sleep(0.5)
    
    # Test 3: Send bidirectional stream
    logger.info("\nTest 3: Sending bidirectional stream...")
    await client.send_bidirectional_stream(b"Hello via bidirectional stream!")
    await asyncio.sleep(0.5)
    
    # Test 4: Multiple datagrams
    logger.info("\nTest 4: Sending multiple datagrams...")
    for i in range(3):
        client.send_datagram(f"Datagram #{i+1}".encode())
        await asyncio.sleep(0.2)
    
    await asyncio.sleep(1.0)
    logger.info("\n" + "="*60)
    logger.info("Demo complete!")
    logger.info("="*60)


async def main():
    parser = argparse.ArgumentParser(description="WebTransport Echo Client")
    parser.add_argument("--host", default="wt-ord.akaleapi.net", help="Server hostname")
    parser.add_argument("--port", type=int, default=6161, help="Server port")
    parser.add_argument("--path", default="/echo", help="WebTransport endpoint path")
    parser.add_argument("--insecure", action="store_true", default=False,
                       help="Skip certificate verification (for self-signed certs)")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Run in interactive mode")
    args = parser.parse_args()

    # Configure QUIC with datagram support
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,  # Enable datagram support (required for WebTransport)
    )
    
    if args.insecure:
        config.verify_mode = False
        logger.warning("Certificate verification disabled (insecure mode)")

    # Build authority string (host:port)
    authority = f"{args.host}:{args.port}"
    
    logger.info("Connecting to https://%s%s", authority, args.path)

    # Connect to server
    async with connect(
        args.host,
        args.port,
        configuration=config,
        create_protocol=WebTransportClient,
    ) as client:
        # Establish WebTransport session
        await client.establish_session(authority, args.path)
        
        # Run in interactive or demo mode
        if args.interactive:
            await interactive_mode(client)
        else:
            await demo_mode(client)
        
        # Give time for final responses
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
