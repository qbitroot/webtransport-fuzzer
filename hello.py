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

from aioquic.asyncio import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from src.webtransport_client import WebTransportClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


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
                logger.info("Sent datagram: %s", message)
            elif cmd_type == 'u':
                await client.send_unidirectional_stream(data)
                logger.info("Sent unidirectional stream: %s", message)
            elif cmd_type == 'b':
                stream_id, response = await client.send_bidirectional_stream(data)
                logger.info("Sent bidirectional stream: %s", message)
                if response:
                    logger.info("Received response: %s", response.decode('utf-8', errors='ignore'))
            else:
                print(f"Unknown command: {cmd_type}")
            
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
    stream_id, response = await client.send_bidirectional_stream(b"Hello via bidirectional stream!")
    if response:
        logger.info("Received response: %s", response.decode('utf-8', errors='ignore'))
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

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,
    )
    
    if args.insecure:
        config.verify_mode = False
        logger.warning("Certificate verification disabled (insecure mode)")

    authority = f"{args.host}:{args.port}"
    
    logger.info("Connecting to https://%s%s", authority, args.path)

    async with connect(
        args.host,
        args.port,
        configuration=config,
        create_protocol=WebTransportClient,
    ) as client:
        await client.establish_session(authority, args.path)
        
        if args.interactive:
            await interactive_mode(client)
        else:
            await demo_mode(client)
        
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
