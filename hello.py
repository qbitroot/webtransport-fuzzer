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
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def interactive_mode(client: WebTransportClient):
    """Interactive mode for sending messages."""
    print("\n" + "=" * 60)
    print("WebTransport Echo Client - Interactive Mode")
    print("=" * 60)
    print("Commands:")
    print("  d <message>  - Send datagram")
    print("  u <message>  - Send unidirectional stream")
    print("  b <message>  - Send bidirectional stream")
    print("  x <hex>      - Send raw capsule (hex bytes on CONNECT stream)")
    print("  q            - Quit")
    print("=" * 60 + "\n")

    while True:
        try:
            command = await asyncio.get_event_loop().run_in_executor(
                None, input, ">>> "
            )
            command = command.strip()

            if not command:
                continue

            if command.startswith("q"):
                print("Exiting...")
                break

            parts = command.split(" ", 1)
            if len(parts) < 2:
                print("Invalid command. Use: <d|u|b|x> <message>")
                continue

            cmd_type, message = parts

            if cmd_type == "x":
                # Raw capsule: parse hex string into bytes, send on CONNECT stream
                hex_str = message.replace(" ", "").replace("0x", "").replace(",", "")
                try:
                    data = bytes.fromhex(hex_str)
                except ValueError as e:
                    print(f"Invalid hex: {e}")
                    continue
                client.send_capsule(data)
                logger.info("Sent raw capsule (%d bytes): %s", len(data), data.hex())
            else:
                data = message.encode("utf-8")

                if cmd_type == "d":
                    client.send_datagram(data)
                    logger.info("Sent datagram: %s", message)
                    echo = await client.receive_datagram(timeout=2.0)
                    _check_echo("datagram", data, echo)
                elif cmd_type == "u":
                    await client.send_unidirectional_stream(data)
                    logger.info("Sent unidirectional stream: %s", message)
                    result = await client.receive_stream_data(timeout=2.0)
                    echo = result[1] if result else None
                    _check_echo("uni stream", data, echo)
                elif cmd_type == "b":
                    stream_id, response = await client.send_bidirectional_stream(data)
                    logger.info("Sent bidirectional stream: %s", message)
                    _check_echo("bidi stream", data, response)
                else:
                    print(f"Unknown command: {cmd_type}")

            await asyncio.sleep(0.1)

        except EOFError:
            break
        except Exception as e:
            logger.error("Error in interactive mode: %s", e)


def _check_echo(test_name: str, sent: bytes, received: bytes | None) -> bool:
    """Compare sent vs received bytes and log the result. Returns True on match."""
    if received is None:
        logger.error("%s: FAIL - no response received", test_name)
        return False
    if received == sent:
        logger.info("%s: PASS - echo matches (%d bytes)", test_name, len(received))
        return True
    logger.error(
        "%s: FAIL - echo mismatch\n  sent:     %s\n  received: %s",
        test_name,
        sent,
        received,
    )
    return False


async def demo_mode(client: WebTransportClient):
    """Automated demo mode."""
    logger.info("\n" + "=" * 60)
    logger.info("Running automated demo...")
    logger.info("=" * 60 + "\n")

    passed = 0
    failed = 0

    # Test 1: Send a datagram and verify echo
    logger.info("Test 1: Sending datagram...")
    dgram_payload = b"Hello via datagram!"
    client.send_datagram(dgram_payload)
    echo = await client.receive_datagram(timeout=2.0)
    if _check_echo("Test 1 (datagram)", dgram_payload, echo):
        passed += 1
    else:
        failed += 1

    # Test 2: Send unidirectional stream and verify echo on new uni stream
    logger.info("\nTest 2: Sending unidirectional stream...")
    uni_payload = b"Hello via unidirectional stream!"
    await client.send_unidirectional_stream(uni_payload)
    result = await client.receive_stream_data(timeout=2.0)
    echo = result[1] if result else None
    if _check_echo("Test 2 (uni stream)", uni_payload, echo):
        passed += 1
    else:
        failed += 1

    # Test 3: Send bidirectional stream and verify echo
    logger.info("\nTest 3: Sending bidirectional stream...")
    bidi_payload = b"Hello via bidirectional stream!"
    stream_id, response = await client.send_bidirectional_stream(bidi_payload)
    if _check_echo("Test 3 (bidi stream)", bidi_payload, response):
        passed += 1
    else:
        failed += 1

    # Test 4: Multiple datagrams - send all then verify all echoes
    logger.info("\nTest 4: Sending multiple datagrams...")
    dgram_payloads = [f"Datagram #{i + 1}".encode() for i in range(3)]
    for payload in dgram_payloads:
        client.send_datagram(payload)
        await asyncio.sleep(0.1)

    # Collect all echoed datagrams
    received_dgrams: list[bytes] = []
    for _ in dgram_payloads:
        echo = await client.receive_datagram(timeout=2.0)
        if echo is not None:
            received_dgrams.append(echo)

    # Check that every sent datagram was echoed (order may vary)
    sent_set = sorted(dgram_payloads)
    recv_set = sorted(received_dgrams)
    if sent_set == recv_set:
        logger.info(
            "Test 4 (multi-datagram): PASS - all %d datagrams echoed correctly",
            len(dgram_payloads),
        )
        passed += 1
    else:
        logger.error(
            "Test 4 (multi-datagram): FAIL\n  sent:     %s\n  received: %s",
            sent_set,
            recv_set,
        )
        failed += 1

    await asyncio.sleep(0.5)
    logger.info("\n" + "=" * 60)
    logger.info("Demo complete!  %d passed, %d failed", passed, failed)
    logger.info("=" * 60)


async def main():
    # Get mkcert CA root path
    import os

    # Use system CA bundle (includes mkcert CA after mkcert -install)
    system_ca = "/etc/ssl/certs/ca-certificates.crt"

    parser = argparse.ArgumentParser(description="WebTransport Echo Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server hostname")
    parser.add_argument("--port", type=int, default=6161, help="Server port")
    parser.add_argument("--path", default="/echo", help="WebTransport endpoint path")
    parser.add_argument(
        "--ca-cert",
        default=system_ca,
        help="CA certificate for TLS verification (default: system CA bundle)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="Skip certificate verification (for self-signed certs)",
    )
    parser.add_argument(
        "--interactive", "-i", action="store_true", help="Run in interactive mode"
    )
    args = parser.parse_args()

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,
    )

    if args.insecure:
        config.verify_mode = False
        logger.warning("Certificate verification disabled (insecure mode)")
    elif args.ca_cert and os.path.exists(args.ca_cert):
        config.load_verify_locations(args.ca_cert)
        logger.info("Loaded CA certificate from: %s", args.ca_cert)
    else:
        logger.warning(
            "CA certificate not found at %s, connection may fail", args.ca_cert
        )

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
