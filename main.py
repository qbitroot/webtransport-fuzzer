#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time

from boofuzz import Session, Target, FuzzLoggerText

from src.fuzzer_connection import WebTransportConnection
from src.echo_monitor import EchoCompareMonitor
from src.boofuzz_definitions import define_webtransport_protocol, define_valid_webtransport_packet

# ---- Logging setup ----
LOG_FMT = "%(asctime)s [%(levelname)5s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
logger = logging.getLogger("wt_fuzzer")
logging.getLogger("tornado.access").setLevel(logging.WARNING)

# ---- Helper: ensure failure dir exists ----
FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description="WebTransport Fuzzer")
    parser.add_argument("--url", default="https://0.0.0.0:6161/echo", help="Target URL")
    parser.add_argument("--no-fuzz", action="store_true", help="Run in validation mode (send one valid packet)")
    args = parser.parse_args()

    target_url = args.url

    print(
        """
    ╔═══════════════════════════════════════════════════════╗
    ║   WebTransport Black-Box Fuzzer - Protocol Level      ║
    ║   Target: WebTransport over HTTP/3 Framing            ║
    ╚═══════════════════════════════════════════════════════╝
    """
    )
    logger.info("Target: %s", target_url)

    connection = WebTransportConnection(target_url, timeout=3.0)
    
    # We only use the monitor in Fuzzing mode usually, but useful for validation too
    echo_monitor = EchoCompareMonitor(crash_on_mismatch=True)
    target = Target(connection=connection, monitors=[echo_monitor])

    session = Session(
        target=target,
        fuzz_loggers=[FuzzLoggerText()],
        sleep_time=1.0,
        restart_sleep_time=2.0,
        reuse_target_connection=False, 
        # Note: reusing connection for WebTransport fuzzing is tricky due to state.
        # Best to reconnect for each test case for isolation.
    )

    if args.no_fuzz:
        logger.info("Running in VALIDATION MODE (--no-fuzz)")
        logger.info("Sending a single valid WebTransport packet to verify connectivity...")
        
        try:
            connection.open()
            
            # 1. High-Level Check (Control)
            logger.info("--- Phase 1: High-Level Client Check ---")
            payload_hl = b"HelloHighLevel"
            # We access the underlying protocol directly to use high-level methods
            # This requires us to run a small coroutine on the loop
            async def send_hl():
                 await connection._protocol.send_unidirectional_stream(payload_hl)
            
            connection._loop.run_until_complete(send_hl())
            
            # Receive response for High Level
            response = connection.recv(1024)
            logger.info("High-Level Response: %s", response)
            
            if b"HelloHighLevel" in response:
                logger.info("Phase 1 SUCCESS: Server echoed high-level packet.")
            else:
                logger.warning("Phase 1 FAILED: Server did not echo high-level packet.")

            # 2. Low-Level Check (Target)
            logger.info("--- Phase 2: Low-Level (Raw) Check ---")
            # Construct a valid packet manually matching the definition
            # [StreamType (0x54)] + [SessionID placeholder (0xAA)] + [Payload]
            # connection.send will patch the session ID.
            
            # NOTE: For "Hello World" request by user
            target_payload = b"Hello World"
            # Stream Type 0x54 encoded as VarInt (2 bytes): \x40\x54
            raw_payload = b"\x40\x54\xAA" + target_payload
            connection.send(raw_payload)
            
            # Read response
            response = connection.recv(1024)
            logger.info("Low-Level Response: %s", response)
            
            if target_payload in response:
                logger.info("Phase 2 SUCCESS: Server echoed raw packet.")
            else:
                logger.warning("Phase 2 FAILED: Server did not echo raw packet. Debug: Sent header 0x54 + SessionID")
                
        except Exception:
            logger.exception("Validation FAILED")
        finally:
            connection.close()
            
    else:
        logger.info("Running in FUZZING MODE")
        msg = define_webtransport_protocol()
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
