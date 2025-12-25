#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time

from boofuzz import Session, Target, FuzzLoggerText

from src.fuzzer_connection import WebTransportConnection
from src.echo_monitor import EchoCompareMonitor
from src.boofuzz_definitions import define_webtransport_protocol, define_valid_webtransport_packet, callback_fill_session_id

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
        logger.info("Opening connection to verify server health directly...")
        
        try:
            # Open generic connection
            connection.open()
            
            # Use the EXACT same check logic that fuzzing uses (DRY)
            logger.info("Sending Health Check (Standard Probe)...")
            success = connection.send_health_check()
            
            if success:
                logger.info("Validation SUCCESS: Server responded to health check.")
            else:
                logger.error("Validation FAILED: Server did not respond to health check.")
            
            # Clean exit
            connection.close()

        except Exception:
            logger.exception("Validation encountered an error")
            
    else:
        logger.info("Running in FUZZING MODE")
        msg = define_webtransport_protocol()
        # Connect with callback to inject session ID dynamically
        session.connect(msg, callback=callback_fill_session_id)

        logger.info("Starting fuzzing session")
        logger.info("Web UI available at: http://localhost:26000 (if enabled)")
        logger.info("Press Ctrl+C to stop")

        try:
            session.fuzz()
        except KeyboardInterrupt:
            logger.info("Fuzzing stopped by user")
        except (TimeoutError, ConnectionError, RuntimeError) as e:
            # Handle known connection/crash errors cleanly without full traceback
            logger.error(f"Fuzzing halted: {e}")
        except Exception:
            logger.exception("Fuzzing encountered an unexpected error")
        finally:
            logger.info("Fuzzing session finished")


if __name__ == "__main__":
    main()
