#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time

from boofuzz import Session, Target, FuzzLoggerText
from boofuzz.fuzz_logger_db import FuzzLoggerDb

from src.fuzzer_connection import WebTransportConnection
from src.echo_monitor import EchoCompareMonitor, ServerDownError
from src.boofuzz_definitions import define_oneshot_capsule

# ---- Logging setup ----
LOG_FMT = "%(asctime)s [%(levelname)5s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
logger = logging.getLogger("wt_fuzzer")
logging.getLogger("tornado.access").setLevel(logging.WARNING)

# ---- Helper: ensure failure dir exists ----
FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description="WebTransport One-Shot Fuzzer")
    parser.add_argument("--url", default="https://0.0.0.0:6161/echo", help="Target URL")
    parser.add_argument("--no-fuzz", action="store_true", help="Run in validation mode (health check only)")
    parser.add_argument(
        "--mode",
        choices=["oneshot"],
        default="oneshot",
        help="Fuzzing mode (default: oneshot)"
    )
    parser.add_argument(
        "--fuzz-payload",
        action="store_true",
        help="Also fuzz payload content (default: only fuzz packet structure)"
    )
    parser.add_argument(
        "--start-index",
        type=int,
        default=1,
        help="Start fuzzing from this test case index"
    )
    parser.add_argument(
        "--end-index",
        type=int,
        help="Stop fuzzing after this test case index"
    )
    args = parser.parse_args()

    target_url = args.url

    print(
        """
    ╔═══════════════════════════════════════════════════════╗
    ║   WebTransport One-Shot Fuzzer - Protocol Level        ║
    ║   Target: WebTransport over HTTP/3 Framing             ║
    ║   Mode: One-Shot (fuzz → health check per request)     ║
    ╚═══════════════════════════════════════════════════════╝
    """
    )
    logger.info("Target: %s", target_url)

    if args.no_fuzz:
        logger.info("Running in VALIDATION MODE (--no-fuzz)")
        connection = WebTransportConnection(target_url, timeout=3.0)
        
        try:
            connection.open()

            logger.info("Sending Health Check (Standard Probe)...")
            success = connection.send_health_check()
            
            if success:
                logger.info("Validation SUCCESS: Server responded to health check.")
            else:
                logger.error("Validation FAILED: Server did not respond to health check.")
            
            connection.close()
        except Exception:
            logger.exception("Validation encountered an error")
            
    else:
        logger.info("Running in ONE-SHOT FUZZING MODE")
        logger.info("Press Ctrl+C to stop")

        # Single connection — always capsule mode (writes to CONNECT stream)
        connection = WebTransportConnection(
            target_url, 
            timeout=3.0, 
            send_mode="capsule"
        )
        
        echo_monitor = EchoCompareMonitor(crash_on_mismatch=True)
        target = Target(connection=connection, monitors=[echo_monitor])

        # Database logger
        db_filename = os.path.join("boofuzz-results", f"run_{int(time.time())}.db")
        db_logger = FuzzLoggerDb(db_filename=db_filename)
        logger.info(f"Logging results to {db_filename}")

        session = Session(
            target=target,
            fuzz_loggers=[FuzzLoggerText(), db_logger],
            sleep_time=0.0,
            restart_sleep_time=0.0,
            reuse_target_connection=False,
            index_start=args.start_index,
            index_end=args.end_index,
        )

        # Single boofuzz node for one-shot capsule fuzzing
        msg = define_oneshot_capsule(
            session_name="wt_oneshot",
            fuzz_payload=args.fuzz_payload
        )
        session.connect(msg)

        try:
            session.fuzz()
        except KeyboardInterrupt:
            logger.info("Fuzzing stopped by user")
        except ServerDownError as e:
            logger.critical(f"Fuzzing ABORTED: {e}")
            sys.exit(1)
        except (TimeoutError, ConnectionError, RuntimeError) as e:
            logger.error(f"Fuzzing halted: {e}")
        except Exception:
            logger.exception("Fuzzing encountered an unexpected error")
        finally:
            logger.info("Fuzzing session finished")


if __name__ == "__main__":
    main()
