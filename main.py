#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time

from boofuzz import Session, Target

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
    parser.add_argument(
        "--no-fuzz",
        action="store_true",
        help="Run in validation mode (health check only)",
    )
    parser.add_argument(
        "--mode",
        choices=["oneshot"],
        default="oneshot",
        help="Fuzzing mode (default: oneshot)",
    )
    parser.add_argument(
        "--no-healthcheck",
        action="store_true",
        help="Disable health checks after each test case",
    )
    parser.add_argument(
        "--start-index",
        type=int,
        default=1,
        help="Start fuzzing from this test case index",
    )
    parser.add_argument(
        "--end-index", type=int, help="Stop fuzzing after this test case index"
    )
    parser.add_argument(
        "--server-cmd",
        type=str,
        default=None,
        help="Shell command to launch the target server as a subprocess (e.g. 'python server.py cert.pem key.pem')",
    )
    parser.add_argument(
        "--server-startup-delay",
        type=float,
        default=1.0,
        help="Seconds to wait after launching server before fuzzing (default: 1.0)",
    )
    parser.add_argument(
        "--server-log-delay",
        type=int,
        default=250,
        help="Milliseconds to wait for server logs after each test case (default: 250)",
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

    # ---- Server subprocess management ----
    server_manager = None
    log_db = None

    if args.server_cmd:
        from src.server_manager import ServerManager
        from src.log_db import LogDB

        server_manager = ServerManager(
            cmd=args.server_cmd,
            startup_delay=args.server_startup_delay,
        )
        server_manager.start()

        # Log DB alongside boofuzz results
        os.makedirs("boofuzz-results", exist_ok=True)
        log_db_path = os.path.join(
            "boofuzz-results", f"server_logs_{int(time.time())}.db"
        )
        log_db = LogDB(log_db_path)
        logger.info("Server log database: %s", log_db_path)

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
                logger.error(
                    "Validation FAILED: Server did not respond to health check."
                )

            connection.close()
        except Exception:
            logger.exception("Validation encountered an error")

    else:
        logger.info("Running in ONE-SHOT FUZZING MODE")
        logger.info("Press Ctrl+C to stop")

        # Single connection — always capsule mode (writes to CONNECT stream)
        connection = WebTransportConnection(
            target_url, timeout=3.0, send_mode="capsule"
        )

        monitors = []
        if not args.no_healthcheck:
            monitors.append(EchoCompareMonitor(crash_on_mismatch=True))

        # Add server log monitor if server is managed
        if server_manager and log_db:
            from src.server_log_monitor import ServerLogMonitor

            monitors.append(
                ServerLogMonitor(server_manager, log_db, delay_ms=args.server_log_delay)
            )

        target = Target(connection=connection, monitors=monitors)

        session = Session(
            target=target,
            fuzz_loggers=[],  # Web GUI at :26000 handles its own DB
            db_filename=":memory:",  # Don't write boofuzz's default run-*.db to disk
            sleep_time=0.0,
            restart_sleep_time=0.0,
            reuse_target_connection=False,
            index_start=args.start_index,
            index_end=args.end_index,
        )

        # Single boofuzz node for one-shot capsule fuzzing
        msg = define_oneshot_capsule(session_name="wt_oneshot")
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
            if log_db:
                logger.info("Server logs saved to: %s", log_db_path)
                log_db.close()
            if server_manager:
                server_manager.stop()


if __name__ == "__main__":
    main()
