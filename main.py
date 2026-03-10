#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time

from boofuzz import Session, Target

from src.fuzzer_connection import WebTransportConnection
from src.echo_monitor import EchoCompareMonitor, ServerDownError
from src.boofuzz_definitions import (
    define_oneshot_capsule,
    define_multistep,
    define_scenario_lastfuzz,
    define_all,
)

# ---- Logging setup ----
LOG_FMT = "%(asctime)s [%(levelname)5s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
logger = logging.getLogger("wt_fuzzer")
logging.getLogger("tornado.access").setLevel(logging.WARNING)

# ---- Helper: ensure failure dir exists ----
FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description="WebTransport Protocol Fuzzer")
    parser.add_argument("--url", default="https://0.0.0.0:6161/echo", help="Target URL")
    parser.add_argument(
        "--no-fuzz",
        action="store_true",
        help="Run in validation mode (health check only)",
    )
    parser.add_argument(
        "--mode",
        choices=["oneshot", "multistep", "scenario-lastfuzz", "all"],
        default="oneshot",
        help="Fuzzing mode: oneshot (single malformed capsule), "
        "multistep (scenarios with interleaved data streams + capsules), "
        "scenario-lastfuzz (scenarios in original order, last step replaced "
        "with fuzzed capsule), "
        "all (oneshot + multistep + scenario-lastfuzz combined) "
        "(default: oneshot)",
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
        help="Shell command to launch the target server as a subprocess. "
        "Redirect its stdout to a log file for later analysis with analyze_logs.py, e.g.: "
        "'python server.py cert.pem key.pem 2>/dev/null | tee server.log'",
    )
    parser.add_argument(
        "--server-startup-delay",
        type=float,
        default=1.0,
        help="Seconds to wait after launching server before fuzzing (default: 1.0)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to the SQLite log database. Defaults to boofuzz-results/run_<timestamp>.db",
    )
    args = parser.parse_args()

    target_url = args.url

    mode_desc = {
        "oneshot": "One-Shot (single malformed capsule per connection)",
        "multistep": "Multistep (data streams + capsule sequences)",
        "scenario-lastfuzz": "Scenario-LastFuzz (scenario + fuzzed last step)",
        "all": "All modes combined (oneshot + multistep + lastfuzz)",
    }

    print(
        f"""
    ╔═══════════════════════════════════════════════════════╗
    ║   WebTransport Protocol Fuzzer                         ║
    ║   Target: WebTransport over HTTP/3 Framing             ║
    ║   Mode: {mode_desc[args.mode]:<47s}║
    ╚═══════════════════════════════════════════════════════╝
    """
    )
    logger.info("Target: %s", target_url)
    logger.info("Mode: %s", args.mode)

    # ---- Server subprocess management ----
    server_manager = None

    if args.server_cmd:
        from src.server_manager import ServerManager

        server_manager = ServerManager(
            cmd=args.server_cmd,
            startup_delay=args.server_startup_delay,
        )
        server_manager.start()

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
        logger.info("Running in %s FUZZING MODE", args.mode.upper())
        logger.info("Press Ctrl+C to stop")

        # ---- Log DB setup ----
        from src.log_db import LogDB
        from src.request_logger import RequestLogger

        os.makedirs("boofuzz-results", exist_ok=True)
        log_db_path = args.db or os.path.join(
            "boofuzz-results", f"run_{int(time.time())}.db"
        )
        log_db = LogDB(log_db_path)
        logger.info("Log database: %s", log_db_path)

        # ---- Select send mode and boofuzz definition based on --mode ----
        if args.mode == "oneshot":
            send_mode = "capsule"
            msg = define_oneshot_capsule(session_name="wt_oneshot")
        elif args.mode == "multistep":
            send_mode = "scenario"
            msg = define_multistep(session_name="wt_multistep")
        elif args.mode == "scenario-lastfuzz":
            send_mode = "scenario"
            msg = define_scenario_lastfuzz(session_name="wt_scenario_lastfuzz")
        elif args.mode == "all":
            send_mode = "scenario"
            msg = define_all(session_name="wt_all")
        else:
            logger.error("Unknown mode: %s", args.mode)
            sys.exit(1)

        connection = WebTransportConnection(
            target_url, timeout=3.0, send_mode=send_mode
        )

        # Log mutation count
        num_mutations = msg.num_mutations()
        logger.info("Mode %s: %d test cases to run", args.mode, num_mutations)

        monitors = []
        if not args.no_healthcheck:
            monitors.append(EchoCompareMonitor(crash_on_mismatch=True))

        monitors.append(RequestLogger(log_db))

        target = Target(connection=connection, monitors=monitors)

        session = Session(
            target=target,
            fuzz_loggers=[],  # Web GUI at :26000 handles its own DB
            db_filename=":memory:",  # Don't write boofuzz's default run-*.db to disk
            sleep_time=0.0,
            restart_sleep_time=0,
            reuse_target_connection=False,
            index_start=args.start_index,
            index_end=args.end_index,
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
            logger.info("Log database: %s", log_db_path)
            logger.info(
                "Run analyze_logs.py --log <server.log> --db %s to correlate server output.",
                log_db_path,
            )
            log_db.close()
            if server_manager:
                server_manager.stop()


if __name__ == "__main__":
    main()
