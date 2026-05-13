#!/usr/bin/env python3
"""
WebTransport Protocol Fuzzer — CLI entry point.

Wires up:
  * A boofuzz ``Session`` with ``reuse_target_connection=False`` so each
    test case runs on a fresh QUIC handshake (one-shot crash isolation).
  * The ``WebTransportConnection`` target connection.
  * Monitors: ``EchoCompareMonitor`` (per-step echo logging) and
    ``RequestLogger`` (SQLite test-case recorder).

Liveness is not probed actively after each test case; the next
``connection.open()`` is the implicit health check. If the server is
down, the open call raises ``ConnectionError``, boofuzz catches it, and
the run continues / aborts based on its own retry policy.
"""

import argparse
import logging
import os
import sys
import time

from boofuzz import Session, Target

from src.boofuzz_definitions import (
    define_all,
    define_multistep,
    define_oneshot_capsule,
    define_scenario_lastfuzz,
)
from src.echo_monitor import EchoCompareMonitor
from src.fuzzer_connection import (
    SEND_MODE_CAPSULE,
    SEND_MODE_SCENARIO,
    WebTransportConnection,
)

LOG_FMT = "%(asctime)s [%(levelname)5s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
logger = logging.getLogger("wt_fuzzer")
logging.getLogger("tornado.access").setLevel(logging.WARNING)

os.makedirs("failures", exist_ok=True)


_MODE_DESCRIPTIONS = {
    "oneshot": "One-shot (single malformed capsule per connection)",
    "multistep": "Multistep (data streams + capsule sequences)",
    "scenario-lastfuzz": "Scenario-LastFuzz (scenario + fuzzed last step)",
    "all": "All modes combined (oneshot + multistep + lastfuzz)",
}


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WebTransport Protocol Fuzzer")
    p.add_argument("--url", default="https://0.0.0.0:6161/echo", help="Target URL")
    p.add_argument(
        "--no-fuzz",
        action="store_true",
        help="Validation mode: open one connection, send a bidi echo probe, exit.",
    )
    p.add_argument(
        "--mode",
        choices=list(_MODE_DESCRIPTIONS),
        default="oneshot",
        help="Fuzzing mode (default: oneshot).",
    )
    p.add_argument(
        "--no-echo-monitor",
        action="store_true",
        help="Skip the EchoCompareMonitor; only the SQLite RequestLogger runs.",
    )
    p.add_argument(
        "--fail-on-echo-mismatch",
        action="store_true",
        help="Treat any echo mismatch as a boofuzz failure (default: log only).",
    )
    p.add_argument("--start-index", type=int, default=1)
    p.add_argument("--end-index", type=int)
    p.add_argument(
        "--server-cmd",
        type=str,
        default=None,
        help="Optional shell command to launch the target server as a subprocess.",
    )
    p.add_argument("--server-startup-delay", type=float, default=1.0)
    p.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to the SQLite log DB (default: boofuzz-results/run_<timestamp>.db).",
    )
    return p


def _print_banner(mode: str) -> None:
    print(
        f"""
    ╔═══════════════════════════════════════════════════════╗
    ║   WebTransport Protocol Fuzzer                         ║
    ║   Target: WebTransport over HTTP/3                     ║
    ║   Mode: {_MODE_DESCRIPTIONS[mode]:<47s}║
    ╚═══════════════════════════════════════════════════════╝
    """
    )


def _run_validation(url: str) -> int:
    """Open one connection, send a bidi echo probe, report the result."""
    logger.info("Validation mode: probing %s", url)
    conn = WebTransportConnection(url, timeout=3.0)
    try:
        conn.open()
    except Exception:
        logger.exception("Validation failed: could not open connection")
        return 1

    try:
        loop = conn._loop
        assert loop is not None and conn._protocol is not None
        probe = b"HEALTHCHECK"
        _sid, response = loop.run_until_complete(
            conn._protocol.send_bidirectional_stream(probe, timeout=2.0)
        )
        if response == probe:
            logger.info("Validation SUCCESS: bidi echo round-trip OK")
            return 0
        logger.error(
            "Validation FAILED: bidi echo mismatch (sent %r, got %r)",
            probe,
            response,
        )
        return 1
    finally:
        conn.close()


def main() -> int:
    args = _build_argparser().parse_args()
    _print_banner(args.mode)
    logger.info("Target: %s", args.url)

    server_manager = None
    if args.server_cmd:
        from src.server_manager import ServerManager

        server_manager = ServerManager(
            cmd=args.server_cmd, startup_delay=args.server_startup_delay
        )
        server_manager.start()

    try:
        if args.no_fuzz:
            return _run_validation(args.url)
        return _run_fuzz(args)
    finally:
        if server_manager is not None:
            server_manager.stop()


def _run_fuzz(args: argparse.Namespace) -> int:
    from src.log_db import LogDB
    from src.request_logger import RequestLogger

    os.makedirs("boofuzz-results", exist_ok=True)
    db_path = args.db or os.path.join("boofuzz-results", f"run_{int(time.time())}.db")
    log_db = LogDB(db_path)
    logger.info("Log database: %s", db_path)

    if args.mode == "oneshot":
        send_mode = SEND_MODE_CAPSULE
        msg = define_oneshot_capsule(session_name="wt_oneshot")
    elif args.mode == "multistep":
        send_mode = SEND_MODE_SCENARIO
        msg = define_multistep(session_name="wt_multistep")
    elif args.mode == "scenario-lastfuzz":
        send_mode = SEND_MODE_SCENARIO
        msg = define_scenario_lastfuzz(session_name="wt_scenario_lastfuzz")
    elif args.mode == "all":
        send_mode = SEND_MODE_SCENARIO
        msg = define_all(session_name="wt_all")
    else:  # pragma: no cover — argparse already validates
        logger.error("Unknown mode: %s", args.mode)
        return 1

    connection = WebTransportConnection(args.url, timeout=3.0, send_mode=send_mode)
    logger.info("Mode %s: %d test cases queued", args.mode, msg.num_mutations())

    monitors = []
    if not args.no_echo_monitor:
        monitors.append(EchoCompareMonitor(fail_on_mismatch=args.fail_on_echo_mismatch))
    monitors.append(RequestLogger(log_db))

    session = Session(
        target=Target(connection=connection, monitors=monitors),
        fuzz_loggers=[],  # boofuzz's web GUI runs its own DB at :26000
        db_filename=":memory:",
        sleep_time=0.0,
        restart_sleep_time=0,
        reuse_target_connection=False,
        index_start=args.start_index,
        index_end=args.end_index,
    )
    session.connect(msg)

    rc = 0
    try:
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing stopped by user")
    except EOFError:
        # boofuzz's web GUI prompts for ENTER on shutdown; harmless under non-TTY.
        pass
    except (TimeoutError, ConnectionError, RuntimeError) as e:
        logger.error("Fuzzing halted: %s", e)
        rc = 1
    except Exception:
        logger.exception("Fuzzing encountered an unexpected error")
        rc = 1
    finally:
        logger.info("Session finished. Log DB: %s", db_path)
        logger.info(
            "Use analyze_logs.py --log <server.log> --db %s to correlate server output.",
            db_path,
        )
        log_db.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
