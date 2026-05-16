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
    define_sc_capsule,
    define_sc_shuffle,
    define_oneshot_capsule,
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

os.makedirs("failures", exist_ok=True)

# Loggers that are noisy per-test-case (open/close/session setup lines).
# Quieted to WARNING by default; -v restores them to INFO.
_NOISY_LOGGERS = [
    "src.fuzzer_connection",
    "src.webtransport_client",
    "src.log_db",
    "quic",
    "asyncio",
    "tornado.access",
]


def _configure_logging(verbose: bool) -> None:
    if not verbose:
        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)


_MODE_DESCRIPTIONS = {
    "oneshot": "One-shot (single malformed capsule per connection)",
    "sc-shuffle": "Sc-shuffle (step-reordering mutations on named scenarios)",
    "sc-capsule": "Sc-capsule (malformed capsule injected at first/last step)",
    "all": "All modes combined (oneshot + sc-shuffle + sc-capsule)",
}


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WebTransport Protocol Fuzzer")
    p.add_argument("--url", default="https://0.0.0.0:6000/echo", help="Target URL")
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
    p.add_argument("--server-startup-delay", type=float, default=30.0)
    p.add_argument(
        "--server-log",
        type=str,
        default=None,
        help="Path to the server log file (enables readiness detection via SERVER_READY).",
    )
    p.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to the SQLite log DB (default: boofuzz-results/run_<timestamp>.db).",
    )
    p.add_argument(
        "--web-port",
        type=int,
        default=26000,
        help="Port for the boofuzz web UI (default: 26000).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show per-test-case connection/session logs (default: quiet, progress only).",
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
    conn = WebTransportConnection(url, timeout=0.5)
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
    _configure_logging(args.verbose)
    _print_banner(args.mode)
    logger.info("Target: %s", args.url)

    server_manager = None
    if args.server_cmd:
        from src.server_manager import ServerManager

        server_manager = ServerManager(
            cmd=args.server_cmd,
            startup_delay=args.server_startup_delay,
            log_file=args.server_log,
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
    elif args.mode == "sc-shuffle":
        send_mode = SEND_MODE_SCENARIO
        msg = define_sc_shuffle(session_name="wt_sc_shuffle")
    elif args.mode == "sc-capsule":
        send_mode = SEND_MODE_SCENARIO
        msg = define_sc_capsule(session_name="wt_sc_capsule")
    elif args.mode == "all":
        send_mode = SEND_MODE_SCENARIO
        msg = define_all(session_name="wt_all")
    else:  # pragma: no cover — argparse already validates
        logger.error("Unknown mode: %s", args.mode)
        return 1

    connection = WebTransportConnection(args.url, timeout=0.5, send_mode=send_mode)
    total = msg.num_mutations()
    logger.info("Mode %s: %d test cases queued", args.mode, total)

    monitors = []
    if not args.no_echo_monitor:
        monitors.append(EchoCompareMonitor(fail_on_mismatch=args.fail_on_echo_mismatch))
    req_logger = RequestLogger(log_db, total=total)
    monitors.append(req_logger)

    session = Session(
        target=Target(connection=connection, monitors=monitors),
        fuzz_loggers=[],
        db_filename=":memory:",
        web_port=args.web_port,
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
        req_logger.print_summary()
        logger.info("Session finished. Log DB: %s", db_path)
        logger.info(
            "Use analyze_logs.py --log <server.log> --db %s to correlate server output.",
            db_path,
        )
        log_db.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
