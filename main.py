#!/usr/bin/env python3

import logging
import os

from boofuzz import Session, Target, FuzzLoggerText
from boofuzz import s_initialize, s_get, s_string

from src.fuzzer_connection import WebTransportConnection
from src.echo_monitor import EchoCompareMonitor

# ---- Logging setup ----
LOG_FMT = "%(asctime)s [%(levelname)5s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
logger = logging.getLogger("wt_fuzzer")
logging.getLogger("tornado.access").setLevel(logging.WARNING)

# ---- Helper: ensure failure dir exists ----
FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)


def define_protocol():
    """Define the fuzzable protocol using boofuzz primitives."""
    s_initialize("webtransport_echo")
    s_string("Hello, WebTransport!", fuzzable=True)
    return s_get("webtransport_echo")


def main():
    target_url = "https://0.0.0.0:6161/echo"

    print(
        """
╔═══════════════════════════════════════════════════════╗
║   WebTransport Black-Box Fuzzer - PoC                 ║
║   Using: boofuzz + aioquic                            ║
║   Transport: Bidirectional WebTransport Streams       ║
╚═══════════════════════════════════════════════════════╝
    """
    )
    logger.info("Target: %s", target_url)

    connection = WebTransportConnection(target_url, timeout=3.0)
    echo_monitor = EchoCompareMonitor(crash_on_mismatch=True)
    target = Target(connection=connection, monitors=[echo_monitor])

    session = Session(
        target=target,
        fuzz_loggers=[FuzzLoggerText()],
        sleep_time=1.0,
        restart_sleep_time=2.0,
        reuse_target_connection=False,
    )

    msg = define_protocol()
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
