#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time

from boofuzz import Session, Target, FuzzLoggerText

from src.fuzzer_connection import WebTransportConnection
from src.echo_monitor import EchoCompareMonitor
from src.boofuzz_definitions import (
    define_webtransport_protocol,
    define_bidirectional_stream,
    define_datagram,
    define_malformed_frames,
    define_capsule_generic,
    define_capsule_drain,
    define_capsule_close,
    define_valid_webtransport_packet,
)
from src.callbacks import callback_fill_session_id

# ---- Logging setup ----
LOG_FMT = "%(asctime)s [%(levelname)5s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
logger = logging.getLogger("wt_fuzzer")
logging.getLogger("tornado.access").setLevel(logging.WARNING)

# ---- Helper: ensure failure dir exists ----
FAILURES_DIR = "failures"
os.makedirs(FAILURES_DIR, exist_ok=True)

# Available fuzzing modes and their definitions
FUZZ_MODES = {
    # Data streams
    "unidirectional": {
        "define_func": define_webtransport_protocol,
        "send_mode": "unidirectional",
        "desc": "Unidirectional streams (0x54)",
    },
    "bidirectional": {
        "define_func": define_bidirectional_stream,
        "send_mode": "bidirectional", 
        "desc": "Bidirectional streams (0x41)",
    },
    "datagram": {
        "define_func": define_datagram,
        "send_mode": "datagram",
        "desc": "Datagrams (unreliable)",
    },
    "malformed": {
        "define_func": define_malformed_frames,
        "send_mode": "unidirectional",
        "desc": "Malformed/edge-case frames",
    },
    # Control capsules (NEW)
    "capsule": {
        "define_func": define_capsule_generic,
        "send_mode": "capsule",
        "desc": "Generic HTTP/3 Capsules (control channel)",
    },
    "drain": {
        "define_func": define_capsule_drain,
        "send_mode": "capsule",
        "desc": "DRAIN_WEBTRANSPORT_SESSION Capsule (0x78AE)",
    },
    "close": {
        "define_func": define_capsule_close,
        "send_mode": "capsule",
        "desc": "CLOSE_WEBTRANSPORT_SESSION Capsule (0x2843)",
    },
}


def run_fuzzing_mode(target_url: str, mode_name: str, mode_config: dict, fuzz_payload: bool):
    """Run fuzzing for a single specific mode."""
    logger.info("=" * 60)
    logger.info("Starting %s fuzzing: %s", mode_name.upper(), mode_config["desc"])
    logger.info("Payload fuzzing: %s", "ENABLED" if fuzz_payload else "DISABLED (structure only)")
    logger.info("=" * 60)
    
    connection = WebTransportConnection(
        target_url, 
        timeout=3.0, 
        send_mode=mode_config["send_mode"]
    )
    
    echo_monitor = EchoCompareMonitor(crash_on_mismatch=True)
    target = Target(connection=connection, monitors=[echo_monitor])

    session = Session(
        target=target,
        fuzz_loggers=[FuzzLoggerText()],
        sleep_time=0.0,
        restart_sleep_time=2.0,
        reuse_target_connection=False,
    )

    msg = mode_config["define_func"](fuzz_payload=fuzz_payload)
    session.connect(msg, callback=callback_fill_session_id)

    try:
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing stopped by user")
        raise
    except (TimeoutError, ConnectionError, RuntimeError) as e:
        logger.error(f"Fuzzing halted: {e}")


def main():
    parser = argparse.ArgumentParser(description="WebTransport Fuzzer")
    parser.add_argument("--url", default="https://0.0.0.0:6161/echo", help="Target URL")
    parser.add_argument("--no-fuzz", action="store_true", help="Run in validation mode")
    parser.add_argument(
        "--mode",
        choices=list(FUZZ_MODES.keys()),
        default="unidirectional",
        help="Fuzzing mode (see --list-modes for descriptions)"
    )
    parser.add_argument(
        "--list-modes",
        action="store_true",
        help="List all available fuzzing modes and exit"
    )
    parser.add_argument(
        "--fuzz-payload",
        action="store_true",
        help="Also fuzz payload content (default: only fuzz packet structure)"
    )
    args = parser.parse_args()

    if args.list_modes:
        print("\nAvailable fuzzing modes:\n")
        for name, config in FUZZ_MODES.items():
            print(f"  {name:15} - {config['desc']}")
        print()
        return

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
        logger.info("Running in FUZZING MODE")
        mode_config = FUZZ_MODES[args.mode]
        
        logger.info("Mode: %s", args.mode)
        logger.info("Web UI available at: http://localhost:26000 (if enabled)")
        logger.info("Press Ctrl+C to stop")

        try:
            run_fuzzing_mode(target_url, args.mode, mode_config, args.fuzz_payload)
        except KeyboardInterrupt:
            logger.info("Fuzzing stopped by user")
        except Exception:
            logger.exception("Fuzzing encountered an unexpected error")
        finally:
            logger.info("Fuzzing session finished")


if __name__ == "__main__":
    main()
