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
    define_stream_dos,
    define_stream_dos,
    define_valid_webtransport_packet,
    define_capsule_reset_stream,
    define_capsule_stop_sending,
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
    "wt_close": {
        "define_func": define_capsule_close,
        "send_mode": "capsule",
        "desc": "CLOSE_WEBTRANSPORT_SESSION Capsule (0x2843)",
    },
    "wt_stream_dos": {
        "define_func": define_stream_dos,
        "send_mode": "unidirectional",
        "desc": "DoS: 10k Small Streams (Resource Exhaustion)",
    },
    "multistep": {
        "define_func": None, # Handled specially
        "send_mode": "special",
        "desc": "Multi-Step Sequences (State Violations)",
    },
}


def make_mode_callback(send_mode: str):
    """Factory for a callback that sets the connection's send mode."""
    def callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
        # 1. Update send mode
        try:
            if hasattr(target, "_target_connection"):
                target._target_connection.set_send_mode(send_mode)
        except Exception as e:
            fuzz_data_logger.log_error(f"Failed to set send mode: {e}")
            
        # 2. Chain to the session ID callback
        callback_fill_session_id(target, fuzz_data_logger, session, node, edge, *args, **kwargs)
        
    return callback


def main():
    parser = argparse.ArgumentParser(description="WebTransport Fuzzer")
    parser.add_argument("--url", default="https://0.0.0.0:6161/echo", help="Target URL")
    parser.add_argument("--no-fuzz", action="store_true", help="Run in validation mode")
    parser.add_argument(
        "--mode",
        choices=list(FUZZ_MODES.keys()) + ["all"],
        default="unidirectional",
        help="Fuzzing mode: specific mode name or 'all' to run all modes sequentially"
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
        print(f"  {'all':15} - Run all modes sequentially")
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
        
        # Determine which modes to run
        if args.mode == "all":
            modes_to_run = list(FUZZ_MODES.items())
            logger.info("Mode: ALL (%d modes)", len(modes_to_run))
        else:
            modes_to_run = [(args.mode, FUZZ_MODES[args.mode])]
            logger.info("Mode: %s", args.mode)
        
        logger.info("Web UI available at: http://localhost:26000 (if enabled)")
        logger.info("Press Ctrl+C to stop")

        # Initialize SINGLE Session and Connection
        connection = WebTransportConnection(
            target_url, 
            timeout=3.0, 
            send_mode="unidirectional"  # Default, overridden by callback
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

        # Connect nodes to the session graph
        for mode_name, mode_config in modes_to_run:
            logger.info("Registering mode: %s", mode_name)

            if mode_name == "multistep":
                logger.info("Building Multi-Step Graph...")
                
                # Sequence 1: Stream -> Reset Stream (Close) -> Stream (Attempt to send on closed?)
                # We link Step 1 (Stream) -> Step 2 (Reset).
                # Note: Probabilistic matching of IDs relies on fuzzing same small integers (0, 1...).
                ms_step1 = define_webtransport_protocol("ms_stream_open", fuzz_payload=args.fuzz_payload)
                ms_step2 = define_capsule_reset_stream("ms_reset_stream")
                
                # Connect Root -> Stream
                session.connect(ms_step1, callback=make_mode_callback("unidirectional"))
                # Connect Stream -> Reset
                session.connect(ms_step1, ms_step2, callback=make_mode_callback("capsule"))

                # Sequence 2: Drain Session -> Open New Stream (Should fail/ignore)
                ms_drain = define_capsule_drain("ms_drain")
                ms_post_drain = define_webtransport_protocol("ms_post_drain", fuzz_payload=args.fuzz_payload)
                
                session.connect(ms_drain, callback=make_mode_callback("capsule"))
                session.connect(ms_drain, ms_post_drain, callback=make_mode_callback("unidirectional"))

                # Sequence 3: Close Session -> Open New Stream
                ms_close = define_capsule_close("ms_close")
                ms_post_close = define_webtransport_protocol("ms_post_close", fuzz_payload=args.fuzz_payload)
                
                session.connect(ms_close, callback=make_mode_callback("capsule"))
                session.connect(ms_close, ms_post_close, callback=make_mode_callback("unidirectional"))

            else:
                # Standard Single-Step Mode
                msg = mode_config["define_func"](
                    session_name=f"wt_{mode_name}",
                    fuzz_payload=args.fuzz_payload
                )
                
                # Use specific callback that sets the correct send_mode
                session.connect(
                    msg, 
                    callback=make_mode_callback(mode_config["send_mode"])
                )

        try:
            session.fuzz()
        except KeyboardInterrupt:
            logger.info("Fuzzing stopped by user")
        except (TimeoutError, ConnectionError, RuntimeError) as e:
            logger.error(f"Fuzzing halted: {e}")
        except Exception:
            logger.exception("Fuzzing encountered an unexpected error")
        finally:
            logger.info("Fuzzing session finished")


if __name__ == "__main__":
    main()
