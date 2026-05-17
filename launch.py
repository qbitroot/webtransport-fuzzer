#!/usr/bin/env python3
"""
launch.py — run the fuzzer and stitch the server log into the DB.

Produces two files in ./logs/ with a shared stem:
    <server>_<mode>_<timestamp>.db          — fuzzer SQLite database
    <server>_<mode>_<timestamp>.server.log  — server stdout/stderr

After the fuzzer exits, correlate_logs.py is run to correlate the log
with the DB (populating log_group_id for each test case).

Server ports (fixed per implementation):
    aioquic    — server :6000   web UI :26000
    wtransport — server :6001   web UI :26001
    go         — server :6002   web UI :26002

Usage:
    uv run launch.py aioquic oneshot
    uv run launch.py wtransport sc-shuffle --no-echo-monitor
    uv run launch.py go sc-capsule
    uv run launch.py aioquic oneshot --start-index 500
"""

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).parent
LOGS_DIR = _ROOT / "logs"

SERVERS = {
    "aioquic": {
        "cmd": (
            "uv run {root}/server/aioquic/server.py"
            " {root}/server/aioquic/cert.pem"
            " {root}/server/aioquic/key.pem"
        ),
        "port": 6000,
        "web_port": 26000,
        "path": "/echo",
        "startup_delay": 10.0,
    },
    "wtransport": {
        "cmd": "cargo run --manifest-path {root}/server/wtransport/Cargo.toml --release --quiet",
        "port": 6001,
        "web_port": 26001,
        "path": "/echo",
        "startup_delay": 120.0,
    },
    "go": {
        "cmd": "{root}/server/webtransport-go/webtransport-go-server",
        "port": 6002,
        "web_port": 26002,
        "path": "/echo",
        "startup_delay": 10.0,
    },
}

MODES = ["oneshot", "sc-shuffle", "sc-capsule", "all"]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Run the WebTransport fuzzer and stitch logs into the DB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("server", choices=list(SERVERS))
    p.add_argument("mode", choices=MODES)
    p.add_argument("--url", help="Override target URL.")
    p.add_argument("--startup-delay", type=float, help="Override server startup delay.")
    p.add_argument("--start-index", type=int, help="Resume from this test case index.")
    p.add_argument("--end-index", type=int, help="Stop after this test case index.")
    p.add_argument("--no-echo-monitor", action="store_true")
    p.add_argument("--fail-on-echo-mismatch", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    cfg = SERVERS[args.server]
    LOGS_DIR.mkdir(exist_ok=True)

    url = args.url or f"https://0.0.0.0:{cfg['port']}{cfg['path']}"
    startup_delay = args.startup_delay or cfg["startup_delay"]

    stem = f"{args.server}_{args.mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    db_path = LOGS_DIR / f"{stem}.db"
    server_log = LOGS_DIR / f"{stem}.server.log"

    base_cmd = cfg["cmd"].format(root=_ROOT)
    if args.verbose:
        server_cmd = f"{base_cmd} 2>&1 | tee {server_log}"
    else:
        server_cmd = f"{base_cmd} > {server_log} 2>&1"

    fuzzer_argv = [
        "uv",
        "run",
        "main.py",
        "--url",
        url,
        "--mode",
        args.mode,
        "--db",
        str(db_path),
        "--server-cmd",
        server_cmd,
        "--server-log",
        str(server_log),
        "--server-startup-delay",
        str(startup_delay),
        "--web-port",
        str(cfg["web_port"]),
    ]
    if args.verbose:
        fuzzer_argv += ["--verbose"]
    if args.start_index:
        fuzzer_argv += ["--start-index", str(args.start_index)]
    if args.end_index:
        fuzzer_argv += ["--end-index", str(args.end_index)]
    if args.no_echo_monitor:
        fuzzer_argv += ["--no-echo-monitor"]
    if args.fail_on_echo_mismatch:
        fuzzer_argv += ["--fail-on-echo-mismatch"]

    print(f"[launch] stem       : {stem}")
    print(f"[launch] server     : {args.server}  port={cfg['port']}  ({url})")
    print(f"[launch] mode       : {args.mode}")
    print(f"[launch] web UI     : http://localhost:{cfg['web_port']}")
    print(f"[launch] db         : {db_path.name}")
    print(f"[launch] server log : {server_log.name}")
    print()

    rc = subprocess.call(fuzzer_argv, cwd=_ROOT)
    print(f"\n[launch] fuzzer exited with code {rc}")

    print(f"[launch] stitching log into db via correlate_logs.py")
    subprocess.call(
        [
            "uv",
            "run",
            "correlate_logs.py",
            "--log",
            str(server_log),
            "--db",
            str(db_path),
        ],
        cwd=_ROOT,
    )
    return rc


if __name__ == "__main__":
    sys.exit(main())
