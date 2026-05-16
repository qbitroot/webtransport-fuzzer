#!/usr/bin/env python3
"""
launch.py — WebTransport fuzzer runner with structured log management.

Each run produces three files in ./logs/ with a shared stem:
    <server>_<mode>_<timestamp>.db          — fuzzer SQLite database
    <server>_<mode>_<timestamp>.server.log  — server stdout/stderr
    <server>_<mode>_<timestamp>.report.txt  — analyze_logs output

Usage examples:
    uv run launch.py run aioquic oneshot
    uv run launch.py run wtransport sc-shuffle --no-echo-monitor
    uv run launch.py run go sc-capsule --url https://localhost:4433/echo
    uv run launch.py run aioquic oneshot --start-index 500
    uv run launch.py analyze aioquic oneshot
    uv run launch.py analyze aioquic oneshot --stem aioquic_oneshot_20260516_120000
    uv run launch.py report aioquic oneshot
    uv run launch.py report aioquic oneshot --all
    uv run launch.py list
    uv run launch.py list aioquic
"""

import argparse
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Server definitions
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).parent
LOGS_DIR = _ROOT / "logs"

SERVERS = {
    "aioquic": {
        "cmd": (
            "uv run {root}/server/aioquic/server.py"
            " {root}/server/aioquic/cert.pem"
            " {root}/server/aioquic/key.pem"
        ),
        "url": "https://0.0.0.0:6161/echo",
        "startup_delay": 1.5,
    },
    "wtransport": {
        "cmd": "cargo run --manifest-path {root}/server/wtransport/Cargo.toml --release --quiet",
        "url": "https://0.0.0.0:4433/echo",
        "startup_delay": 3.0,
    },
    "go": {
        "cmd": "{root}/server/webtransport-go/webtransport-go-server",
        "url": "https://0.0.0.0:4433/echo",
        "startup_delay": 1.0,
    },
}

MODES = ["oneshot", "sc-shuffle", "sc-capsule", "all"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _stem(server: str, mode: str, ts: str) -> str:
    return f"{server}_{mode}_{ts}"


def _latest_stem(server: str, mode: str) -> str | None:
    prefix = f"{server}_{mode}_"
    dbs = sorted(LOGS_DIR.glob(f"{prefix}*.db"))
    return dbs[-1].stem if dbs else None


def _server_cmd(server: str) -> str:
    return SERVERS[server]["cmd"].format(root=_ROOT)


def _tag(label: str) -> str:
    return f"[launch] {label}"


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    server_cfg = SERVERS[args.server]
    LOGS_DIR.mkdir(exist_ok=True)

    stem = _stem(args.server, args.mode, _timestamp())
    db_path = LOGS_DIR / f"{stem}.db"
    server_log = LOGS_DIR / f"{stem}.server.log"

    url = args.url or server_cfg["url"]
    startup_delay = args.startup_delay or server_cfg["startup_delay"]

    # Redirect server output to the log file.
    # With -v: tee to both file and terminal.  Without: file only (quiet).
    base_cmd = _server_cmd(args.server)
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
        "--server-startup-delay",
        str(startup_delay),
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

    print(_tag(f"stem       : {stem}"))
    print(_tag(f"server     : {args.server}  ({url})"))
    print(_tag(f"mode       : {args.mode}"))
    print(_tag(f"db         : {db_path.name}"))
    print(_tag(f"server log : {server_log.name}"))
    print()

    rc = subprocess.call(fuzzer_argv, cwd=_ROOT)
    print("\n" + _tag(f"fuzzer exited with code {rc}"))

    if not args.no_analyze:
        _analyze(stem, server_log, db_path)

    return rc


def cmd_analyze(args: argparse.Namespace) -> int:
    if args.stem:
        stem = args.stem
    else:
        stem = _latest_stem(args.server, args.mode)
        if stem is None:
            print(_tag(f"no runs found for {args.server}/{args.mode} in {LOGS_DIR}"))
            return 1
        print(_tag(f"using latest: {stem}"))

    db_path = LOGS_DIR / f"{stem}.db"
    server_log = LOGS_DIR / f"{stem}.server.log"

    for p in (db_path, server_log):
        if not p.exists():
            print(_tag(f"not found: {p}"))
            return 1

    _analyze(stem, server_log, db_path)
    return 0


def _analyze(stem: str, server_log: Path, db_path: Path) -> None:
    report_path = LOGS_DIR / f"{stem}.report.txt"
    print(_tag(f"analyze_logs -> {report_path.name}"))

    result = subprocess.run(
        [
            "uv",
            "run",
            "analyze_logs.py",
            "--log",
            str(server_log),
            "--db",
            str(db_path),
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
    )

    report_path.write_text(result.stdout + result.stderr)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def cmd_report(args: argparse.Namespace) -> int:
    """
    Query the correlated DB and print test cases whose server log looks anomalous.

    Anomaly heuristics (applied to each log_group's raw_text):
      - contains "panic", "traceback", "exception", "error" (case-insensitive)
      - missing SESSION_CLOSE  (server dropped the connection unexpectedly)
      - missing SESSION_OPEN   (connection was never established)

    With --all, print every test case regardless of anomaly status.
    """
    if args.stem:
        stem = args.stem
    else:
        stem = _latest_stem(args.server, args.mode)
        if stem is None:
            print(_tag(f"no runs found for {args.server}/{args.mode} in {LOGS_DIR}"))
            return 1
        print(_tag(f"using latest: {stem}"))

    db_path = LOGS_DIR / f"{stem}.db"
    if not db_path.exists():
        print(_tag(f"db not found: {db_path}"))
        return 1

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT
            tc.id,
            tc.test_index,
            tc.sent_data,
            lg.raw_text
        FROM test_cases tc
        LEFT JOIN log_groups lg ON tc.log_group_id = lg.id
        ORDER BY tc.id
    """).fetchall()
    conn.close()

    _ANOMALY_KEYWORDS = {"panic", "traceback", "exception", "error"}

    def _classify(raw_text: str | None) -> tuple[bool, list[str]]:
        """Return (is_anomaly, list-of-reasons)."""
        if raw_text is None:
            return True, ["no server log correlated (analyze first)"]
        reasons = []
        lower = raw_text.lower()
        for kw in _ANOMALY_KEYWORDS:
            if kw in lower:
                reasons.append(f"contains '{kw}'")
        if "SESSION_CLOSE" not in raw_text:
            reasons.append("missing SESSION_CLOSE")
        if "SESSION_OPEN" not in raw_text:
            reasons.append("missing SESSION_OPEN")
        return bool(reasons), reasons

    total = len(rows)
    anomalies = []
    for row in rows:
        is_anomaly, reasons = _classify(row["raw_text"])
        if is_anomaly or args.all:
            anomalies.append((row, reasons, is_anomaly))

    print(f"\n{'=' * 70}")
    print(f"  Run    : {stem}")
    print(f"  Total  : {total} test cases")
    print(f"  Shown  : {len(anomalies)} ({'all' if args.all else 'anomalies only'})")
    print(f"{'=' * 70}\n")

    if not anomalies:
        print("No anomalies found.")
        return 0

    for row, reasons, is_anomaly in anomalies:
        sent = row["sent_data"] or "(none)"
        label = "ANOMALY" if is_anomaly else "ok"
        print(f"--- tc.id={row['id']}  index={row['test_index']}  [{label}]")
        if reasons:
            print(f"    reasons : {', '.join(reasons)}")
        for line in sent.splitlines():
            print(f"    sent    : {line}")
        if args.verbose and row["raw_text"]:
            print("    server log:")
            for log_line in row["raw_text"].splitlines():
                print(f"      {log_line}")
        print()

    print(f"{len([a for a in anomalies if a[2]])} anomalous / {total} total test cases")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    if not LOGS_DIR.exists():
        print(_tag(f"no logs directory at {LOGS_DIR}"))
        return 0

    if args.server and args.mode:
        pattern = f"{args.server}_{args.mode}_*.db"
    elif args.server:
        pattern = f"{args.server}_*.db"
    else:
        pattern = "*.db"

    dbs = sorted(LOGS_DIR.glob(pattern))
    if not dbs:
        print(_tag("no runs found"))
        return 0

    print(f"{'stem':<45} {'db':>10}  {'server.log':>12}  {'report':>8}")
    print("-" * 82)
    for db in dbs:
        stem = db.stem
        slog = LOGS_DIR / f"{stem}.server.log"
        report = LOGS_DIR / f"{stem}.report.txt"
        db_size = db.stat().st_size
        slog_size = slog.stat().st_size if slog.exists() else 0
        report_mark = "yes" if report.exists() else "-"
        print(f"{stem:<45} {db_size:>10,}  {slog_size:>12,}  {report_mark:>8}")
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="WebTransport fuzzer launcher.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command")

    # run
    run_p = sub.add_parser("run", help="Run the fuzzer.")
    run_p.add_argument("server", choices=list(SERVERS))
    run_p.add_argument("mode", choices=MODES)
    run_p.add_argument("--url", help="Override target URL.")
    run_p.add_argument(
        "--startup-delay", type=float, help="Override server startup delay."
    )
    run_p.add_argument(
        "--start-index", type=int, help="Resume from this test case index."
    )
    run_p.add_argument("--end-index", type=int, help="Stop after this test case index.")
    run_p.add_argument("--no-echo-monitor", action="store_true")
    run_p.add_argument("--fail-on-echo-mismatch", action="store_true")
    run_p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show per-test-case logs and server stdout (default: quiet).",
    )
    run_p.add_argument(
        "--no-analyze",
        action="store_true",
        help="Skip auto-running analyze_logs after fuzzer exits.",
    )

    # analyze
    ana_p = sub.add_parser("analyze", help="Analyze an existing run.")
    ana_p.add_argument("server", choices=list(SERVERS))
    ana_p.add_argument("mode", choices=MODES)
    ana_p.add_argument("--stem", help="Exact file stem (default: latest).")

    # report
    rep_p = sub.add_parser(
        "report", help="Show anomalous test cases from a correlated run."
    )
    rep_p.add_argument("server", choices=list(SERVERS))
    rep_p.add_argument("mode", choices=MODES)
    rep_p.add_argument("--stem", help="Exact file stem (default: latest).")
    rep_p.add_argument(
        "--all", action="store_true", help="Show all test cases, not just anomalies."
    )
    rep_p.add_argument(
        "--verbose", "-v", action="store_true", help="Print full server log per case."
    )

    # list
    list_p = sub.add_parser("list", help="List runs in ./logs/.")
    list_p.add_argument("server", choices=list(SERVERS), nargs="?")
    list_p.add_argument("mode", choices=MODES, nargs="?")

    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "run":
        return cmd_run(args)
    elif args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "report":
        return cmd_report(args)
    elif args.command == "list":
        return cmd_list(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
