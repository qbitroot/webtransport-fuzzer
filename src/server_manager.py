"""
Server subprocess manager.

Launches the target server as a child process with stdout/stderr
redirected at the shell level (the caller constructs the command string
with ``> file 2>&1`` or ``| tee file``).

Readiness is detected by polling a log file for a ``ready_pattern``
string (default: ``SERVER_READY``). This avoids the race where a build
step (e.g. ``cargo run --release``) keeps the process alive for tens of
seconds before the server actually starts listening.

Usage:
    mgr = ServerManager(
        cmd="uv run server/aioquic/server.py cert.pem key.pem > s.log 2>&1",
        log_file="s.log",
    )
    mgr.start()    # launches process, polls log for SERVER_READY
    ...
    mgr.stop()     # SIGTERM → SIGKILL if needed
"""

import logging
import os
import signal
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_READY_POLL_INTERVAL = 0.25  # seconds between log file checks


class ServerManager:
    """Manages a server subprocess lifetime (start / stop / liveness check)."""

    def __init__(
        self,
        cmd: str,
        startup_delay: float = 1.0,
        log_file: str | None = None,
        ready_pattern: str = "SERVER_READY",
    ):
        self._cmd = cmd
        self._startup_delay = startup_delay
        self._log_file = Path(log_file) if log_file else None
        self._ready_pattern = ready_pattern
        self._process: subprocess.Popen | None = None

    def start(self):
        """Launch the server subprocess and wait until it is ready."""
        logger.info("Starting server: %s", self._cmd)

        self._process = subprocess.Popen(
            self._cmd,
            shell=True,
            # stdout/stderr pass through — redirect at the shell if needed
            preexec_fn=os.setsid,  # new process group for clean kill
        )

        if self._log_file is not None:
            self._wait_for_ready()
        else:
            logger.info("Waiting %.1fs for server startup...", self._startup_delay)
            time.sleep(self._startup_delay)

        if not self.is_alive():
            raise RuntimeError(
                f"Server process exited immediately (rc={self._process.returncode})."
            )

        logger.info("Server is running (pid=%d)", self._process.pid)

    def _wait_for_ready(self):
        """Poll the log file for ``ready_pattern`` up to ``startup_delay``."""
        deadline = time.monotonic() + self._startup_delay
        logger.info(
            "Waiting up to %.0fs for %s in %s...",
            self._startup_delay,
            self._ready_pattern,
            self._log_file.name,
        )
        while time.monotonic() < deadline:
            if not self.is_alive():
                log_tail = self._read_log_tail()
                raise RuntimeError(
                    f"Server process exited during startup "
                    f"(rc={self._process.returncode}).\n"
                    f"Server log: {log_tail}"
                )
            if self._log_file.exists():
                try:
                    content = self._log_file.read_text()
                    if self._ready_pattern in content:
                        logger.info("Server ready (found %s)", self._ready_pattern)
                        return
                except OSError:
                    pass  # file may be partially written
            time.sleep(_READY_POLL_INTERVAL)

        log_tail = self._read_log_tail()
        raise RuntimeError(
            f"Server did not emit {self._ready_pattern!r} within "
            f"{self._startup_delay}s.\n"
            f"Server log: {log_tail}"
        )

    def _read_log_tail(self, max_bytes: int = 2048) -> str:
        """Return the last ``max_bytes`` of the log file, or '(empty)'."""
        if self._log_file is None or not self._log_file.exists():
            return "(no log file)"
        try:
            content = self._log_file.read_text()
            if not content:
                return "(empty)"
            if len(content) > max_bytes:
                return f"...{content[-max_bytes:]}"
            return content.rstrip()
        except OSError:
            return "(unreadable)"

    def is_alive(self) -> bool:
        """Check if the server process is still running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    def stop(self, timeout: float = 5.0):
        """Stop the server process (SIGTERM, then SIGKILL)."""
        if self._process is None:
            return

        if self._process.poll() is not None:
            logger.info("Server already exited (rc=%d)", self._process.returncode)
            return

        logger.info("Stopping server (pid=%d)...", self._process.pid)
        try:
            os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
            self._process.wait(timeout=timeout)
            logger.info("Server stopped (rc=%d)", self._process.returncode)
        except subprocess.TimeoutExpired:
            logger.warning("Server did not exit after SIGTERM, sending SIGKILL")
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
                self._process.wait(timeout=2.0)
            except Exception:
                logger.exception("Failed to SIGKILL server")
        except Exception:
            logger.exception("Error stopping server")
