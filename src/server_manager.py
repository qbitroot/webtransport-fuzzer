"""
Server subprocess manager.

Launches the target server as a child process with stdout/stderr passed
through to the terminal (not captured). The caller is responsible for
redirecting output at the shell level, e.g.:

    server.py cert.pem key.pem 2>/dev/null | tee server.log

Usage:
    mgr = ServerManager("uv run python server/aioquic/server.py cert.pem key.pem")
    mgr.start()    # launches process, waits for startup delay
    ...
    mgr.stop()     # SIGTERM → SIGKILL if needed
"""

import logging
import os
import signal
import subprocess
import time

logger = logging.getLogger(__name__)


class ServerManager:
    """Manages a server subprocess lifetime (start / stop / liveness check)."""

    def __init__(self, cmd: str, startup_delay: float = 1.0):
        self._cmd = cmd
        self._startup_delay = startup_delay
        self._process: subprocess.Popen | None = None

    def start(self):
        """Launch the server subprocess and wait for startup_delay."""
        logger.info("Starting server: %s", self._cmd)

        self._process = subprocess.Popen(
            self._cmd,
            shell=True,
            # stdout/stderr pass through — redirect at the shell if needed
            preexec_fn=os.setsid,  # new process group for clean kill
        )

        logger.info("Waiting %.1fs for server startup...", self._startup_delay)
        time.sleep(self._startup_delay)

        if not self.is_alive():
            raise RuntimeError(
                f"Server process exited immediately (rc={self._process.returncode})."
            )

        logger.info("Server is running (pid=%d)", self._process.pid)

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
