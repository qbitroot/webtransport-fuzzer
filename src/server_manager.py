"""
Server subprocess manager.

Launches the target server as a child process, captures stdout+stderr
in a background thread, and provides drain_lines() to retrieve buffered
output between fuzzer test cases.
"""

import logging
import os
import shlex
import signal
import subprocess
import threading
import time
from queue import Queue, Empty

logger = logging.getLogger(__name__)


class ServerManager:
    """
    Manages a server subprocess with real-time stdout+stderr capture.

    Usage:
        mgr = ServerManager("uv run python server/aioquic/server.py cert.pem key.pem")
        mgr.start()          # launches process, waits for startup delay
        ...
        lines = mgr.drain_lines()  # get all buffered output since last drain
        ...
        mgr.stop()            # SIGTERM → SIGKILL if needed
    """

    def __init__(self, cmd: str, startup_delay: float = 1.0):
        self._cmd = cmd
        self._startup_delay = startup_delay
        self._process: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._line_queue: Queue[str] = Queue()
        self._stopped = threading.Event()

    def start(self):
        """Launch the server subprocess and wait for startup_delay."""
        logger.info("Starting server: %s", self._cmd)

        # Use shell=True so the user can pass a full command string
        # with pipes, env vars, etc.
        self._process = subprocess.Popen(
            self._cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr into stdout
            # Line-buffered text mode
            text=True,
            bufsize=1,
            # New process group so we can kill the tree
            preexec_fn=os.setsid,
        )

        self._stopped.clear()
        self._reader_thread = threading.Thread(
            target=self._read_loop, daemon=True, name="server-stdout-reader"
        )
        self._reader_thread.start()

        logger.info("Waiting %.1fs for server startup...", self._startup_delay)
        time.sleep(self._startup_delay)

        if not self.is_alive():
            # Drain whatever output the process produced before dying
            lines = self.drain_lines()
            output = "\n".join(lines) if lines else "(no output)"
            raise RuntimeError(
                f"Server process exited immediately (rc={self._process.returncode}).\n"
                f"Output:\n{output}"
            )

        logger.info("Server is running (pid=%d)", self._process.pid)

    def _read_loop(self):
        """Background thread: read lines from the process stdout until EOF."""
        assert self._process is not None
        assert self._process.stdout is not None

        try:
            for line in self._process.stdout:
                if self._stopped.is_set():
                    break
                # Strip the trailing newline but preserve the rest
                self._line_queue.put(line.rstrip("\n"))
        except Exception as e:
            if not self._stopped.is_set():
                logger.warning("Server reader thread error: %s", e)
        finally:
            logger.debug("Server reader thread exiting")

    def drain_lines(self) -> list[str]:
        """Return all buffered lines since the last drain (non-blocking)."""
        lines = []
        while True:
            try:
                lines.append(self._line_queue.get_nowait())
            except Empty:
                break
        return lines

    def is_alive(self) -> bool:
        """Check if the server process is still running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    def stop(self, timeout: float = 5.0):
        """Stop the server process (SIGTERM, then SIGKILL)."""
        self._stopped.set()

        if self._process is None:
            return

        if self._process.poll() is not None:
            logger.info("Server already exited (rc=%d)", self._process.returncode)
            return

        logger.info("Stopping server (pid=%d)...", self._process.pid)
        try:
            # Kill the entire process group
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
