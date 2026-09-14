"""
progress.py

A minimal terminal spinner so a blocking call (warming up Ollama, waiting
on a pipeline stage) shows *something* moving instead of sitting silent --
that silence is a big part of what makes a slow/cold Ollama server feel
like it's randomly stuck rather than predictably working.

Usage:
    with Spinner("Waking up the model"):
        llm_client.warm_up()

Deliberately does nothing fancy when stdout isn't a real terminal (piped
output, a test capturing stdout with io.StringIO, a log file) -- printing
\\r-driven animation frames to a non-tty just produces line noise, so it
prints the message once instead and skips the animation entirely.
"""

import sys
import threading
import time


class Spinner:
    def __init__(self, message: str, stream=None, interval: float = 0.1):
        self.message = message
        self.stream = stream if stream is not None else sys.stdout
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None

    def _is_tty(self) -> bool:
        is_tty = getattr(self.stream, "isatty", None)
        return bool(is_tty and is_tty())

    def _spin(self) -> None:
        frames = "|/-\\"
        i = 0
        start = time.time()
        while not self._stop_event.is_set():
            elapsed = time.time() - start
            self.stream.write(f"\r{frames[i % len(frames)]} {self.message} ({elapsed:.0f}s) ")
            self.stream.flush()
            i += 1
            time.sleep(self.interval)

    def __enter__(self) -> "Spinner":
        if not self._is_tty():
            # non-interactive output -- print once, no animation
            self.stream.write(f"{self.message}...\n")
            self.stream.flush()
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._thread is not None:
            self._stop_event.set()
            self._thread.join()
            clear_width = len(self.message) + 24
            self.stream.write("\r" + " " * clear_width + "\r")
            self.stream.flush()
        return False
