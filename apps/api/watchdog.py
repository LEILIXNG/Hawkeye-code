"""Stops the server once the page that was using it goes away.

The server is started detached and has no console, so the page is the only
window it has -- closing that page should end the process the way closing an
app's window ends the app.

Two signals, one deadline. The page beats every few seconds, which pushes
the deadline out; a beat that stops coming (tab closed, browser quit, laptop
shut) lets the deadline pass on its own. A page being closed on purpose also
fires a beacon, which pulls the deadline in to a few seconds so a deliberate
close does not wait out the full idle timeout. Either way a beat arriving in
the meantime cancels it, which is what keeps a reload -- pagehide followed by
a fresh page a moment later -- from taking the server down, and what keeps a
second open tab from being ignored.

Nothing is armed until the first beat arrives: a server whose browser never
opened would otherwise shut itself down while the user was still looking for
the window.
"""
from __future__ import annotations

import threading
import time
from typing import Callable

# Comfortably longer than the page's beat interval, so one dropped request
# does not read as a closed page.
IDLE_TIMEOUT_SECONDS = 20.0
# Shorter, but still longer than one beat interval: a reload's pagehide
# arrives just before the new page's first beat, and the surviving tab of two
# needs a chance to speak up.
CLOSE_GRACE_SECONDS = 8.0
CHECK_INTERVAL_SECONDS = 1.0


class PageWatchdog:
    def __init__(self, on_expire: Callable[[], None], is_busy: Callable[[], bool] = lambda: False,
                 idle_timeout: float = IDLE_TIMEOUT_SECONDS,
                 close_grace: float = CLOSE_GRACE_SECONDS,
                 check_interval: float = CHECK_INTERVAL_SECONDS) -> None:
        self._on_expire = on_expire
        self._is_busy = is_busy
        self._idle_timeout = idle_timeout
        self._close_grace = close_grace
        self._check_interval = check_interval
        self._deadline: float | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def beat(self) -> None:
        with self._lock:
            self._deadline = time.monotonic() + self._idle_timeout

    def page_closing(self) -> None:
        """Only ever pulls the deadline in, never pushes it out -- a beacon
        from one tab must not extend the life of a server whose other tabs
        have already gone quiet."""
        with self._lock:
            if self._deadline is None:
                return
            self._deadline = min(self._deadline, time.monotonic() + self._close_grace)

    def expired(self) -> bool:
        with self._lock:
            return self._deadline is not None and time.monotonic() >= self._deadline

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="page-watchdog")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.wait(self._check_interval):
            if not self.expired():
                continue
            # A scan runs inside this process. Nobody is watching it, but
            # letting an idle timeout throw away ten minutes of LLM calls is
            # worse than a server that outlives its page for a while -- the
            # deadline is re-armed and checked again once the scan is done.
            if self._is_busy():
                self.beat()
                continue
            self._on_expire()
            return


def _running_scans() -> bool:
    # Imported here rather than at module scope: routers/server.py imports
    # this module, and the scan models reach back into the router package.
    from apps.api import models
    from apps.api.database import SessionLocal
    from apps.api.routers.scans import RUNNING_STATUSES

    db = SessionLocal()
    try:
        return db.query(models.Scan).filter(models.Scan.status.in_(RUNNING_STATUSES)).count() > 0
    finally:
        db.close()


def _shutdown() -> None:
    import signal
    import sys

    # Recorded because this is the one shutdown nobody asked for out loud,
    # and data/server.log is where the reason has to be afterwards.
    print("[watchdog] the page is gone, stopping the server", file=sys.stderr)
    signal.raise_signal(signal.SIGINT)


watchdog = PageWatchdog(on_expire=_shutdown, is_busy=_running_scans)
