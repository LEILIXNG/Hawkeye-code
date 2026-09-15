"""Pause/resume requests for a running scan.

Same shape and same reason as apps/api/cancel.py: the pipeline runs in this
process on a background thread with no way in from outside, so a pause
request needs somewhere to be left and somewhere for the pipeline to notice
it. In memory rather than a DB column, because a request that outlived the
process would be meaningless -- the scan it referred to either finished or
died with it, and there is nothing left to resume.
"""
from __future__ import annotations

from threading import Lock


class PauseRegistry:
    def __init__(self) -> None:
        self._requested: set[str] = set()
        self._lock = Lock()

    def request(self, scan_id: str) -> None:
        with self._lock:
            self._requested.add(scan_id)

    def resume(self, scan_id: str) -> None:
        with self._lock:
            self._requested.discard(scan_id)

    def is_requested(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._requested

    def clear(self, scan_id: str) -> None:
        with self._lock:
            self._requested.discard(scan_id)


pauses = PauseRegistry()
