"""Cancellation requests for a running scan.

The pipeline runs in this process on a background thread with no way in
from outside, so "delete a scan that is still running" needs somewhere for
the request to be left and somewhere for the pipeline to notice it. Same
shape and same reason as apps/api/progress.py: in memory, because a request
that outlived the process would be meaningless -- the scan it referred to
died with it.
"""
from __future__ import annotations

from threading import Lock


class CancelRegistry:
    def __init__(self) -> None:
        self._requested: set[str] = set()
        self._lock = Lock()

    def request(self, scan_id: str) -> None:
        with self._lock:
            self._requested.add(scan_id)

    def is_requested(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._requested

    def clear(self, scan_id: str) -> None:
        with self._lock:
            self._requested.discard(scan_id)


cancels = CancelRegistry()
