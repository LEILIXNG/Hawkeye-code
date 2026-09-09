"""Within-stage progress for a running scan, held in memory.

Deliberately not a column on `scans`: the counter is written from the verify
stage's worker threads, and the background task's SQLAlchemy Session belongs
to one thread. Routing every tick through the DB would mean either a second
session per worker or a lock around the shared one, to persist a number that
is meaningless the moment the scan ends -- a restart loses the running scan
along with it, since the pipeline runs in this process.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True)
class StageProgress:
    stage: str
    done: int
    total: int
    stage_elapsed: float


class ProgressRegistry:
    def __init__(self) -> None:
        self._stages: dict[str, tuple[str, int, int, float]] = {}
        self._lock = Lock()

    def start_stage(self, scan_id: str, stage: str) -> None:
        with self._lock:
            self._stages[scan_id] = (stage, 0, 0, time.monotonic())

    def update(self, scan_id: str, done: int, total: int) -> None:
        with self._lock:
            entry = self._stages.get(scan_id)
            if entry is None:
                self._stages[scan_id] = ("", done, total, time.monotonic())
                return
            stage, _, _, started = entry
            self._stages[scan_id] = (stage, done, total, started)

    def snapshot(self, scan_id: str) -> StageProgress | None:
        with self._lock:
            entry = self._stages.get(scan_id)
        if entry is None:
            return None
        stage, done, total, started = entry
        return StageProgress(stage=stage, done=done, total=total,
                             stage_elapsed=time.monotonic() - started)

    def clear(self, scan_id: str) -> None:
        with self._lock:
            self._stages.pop(scan_id, None)


registry = ProgressRegistry()
