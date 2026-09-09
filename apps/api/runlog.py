"""The server's own console output, kept in memory so the page can show it.

The black console window a local run leaves open is only worth looking at
for what it prints -- the semgrep command line, `[pipeline] verifying 3/57`,
a traceback when a scan dies. This module captures that same text into a
bounded buffer that `GET /logs` serves, which is what lets the page stand in
for the window.

Two sources feed it, because they escape through different holes:

* raw `print(..., file=sys.stderr)` from the scanner package -- caught by
  swapping sys.stderr for a tee that still writes to the real stream.
* uvicorn's own records -- caught with a logging handler. A tee cannot get
  these: uvicorn.Config configures logging in its constructor, before it
  imports the app, so its StreamHandler is already holding a reference to
  the original sys.stderr by the time any of our code runs.
"""
from __future__ import annotations

import logging
import sys
from collections import deque
from threading import Lock
from typing import TextIO

MAX_LINES = 2000

NEWLINE = chr(10)

# uvicorn sets propagate=False on "uvicorn" itself, so a handler on the root
# logger would never see any of these.
UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")

# Set on a record the first time it is buffered. "uvicorn.error" does
# propagate to "uvicorn", so a startup line reaches this handler twice --
# once on its own logger and once on the parent's -- and every uvicorn line
# was showing up doubled in the panel. Logging hands the same record object
# to both, which is what makes a mark on it a reliable way to tell the
# second visit from a genuinely repeated message.
SEEN_ATTRIBUTE = "_runlog_buffered"

# The panel polls this path, and uvicorn logs every request to it -- so each
# poll appends a line about the poll, which the next poll fetches, forever.
# Left in, the panel shows almost nothing but its own traffic and the buffer
# turns over fast enough to push real output out of it.
POLL_PATH = "/logs"


class _ActiveScan:
    """Which scan the pipeline is currently running, if any.

    A plain module-level value rather than a context variable: the pipeline
    is deliberately one-scan-at-a-time (scanner/pipeline.py), and the verify
    stage fans out over a ThreadPoolExecutor whose workers inherit neither a
    thread local nor a context.
    """

    def __init__(self) -> None:
        self._scan_id: str | None = None
        self._lock = Lock()

    def set(self, scan_id: str | None) -> None:
        with self._lock:
            self._scan_id = scan_id

    def get(self) -> str | None:
        with self._lock:
            return self._scan_id


active_scan = _ActiveScan()


class RunLog:
    """A bounded, monotonically numbered line buffer.

    The sequence number is what makes polling incremental: a client asks for
    everything after the last number it saw, and numbering continues past
    the point where old lines fall out of the deque, so a client that was
    away too long gets whatever survived rather than a silent replay.
    """

    def __init__(self, max_lines: int = MAX_LINES) -> None:
        self._lines: deque[tuple[int, str]] = deque(maxlen=max_lines)
        self._lock = Lock()
        self._next_seq = 1
        self._pending = ""

    def append(self, line: str, scan_id: str | None = None) -> None:
        with self._lock:
            self._lines.append((self._next_seq, line, scan_id))
            self._next_seq += 1

    def feed(self, text: str) -> None:
        """Accepts arbitrary writes and emits whole lines.

        `print` reaches a stream as two writes, the text and then the
        newline, so splitting each write into entries would double every
        line in the panel. Anything without a trailing newline is held back
        until the rest of it arrives.
        """
        with self._lock:
            self._pending += text
            if NEWLINE not in self._pending:
                return
            *complete, self._pending = self._pending.split(NEWLINE)
            # Tagged with the scan that was running when the line was
            # printed, which is what lets one task show its own output.
            # Only the tee is tagged: uvicorn records come from request
            # threads, and stamping a scan on an access log line would
            # attribute someone else traffic to it.
            scan_id = active_scan.get()
            for line in complete:
                self._lines.append((self._next_seq, line, scan_id))
                self._next_seq += 1

    def since(self, after: int, scan_id: str | None = None) -> tuple[list[dict], int]:
        """Lines newer than `after`; with a scan_id, only that scan's own.

        The returned high-water mark is the buffer's, not the filtered
        set's, so a caller polling one scan does not re-walk everything
        written for other reasons between its own lines.
        """
        with self._lock:
            entries = [
                {"seq": seq, "text": text, "scan_id": tag}
                for seq, text, tag in self._lines
                if seq > after and (scan_id is None or tag == scan_id)
            ]
            return entries, self._next_seq - 1

    def clear(self) -> None:
        with self._lock:
            self._lines.clear()
            self._pending = ""


run_log = RunLog()


class _Tee:
    """Writes through to the real stream and mirrors into the buffer."""

    def __init__(self, stream: TextIO | None, buffer: RunLog) -> None:
        self._stream = stream
        self._buffer = buffer

    def write(self, text: str) -> int:
        self._buffer.feed(text)
        if self._stream is not None:
            return self._stream.write(text)
        return len(text)

    def flush(self) -> None:
        if self._stream is not None:
            self._stream.flush()

    def isatty(self) -> bool:
        return bool(self._stream is not None and self._stream.isatty())

    def fileno(self) -> int:
        if self._stream is None:
            raise OSError("no underlying stream")
        return self._stream.fileno()


def is_poll_request(record: logging.LogRecord) -> bool:
    """An access-log record for the log endpoint itself.

    Read off the record's args rather than the formatted line: uvicorn
    builds an access record as a format string plus
    (client, method, path, http_version, status), so the path is a field
    here and only becomes text a caller would have to re-parse later.
    """
    if record.name != "uvicorn.access" or not isinstance(record.args, tuple) or len(record.args) < 3:
        return False
    path = record.args[2]
    return isinstance(path, str) and path.split("?")[0] == POLL_PATH


class _BufferHandler(logging.Handler):
    def __init__(self, buffer: RunLog) -> None:
        super().__init__()
        self._buffer = buffer

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(record, SEEN_ATTRIBUTE, False) or is_poll_request(record):
            return
        setattr(record, SEEN_ATTRIBUTE, True)
        try:
            self._buffer.append(self.format(record))
        except Exception:
            self.handleError(record)


_installed = False


def install(buffer: RunLog = run_log) -> None:
    global _installed
    if _installed:
        return
    _installed = True

    sys.stderr = _Tee(sys.stderr, buffer)

    handler = _BufferHandler(buffer)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    for name in UVICORN_LOGGERS:
        logging.getLogger(name).addHandler(handler)
