"""The line buffer behind the page's server-log panel."""
import io
import logging

from apps.api.runlog import RunLog, _BufferHandler, _Tee, is_poll_request


def test_feed_joins_the_two_writes_print_makes():
    buffer = RunLog()

    buffer.feed("[pipeline] verifying 3/57")
    assert buffer.since(0)[0] == []  # nothing until the newline arrives

    buffer.feed("\n")
    entries, _ = buffer.since(0)
    assert [e["text"] for e in entries] == ["[pipeline] verifying 3/57"]


def test_feed_splits_a_multi_line_write():
    buffer = RunLog()

    buffer.feed("one\ntwo\nthree")
    entries, _ = buffer.since(0)

    assert [e["text"] for e in entries] == ["one", "two"]


def test_since_returns_only_newer_lines():
    buffer = RunLog()
    buffer.feed("first\nsecond\n")

    entries, latest = buffer.since(0)
    assert len(entries) == 2

    buffer.feed("third\n")
    entries, latest = buffer.since(latest)
    assert [e["text"] for e in entries] == ["third"]
    assert buffer.since(latest)[0] == []


def test_sequence_keeps_counting_past_evicted_lines():
    """A client polling with the last number it saw must not be handed lines
    it already has, even after the deque has rolled over."""
    buffer = RunLog(max_lines=3)
    buffer.feed("a\nb\nc\nd\ne\n")

    entries, latest = buffer.since(0)

    assert [e["text"] for e in entries] == ["c", "d", "e"]
    assert latest == 5
    assert [e["seq"] for e in entries] == [3, 4, 5]


def test_clear_drops_lines_and_the_partial_one():
    buffer = RunLog()
    buffer.feed("done\npartial")

    buffer.clear()
    buffer.feed(" line\n")

    assert [e["text"] for e in buffer.since(0)[0]] == [" line"]


def test_tee_writes_through_to_the_real_stream():
    stream = io.StringIO()
    buffer = RunLog()
    tee = _Tee(stream, buffer)

    tee.write("hello\n")

    assert stream.getvalue() == "hello\n"
    assert [e["text"] for e in buffer.since(0)[0]] == ["hello"]


def test_tee_survives_a_missing_stream():
    """pythonw leaves sys.stderr as None, and a launcher that hides the
    console must not turn every print into an AttributeError."""
    buffer = RunLog()
    tee = _Tee(None, buffer)

    assert tee.write("still buffered\n") == len("still buffered\n")
    assert [e["text"] for e in buffer.since(0)[0]] == ["still buffered"]
    tee.flush()
    assert tee.isatty() is False


def test_a_record_reaching_the_handler_twice_is_buffered_once():
    """uvicorn.error propagates to uvicorn and both carry this handler, so
    one startup line arrives twice as the same record object."""
    buffer = RunLog()
    handler = _BufferHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))
    record = logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1, "once", None, None)

    handler.emit(record)
    handler.emit(record)

    assert [e["text"] for e in buffer.since(0)[0]] == ["once"]


def test_two_identical_messages_are_both_kept():
    """The guard is per record object, not per text -- `verifying 3/57`
    printed twice by two workers is two real lines."""
    buffer = RunLog()
    handler = _BufferHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))

    for _ in range(2):
        handler.emit(logging.LogRecord("uvicorn", logging.INFO, __file__, 1, "same", None, None))

    assert [e["text"] for e in buffer.since(0)[0]] == ["same", "same"]


def test_handler_records_uvicorn_style_logs():
    buffer = RunLog()
    handler = _BufferHandler(buffer)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    handler.emit(logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1,
                                   "Application startup complete.", None, None))

    assert [e["text"] for e in buffer.since(0)[0]] == ["INFO: Application startup complete."]


def _access_record(method: str, path: str) -> logging.LogRecord:
    return logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1,
                             '%s - "%s %s HTTP/%s" %d',
                             ("127.0.0.1:1", method, path, "1.1", 200), None)


def test_the_panels_own_polling_is_not_logged_back_to_it():
    buffer = RunLog()
    handler = _BufferHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_access_record("GET", "/logs?after=12"))

    assert buffer.since(0)[0] == []


def test_other_requests_still_reach_the_panel():
    buffer = RunLog()
    handler = _BufferHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_access_record("GET", "/scans/abc"))

    assert len(buffer.since(0)[0]) == 1


def test_a_path_merely_starting_with_the_poll_path_is_kept():
    assert is_poll_request(_access_record("GET", "/logs")) is True
    assert is_poll_request(_access_record("GET", "/logs/archive")) is False


def test_a_non_access_record_is_never_treated_as_polling():
    record = logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1, "/logs", None, None)
    assert is_poll_request(record) is False
