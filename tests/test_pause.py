"""Pausing a running scan, and resuming it -- the in-session-only sibling
of tests/test_cancel.py's cancellation coverage. Same shape: a registry the
API layer owns, checked at the same checkpoints should_cancel() already is.
"""
import pytest

from apps.api.pause import PauseRegistry
from scanner import pipeline
from scanner.pipeline import PipelineCancelled, _wait_while_paused


def test_registry_starts_empty():
    assert PauseRegistry().is_requested("s1") is False


def test_a_request_is_visible_and_clearable():
    registry = PauseRegistry()

    registry.request("s1")
    assert registry.is_requested("s1") is True

    registry.clear("s1")
    assert registry.is_requested("s1") is False


def test_resume_clears_the_request_the_same_way():
    """resume() is the pause endpoint's own verb, distinct from clear()
    (used in the pipeline's finally block) even though both just discard
    the request -- kept as two methods so a caller reads intent at the
    call site instead of a bare `clear`."""
    registry = PauseRegistry()
    registry.request("s1")

    registry.resume("s1")
    assert registry.is_requested("s1") is False


def test_scans_do_not_share_requests():
    registry = PauseRegistry()
    registry.request("s1")

    assert registry.is_requested("s2") is False


def test_resuming_or_clearing_an_unknown_scan_is_fine():
    PauseRegistry().resume("never-seen")
    PauseRegistry().clear("never-seen")  # the pipeline's finally does this


@pytest.fixture
def no_real_sleep(monkeypatch):
    """_wait_while_paused polls on a real clock in production; these tests
    care about the decision to wait and the callbacks around it, not about
    burning PAUSE_POLL_SECONDS of wall clock per assertion."""
    monkeypatch.setattr(pipeline.time, "sleep", lambda seconds: None)


class TestWaitWhilePaused:
    def test_returns_immediately_when_not_paused(self, no_real_sleep):
        calls = []
        _wait_while_paused(should_pause=lambda: False, should_cancel=lambda: False,
                           on_pause_change=calls.append)

        assert calls == []

    def test_reports_the_wait_starting_and_ending(self, no_real_sleep):
        # Paused for exactly one tick: True on the first should_pause()
        # check, False on the second -- so the loop exits by resuming, not
        # by the should_cancel() escape hatch below.
        ticks = iter([True, False])
        calls = []

        _wait_while_paused(should_pause=lambda: next(ticks, False), should_cancel=lambda: False,
                           on_pause_change=calls.append)

        assert calls == [True, False]

    def test_a_cancel_while_paused_ends_the_wait_too(self, no_real_sleep):
        """Pausing must not make a scan uncancellable -- should_cancel() is
        checked on every tick of the wait, not only before it starts."""
        calls = []

        _wait_while_paused(should_pause=lambda: True, should_cancel=lambda: True,
                           on_pause_change=calls.append)

        assert calls == [True, False]


@pytest.fixture
def stubbed_verify(monkeypatch):
    monkeypatch.setattr(pipeline, "build_context", lambda workspace, candidate, index: "context")
    monkeypatch.setattr(pipeline, "build_prompt", lambda template, candidate, context: "prompt")
    monkeypatch.setattr(pipeline, "call_llm", lambda provider, model, prompt: {"reachable": "no"})


class TestVerifyAllPausing:
    def test_pauses_between_candidates_and_resumes(self, stubbed_verify, no_real_sleep):
        """Paused after the first candidate, resumed on the next tick of the
        wait -- all 5 must still be verified, just with a pause recorded in
        the middle rather than a PipelineCancelled."""
        seen = []
        paused_after_first = {"armed": False}

        def should_pause():
            if len(seen) >= 1:
                if not paused_after_first["armed"]:
                    paused_after_first["armed"] = True
                    return True
                return False  # resumed on the very next check
            return False

        pause_events = []
        verified = pipeline.verify_all(
            [{"id": i} for i in range(5)], None, None, "", None, "m", concurrency=1,
            on_progress=lambda done, total: seen.append(done),
            should_pause=should_pause, on_pause_change=pause_events.append,
        )

        assert len(verified) == 5
        assert pause_events == [True, False]

    def test_cancelling_a_paused_scan_still_raises(self, stubbed_verify, no_real_sleep):
        with pytest.raises(PipelineCancelled):
            pipeline.verify_all([{"id": i} for i in range(5)], None, None, "", None, "m",
                                concurrency=1, should_pause=lambda: True, should_cancel=lambda: True)

    def test_a_scan_never_paused_never_calls_on_pause_change(self, stubbed_verify, no_real_sleep):
        pause_events = []
        pipeline.verify_all([{"id": i} for i in range(3)], None, None, "", None, "m",
                            concurrency=1, should_pause=lambda: False, on_pause_change=pause_events.append)

        assert pause_events == []
