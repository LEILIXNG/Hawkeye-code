"""Cancelling a running scan, and closing out one the process left behind."""
import pytest

from apps.api.cancel import CancelRegistry
from scanner import pipeline
from scanner.pipeline import PipelineCancelled


def test_registry_starts_empty():
    assert CancelRegistry().is_requested("s1") is False


def test_a_request_is_visible_and_clearable():
    registry = CancelRegistry()

    registry.request("s1")
    assert registry.is_requested("s1") is True

    registry.clear("s1")
    assert registry.is_requested("s1") is False


def test_scans_do_not_share_requests():
    registry = CancelRegistry()
    registry.request("s1")

    assert registry.is_requested("s2") is False


def test_clearing_an_unknown_scan_is_fine():
    CancelRegistry().clear("never-seen")  # the pipeline's finally does this


@pytest.fixture
def stubbed_verify(monkeypatch):
    monkeypatch.setattr(pipeline, "build_context", lambda workspace, candidate, index: "context")
    monkeypatch.setattr(pipeline, "build_prompt", lambda template, candidate, context: "prompt")
    monkeypatch.setattr(pipeline, "call_llm", lambda provider, model, prompt: {"reachable": "no"})


def test_verify_stops_at_the_next_candidate(stubbed_verify):
    """Checked per candidate, not per stage: a scan the user asked to delete
    should not keep spending LLM calls for the minutes the rest would take."""
    seen = []

    def call(candidate):
        seen.append(candidate)
        return len(seen) >= 2

    with pytest.raises(PipelineCancelled):
        pipeline.verify_all([{"id": i} for i in range(10)], None, None, "", None, "m",
                            concurrency=1, should_cancel=lambda: len(seen) >= 2,
                            on_progress=lambda done, total: seen.append(done))

    assert len(seen) < 10


def test_cancellation_escapes_the_worker_threads(stubbed_verify):
    """It is raised inside executor.map's workers, and must not be caught
    and redressed as a verify failure on the way out."""
    with pytest.raises(PipelineCancelled):
        pipeline.verify_all([{"id": i} for i in range(20)], None, None, "", None, "m",
                            concurrency=4, should_cancel=lambda: True)


def test_a_scan_not_cancelled_runs_to_the_end(stubbed_verify):
    verified = pipeline.verify_all([{"id": i} for i in range(5)], None, None, "", None, "m",
                                   concurrency=2, should_cancel=lambda: False)

    assert len(verified) == 5
