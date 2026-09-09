"""verify_all's progress callback, on both the serial and concurrent paths."""
import pytest

from scanner import pipeline


@pytest.fixture
def stubbed_verify(monkeypatch):
    """Everything verify_one touches, replaced -- the callback's contract is
    what is under test, not the verification itself, and no test may make a
    real LLM call."""
    monkeypatch.setattr(pipeline, "build_context", lambda workspace, candidate, index: "context")
    monkeypatch.setattr(pipeline, "build_prompt", lambda template, candidate, context: "prompt")
    monkeypatch.setattr(pipeline, "call_llm", lambda provider, model, prompt: {"reachable": "no"})


def run(candidates, concurrency):
    seen = []
    verified = pipeline.verify_all(
        candidates, workspace_dir=None, index=None, template="", provider=None, model="m",
        concurrency=concurrency, on_progress=lambda done, total: seen.append((done, total)),
    )
    return verified, seen


def test_serial_path_reports_every_candidate(stubbed_verify):
    verified, seen = run([{"id": 1}, {"id": 2}, {"id": 3}], concurrency=1)

    assert len(verified) == 3
    assert seen == [(0, 3), (1, 3), (2, 3), (3, 3)]


def test_concurrent_path_reports_a_total_first_and_counts_up(stubbed_verify):
    verified, seen = run([{"id": i} for i in range(5)], concurrency=3)

    assert len(verified) == 5
    assert seen[0] == (0, 5)
    # Order between workers is not fixed, but the counts they report are a
    # complete run of 1..n -- a lost tick would leave the bar short.
    assert sorted(done for done, _ in seen[1:]) == [1, 2, 3, 4, 5]
    assert {total for _, total in seen} == {5}


def test_no_candidates_still_announces_a_total(stubbed_verify):
    """Otherwise the page keeps last scan's counts on screen for a project
    that produced nothing to verify."""
    verified, seen = run([], concurrency=1)

    assert verified == []
    assert seen == [(0, 0)]


def test_progress_is_optional(stubbed_verify):
    assert len(pipeline.verify_all([{"id": 1}], None, None, "", None, "m")) == 1
